"""
Cross-device identity by per-device keys and delegation (the OSS path).

The private key never travels. Each device mints its OWN key locally, and the
user's root identity delegates scoped, time-bound, revocable authority to that
device's DID. A device signs its actions with its own key, chained under the
root grant. Losing a device means revoking one delegation, not rotating the
whole identity, and no key is ever copied between devices.

This is the open-source, protocol-native answer to "the same identity across all
my devices, without revealing the key". It builds entirely on shipped primitives
(delegation grants, resource-narrowing, the credential chain). Managed
cross-device sync and recovery, and threshold/MPC custody of the root key, are
separate concerns and out of scope here.

Two pieces:

  grant = enroll_device(root, device_did=..., action=..., target=..., resource=...)
      The root authorizes a device's DID for a scope. Hand the grant to the
      device; it signs actions with `parent_credential=grant`.

  result = verify_delegated_chain([grant, action_credential],
                                  trusted_roots={root_did: root_public_key})
      A verifier checks the whole chain back to a trusted root: every proof is
      valid, each step is authorized by the one before it, the scope only
      narrows, and the validity windows nest. This is the part that was missing:
      tying a device credential back to a trusted root key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Union

from vouch.signer import Signer, _is_sub_resource
from vouch.verifier import CredentialPassport, verify


def _root_signer(root: Any) -> Signer:
    """Accept a Signer or an Agent (or anything exposing `.signer`)."""
    if isinstance(root, Signer):
        return root
    signer = getattr(root, "signer", None)
    if isinstance(signer, Signer):
        return signer
    raise TypeError("enroll_device requires a Signer or an Agent as the root")


def enroll_device(
    root: Any,
    *,
    device_did: str,
    action: str,
    target: str,
    resource: str,
    valid_seconds: int = 86400,
    reputation_score: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue a delegation grant from the root identity to a device's DID.

    The returned grant authorizes `device_did` to act within the given scope.
    The device, holding its own key, signs actions with this grant passed as
    ``parent_credential`` so each action chains back to the root. The root never
    sees or holds the device's key.

    Args:
      root: the root Signer or Agent (the durable user identity).
      device_did: the DID of the device's own key (for example a did:key the
        device minted locally).
      action / target / resource: the scope the device is allowed to act within.
      valid_seconds: how long the device grant is valid (default 1 day).
      reputation_score: optional self-reported score in [0, 100].

    Returns:
      The signed delegation grant credential (a dict), to hand to the device.
    """
    signer = _root_signer(root)
    intent: Dict[str, Any] = {
        "action": action,
        "target": target,
        "resource": resource,
        "delegatee": device_did,
    }
    return signer.sign(
        intent,
        valid_seconds=valid_seconds,
        reputation_score=reputation_score,
    )


@dataclass
class FleetResult:
    """Outcome of verifying a delegated device chain."""

    ok: bool
    leaf: Optional[CredentialPassport] = None
    root_did: Optional[str] = None
    reason: Optional[str] = None


def verify_delegated_chain(
    credentials: Sequence[Dict[str, Any]],
    *,
    trusted_roots: Optional[Dict[str, Any]] = None,
    allow_did_resolution: bool = True,
    revoked: Optional[Union[Iterable[str], Callable[[str], bool]]] = None,
    require_action: Optional[str] = None,
    require_target: Optional[str] = None,
    require_resource: Optional[str] = None,
) -> FleetResult:
    """Verify a delegation chain from a trusted root down to a leaf action.

    `credentials` is ordered root-first: ``[root_grant, ...intermediate grants,
    leaf_action]``. The first credential's issuer must be a trusted root. Every
    credential's Data Integrity proof and validity window are checked, each step
    must be authorized by the step before it (the child's issuer is the parent's
    delegatee), the resource may only narrow, and the validity windows must nest.

    Args:
      credentials: the presented chain, root grant first, leaf action last.
      trusted_roots: a ``{did: public_key}`` map of accepted root issuers. The
        root credential's issuer MUST appear here. Other links resolve their key
        from this map, then ``did:key``/``did:web``.
      allow_did_resolution: allow network ``did:web`` resolution for non-root
        links (``did:key`` always resolves offline).
      revoked: revocation oracle. Either a collection of revoked identifiers
        (device DIDs and/or credential ids) or a callable ``is_revoked(id) ->
        bool``. The chain is rejected if any link's issuer, any credential id, or
        any grant's delegatee is revoked. This is how losing a device is handled:
        revoke that device's DID and every chain through it stops verifying.
      require_action / require_target / require_resource: optional exact policy
        on the leaf action's intent.

    Returns:
      A FleetResult. ``ok`` is True only when every check passes.
    """
    if not credentials:
        return FleetResult(ok=False, reason="empty chain")
    trusted_roots = trusted_roots or {}
    is_revoked = _revocation_oracle(revoked)

    passports: List[CredentialPassport] = []
    for index, cred in enumerate(credentials):
        issuer = _issuer_of(cred)
        if not issuer:
            return FleetResult(ok=False, reason=f"credential {index} has no issuer")

        # The root anchor must be explicitly trusted. Later links resolve their
        # key from trusted_roots if present, otherwise by DID.
        key = trusted_roots.get(issuer)
        if index == 0 and key is None:
            return FleetResult(ok=False, reason=f"root issuer {issuer!r} is not in trusted_roots")

        ok, passport = verify(cred, public_key=key, allow_did_resolution=allow_did_resolution)
        if not ok or passport is None:
            return FleetResult(ok=False, reason=f"credential {index} failed verification")

        # Revocation: a revoked issuer (device or root) or a revoked specific
        # credential breaks the chain.
        if is_revoked(passport.issuer):
            return FleetResult(
                ok=False, reason=f"credential {index} issuer {passport.issuer!r} is revoked"
            )
        if passport.credential_id and is_revoked(passport.credential_id):
            return FleetResult(
                ok=False, reason=f"credential {index} ({passport.credential_id}) is revoked"
            )
        passports.append(passport)

    # Walk parent -> child links.
    for i in range(len(passports) - 1):
        parent = passports[i]
        child = passports[i + 1]

        delegatee = (parent.intent or {}).get("delegatee")
        if not delegatee:
            return FleetResult(
                ok=False, reason=f"link {i} (grant by {parent.issuer!r}) names no delegatee"
            )
        if is_revoked(delegatee):
            return FleetResult(ok=False, reason=f"link {i}: delegatee {delegatee!r} is revoked")
        if child.issuer != delegatee:
            return FleetResult(
                ok=False,
                reason=(
                    f"link {i}: child issuer {child.issuer!r} is not the delegatee "
                    f"{delegatee!r} the parent authorized"
                ),
            )

        parent_resource = (parent.intent or {}).get("resource", "")
        child_resource = (child.intent or {}).get("resource", "")
        if (
            parent_resource
            and child_resource
            and not _is_sub_resource(child_resource, parent_resource)
        ):
            return FleetResult(
                ok=False,
                reason=(
                    f"link {i}: resource {child_resource!r} is not within the "
                    f"granted {parent_resource!r}"
                ),
            )

        if not _window_within(child, parent):
            return FleetResult(
                ok=False, reason=f"link {i}: child validity is outside the grant window"
            )

    leaf = passports[-1]
    intent = leaf.intent or {}
    for field, expected in (
        ("action", require_action),
        ("target", require_target),
        ("resource", require_resource),
    ):
        if expected is not None and intent.get(field) != expected:
            return FleetResult(ok=False, leaf=leaf, reason=f"leaf intent.{field} != {expected!r}")

    return FleetResult(ok=True, leaf=leaf, root_did=passports[0].issuer)


def _issuer_of(cred: Dict[str, Any]) -> Optional[str]:
    issuer = cred.get("issuer")
    if isinstance(issuer, list):
        return issuer[0] if issuer else None
    return issuer


def _window_within(child: CredentialPassport, parent: CredentialPassport) -> bool:
    """True if the child's validity window sits inside the parent's (time-bound
    delegation: a device cannot outlive its grant)."""
    from vouch.verifier import _parse_iso8601

    c_from = _parse_iso8601(child.valid_from)
    c_until = _parse_iso8601(child.valid_until)
    p_from = _parse_iso8601(parent.valid_from)
    p_until = _parse_iso8601(parent.valid_until)
    if not all((c_from, c_until, p_from, p_until)):
        return False
    return c_from >= p_from and c_until <= p_until


def _revocation_oracle(
    revoked: Optional[Iterable[str] | Callable[[str], bool]],
) -> Callable[[str], bool]:
    """Normalize the `revoked` argument into an `is_revoked(id) -> bool` callable."""
    if revoked is None:
        return lambda _id: False
    if callable(revoked):
        return revoked
    revoked_set = set(revoked)
    return lambda _id: _id in revoked_set


class DeviceRegistry:
    """A small in-memory record of a root's enrolled and revoked devices.

    Convenience for the common case: track which device DIDs a root has enrolled
    and which it has revoked, and pass :meth:`is_revoked` straight to
    :func:`verify_delegated_chain`. Back it with your own store (a database, a
    BitstringStatusList) by subclassing or by passing a different oracle; this is
    only the simplest default.
    """

    def __init__(self) -> None:
        self._enrolled: Dict[str, Dict[str, Any]] = {}
        self._revoked: Set[str] = set()

    def enroll(self, device_did: str, grant: Optional[Dict[str, Any]] = None) -> None:
        """Record a device as enrolled (optionally keeping its grant)."""
        self._enrolled[device_did] = {"grant": grant}
        self._revoked.discard(device_did)

    def revoke(self, device_did: str) -> None:
        """Revoke a device. Chains issued by or delegated to it stop verifying."""
        self._revoked.add(device_did)

    def is_revoked(self, identifier: str) -> bool:
        return identifier in self._revoked

    def active_devices(self) -> List[str]:
        return [d for d in self._enrolled if d not in self._revoked]

    @property
    def revoked(self) -> Set[str]:
        return set(self._revoked)


__all__ = ["enroll_device", "verify_delegated_chain", "FleetResult", "DeviceRegistry"]
