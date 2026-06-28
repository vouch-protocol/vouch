"""
Robot delegation lease: short-lived, scope-bounded, offline-verifiable authority.

A robot often has to act where there is no connectivity (a warehouse aisle, a
field, a tunnel), so it cannot call home to check whether it is still allowed to
do something. A delegation lease is a self-contained grant of authority it can
verify and act on entirely offline: an authority issues the robot a credential
that bounds what it may physically do (a physical capability scope, including the
zones it may operate in), for a fixed, short window. The robot verifies the
lease's signature, that the window is current, and that a proposed action fits
the scope, with no network call.

Leases nest: an authority can grant a lease, and the holder can sub-grant a
narrower lease to another party, each link attenuating (never widening) the one
above it. That nesting is the open cross-vendor chain, a vendor leases to an
integrator, the integrator to an operator, the operator to the robot, and every
link is verifiable and bounded.

This is the open layer: a plain, offline-verifiable lease. Hosted lease issuance
and management are out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .capability import PhysicalAction, attenuates, check_physical_action
from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
DELEGATION_LEASE_TYPE = "DelegationLeaseCredential"


def build_delegation_lease(
    signer: Any,
    *,
    robot_did: str,
    lease_id: str,
    scope: Dict[str, Any],
    valid_seconds: int,
    valid_from: Optional[datetime] = None,
    parent_lease_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a signed DelegationLeaseCredential granting `robot_did` a bounded
    physical `scope` for a fixed window. `scope` is a physicalScope object (the
    same shape as a PhysicalCapabilityScope credentialSubject.physicalScope).
    Leases are short-lived by design, so `valid_seconds` is required. Set
    `parent_lease_id` when sub-granting from another lease.
    """
    if valid_seconds <= 0:
        raise RoboticsError("valid_seconds must be positive")
    if not lease_id:
        raise RoboticsError("lease_id is required")
    if not isinstance(scope, dict):
        raise RoboticsError("scope must be a physicalScope object")

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "leaseId": lease_id,
        "physicalScope": scope,
    }
    if parent_lease_id is not None:
        subject["parentLeaseId"] = parent_lease_id

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", DELEGATION_LEASE_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "validUntil": _iso(issued + timedelta(seconds=valid_seconds)),
        "credentialSubject": subject,
    }
    return attach_proof(credential, signer)


def verify_delegation_lease(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    now: Optional[datetime] = None,
    parent_scope: Optional[Dict[str, Any]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a DelegationLeaseCredential offline: the issuer's proof, that the
    window is current, and (when `parent_scope` is supplied) that this lease's
    scope attenuates the parent. No network call. Returns (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if DELEGATION_LEASE_TYPE not in type_field:
        return False, None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    if not _window_current(credential, now):
        return False, None

    subject = credential.get("credentialSubject") or {}
    scope = subject.get("physicalScope")
    if not isinstance(scope, dict):
        return False, None
    if parent_scope is not None and not attenuates(parent_scope, scope):
        return False, None

    return True, subject


def lease_permits(
    subject: Dict[str, Any],
    action: PhysicalAction,
    credential: Optional[Dict[str, Any]] = None,
    *,
    now: Optional[datetime] = None,
) -> bool:
    """
    Decide whether a verified lease permits a proposed physical action: the
    action must fit the lease scope, and (when the full `credential` is supplied)
    the window must still be current.
    """
    if credential is not None and not _window_current(credential, now):
        return False
    scope = subject.get("physicalScope") or {}
    return check_physical_action(scope, action).ok


def _window_current(credential: Dict[str, Any], now: Optional[datetime]) -> bool:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    vf = credential.get("validFrom")
    vu = credential.get("validUntil")
    try:
        if vf and moment < _parse_iso(vf):
            return False
        if vu and moment > _parse_iso(vu):
            return False
    except (ValueError, TypeError):
        return False
    return True


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


__all__ = [
    "DELEGATION_LEASE_TYPE",
    "build_delegation_lease",
    "verify_delegation_lease",
    "lease_permits",
]
