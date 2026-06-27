"""
Server-side credential gate — the production counterpart to ``vouch.protect``.

On the sending side, ``protect`` / ``sign_intent`` make an agent sign every tool
call. On the receiving side, an API has to verify those credentials and reject
unsigned or untrusted callers. That used to be hand-written per endpoint: pull a
header, call ``verify_credential`` with a hard-coded public key, raise 401, and
(if you cared) check the intent matched the route.

``CredentialGate`` collapses that to one object. It is framework-agnostic — the
FastAPI/ASGI adapter in :mod:`vouch.integrations.fastapi` is a thin shell over
it, and the same core backs any other web framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from vouch.verifier import CredentialPassport, Verifier, verify


@dataclass
class GateResult:
    """Outcome of checking one inbound credential."""

    ok: bool
    passport: Optional[CredentialPassport] = None
    reason: Optional[str] = None


class CredentialGate:
    """Verify inbound Vouch credentials and enforce simple intent policy.

    One object, configured once, reused per request::

        gate = CredentialGate(allow_did_resolution=True)
        result = gate.check(incoming_credential)
        if not result.ok:
            reject(401, result.reason)
        agent_did = result.passport.iss

    Key resolution, in order of what you configure:

      * ``public_key=`` — a single trusted issuer key (offline, no network).
      * ``trusted_keys=`` — a ``{did: public_key}`` map of allowed issuers
        (offline; an issuer not in the map is rejected).
      * otherwise the issuer's key is resolved automatically from ``did:web``
        (set ``allow_did_resolution=False`` to forbid network resolution).

    Optional intent policy — reject a credential whose intent does not match:

      * ``require_action`` / ``require_target`` / ``require_resource`` — exact
        string match against ``passport.intent``.
    """

    def __init__(
        self,
        *,
        public_key: Optional[Union[str, Any]] = None,
        trusted_keys: Optional[Dict[str, str]] = None,
        allow_did_resolution: bool = True,
        require_action: Optional[str] = None,
        require_target: Optional[str] = None,
        require_resource: Optional[str] = None,
    ) -> None:
        self._public_key = public_key
        self._allow_did_resolution = allow_did_resolution
        self._require_action = require_action
        self._require_target = require_target
        self._require_resource = require_resource

        # An offline allowlist of issuers gets its own Verifier with the keys
        # registered as trusted roots, so unknown issuers can never resolve.
        self._verifier: Optional[Verifier] = None
        if trusted_keys:
            self._verifier = Verifier(allow_did_resolution=False)
            for did, key in trusted_keys.items():
                self._verifier.add_trusted_root(did, key)

    def check(self, credential: Optional[Union[Dict[str, Any], str]]) -> GateResult:
        """Verify a credential and apply intent policy. Never raises."""
        if not credential:
            return GateResult(ok=False, reason="missing credential")

        try:
            if self._verifier is not None:
                ok, passport = self._verifier.check_vouch_credential(credential)
            else:
                ok, passport = verify(
                    credential,
                    public_key=self._public_key,
                    allow_did_resolution=self._allow_did_resolution,
                )
        except Exception as e:  # defensive: a malformed body must not 500
            return GateResult(ok=False, reason=f"verification error: {e}")

        if not ok or passport is None:
            return GateResult(ok=False, reason="invalid or untrusted credential")

        policy_reason = self._check_policy(passport)
        if policy_reason is not None:
            return GateResult(ok=False, passport=passport, reason=policy_reason)

        return GateResult(ok=True, passport=passport)

    def _check_policy(self, passport: CredentialPassport) -> Optional[str]:
        intent = passport.intent or {}
        for field, expected in (
            ("action", self._require_action),
            ("target", self._require_target),
            ("resource", self._require_resource),
        ):
            if expected is not None and intent.get(field) != expected:
                return f"intent.{field} != {expected!r}"
        return None


__all__ = ["CredentialGate", "GateResult"]
