"""
One callable trust check for an incoming agent call.

MCP tool calls and Agent2Agent (A2A) calls both need to answer the same
question before acting on a request from another agent: is the caller who it
claims to be, was it allowed to do this, has it been revoked, and is its trust
still live right now. This module composes the existing primitives (credential
verification including the delegation chain, revocation, and trust-entropy
decay) into a single verdict so every transport checks trust the same way.

The integration packages (MCP, A2A) call `verify_agent_call` rather than
re-implementing the composition. Keep the composition here, once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from .verifier import Verifier
from .trust_entropy import evaluate_trust


@dataclass
class TrustVerdict:
    """
    The outcome of checking an incoming agent call.

    Attributes:
      ok: True only if identity verified, not revoked, and (when a voucher is
        supplied) current trust meets the threshold.
      identity_ok: The credential's Data Integrity proof, timing, resource
        binding, and delegation chain all verified.
      revoked: The issuer DID was reported revoked by the caller.
      trust: Current decayed trust from the SessionVoucher, or None if no
        voucher was supplied.
      trust_ok: Whether `trust` met the threshold, or None if no voucher.
      reasons: Structured failure reasons; empty when ok=True.
      passport: The CredentialPassport from verification, or None.
    """

    ok: bool
    identity_ok: bool
    revoked: bool
    trust: Optional[float] = None
    trust_ok: Optional[bool] = None
    reasons: List[str] = field(default_factory=list)
    passport: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "identity_ok": self.identity_ok,
            "revoked": self.revoked,
            "trust": self.trust,
            "trust_ok": self.trust_ok,
            "reasons": list(self.reasons),
        }


def verify_agent_call(
    credential: Union[Dict[str, Any], str],
    *,
    public_key: Optional[Union[str, Any]] = None,
    revoked: bool = False,
    session_voucher: Optional[Dict[str, Any]] = None,
    trust_threshold: float = 0.0,
    at_time: Optional[datetime] = None,
    clock_skew_seconds: int = 30,
) -> TrustVerdict:
    """
    Check an incoming agent call end to end (synchronous).

    Args:
      credential: the caller's Vouch credential (dict or JSON string). Its
        delegation chain, if present, is verified by `verify_credential`.
      public_key: the issuer's Ed25519 public key (Multikey string or key
        object). If None, only structural and temporal checks run, so
        identity_ok cannot be relied on.
      revoked: whether the issuer DID is revoked. Callers that have a
        revocation registry should pass the result of `is_revoked`, or use
        `verify_agent_call_async` which checks it for them.
      session_voucher: an optional current-trust SessionVoucher. When present,
        the call is only ok if decayed trust meets `trust_threshold`.
      trust_threshold: minimum current trust required when a voucher is given.
      at_time: evaluation time for trust decay (defaults to now).
      clock_skew_seconds: allowed clock drift for credential timing.
    """
    reasons: List[str] = []

    structurally_valid, passport = Verifier.verify_credential(
        credential, public_key=public_key, clock_skew_seconds=clock_skew_seconds
    )
    # Identity is only established when a key was supplied AND the proof verified.
    # With no key, verify_credential runs structural and temporal checks only, so
    # it cannot be treated as proof of who signed the credential.
    if public_key is None:
        identity_ok = False
        reasons.append("no_public_key")
    elif not structurally_valid:
        identity_ok = False
        reasons.append("credential_invalid")
    else:
        identity_ok = True

    if revoked:
        reasons.append("issuer_revoked")

    trust: Optional[float] = None
    trust_ok: Optional[bool] = None
    if session_voucher is not None:
        evaluation = evaluate_trust(session_voucher, trust_threshold, at_time)
        trust = evaluation.trust
        trust_ok = evaluation.passed
        if not evaluation.passed:
            reasons.append(f"trust_below_threshold:{trust:.4f}<{trust_threshold}")

    ok = identity_ok and (not revoked) and (trust_ok is not False)
    return TrustVerdict(
        ok=ok,
        identity_ok=identity_ok,
        revoked=revoked,
        trust=trust,
        trust_ok=trust_ok,
        reasons=reasons,
        passport=passport,
    )


async def verify_agent_call_async(
    credential: Union[Dict[str, Any], str],
    *,
    public_key: Optional[Union[str, Any]] = None,
    revocation: Optional[Any] = None,
    issuer_did: Optional[str] = None,
    session_voucher: Optional[Dict[str, Any]] = None,
    trust_threshold: float = 0.0,
    at_time: Optional[datetime] = None,
    clock_skew_seconds: int = 30,
) -> TrustVerdict:
    """
    Same as `verify_agent_call`, but checks revocation against a registry.

    Args:
      revocation: a RevocationRegistry (or anything with async is_revoked).
      issuer_did: DID to check for revocation. Defaults to the credential's
        `issuer` field.
    """
    revoked = False
    if revocation is not None:
        did = issuer_did
        if did is None and isinstance(credential, dict):
            did = credential.get("issuer")
        if did:
            revoked = await revocation.is_revoked(did)

    return verify_agent_call(
        credential,
        public_key=public_key,
        revoked=revoked,
        session_voucher=session_voucher,
        trust_threshold=trust_threshold,
        at_time=at_time,
        clock_skew_seconds=clock_skew_seconds,
    )
