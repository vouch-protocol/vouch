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
from .authority_state import evaluate_authority_freshness
from .status_list import CONSEQUENCE_ROUTINE


@dataclass
class TrustVerdict:
    """
    The outcome of checking an incoming agent call.

    Attributes:
      ok: True only if identity verified, not revoked, current trust meets the
        threshold (when a voucher is supplied), and the Authority Freshness gate
        passes for the requested consequence.
      identity_ok: The credential's Data Integrity proof, timing, resource
        binding, and delegation chain all verified.
      revoked: The issuer DID was reported revoked by the caller.
      trust: Current decayed trust from the SessionVoucher, or None if no
        voucher was supplied.
      trust_ok: Whether `trust` met the threshold, or None if no voucher.
      authority_ok: Whether the Authority Freshness gate passed, or None when the
        consequence is `routine` (time-decay only, no state gate).
      authority_reason: The Authority Freshness reason code, or None.
      reasons: Structured failure reasons; empty when ok=True.
      passport: The CredentialPassport from verification, or None.
    """

    ok: bool
    identity_ok: bool
    revoked: bool
    trust: Optional[float] = None
    trust_ok: Optional[bool] = None
    authority_ok: Optional[bool] = None
    authority_reason: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    passport: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "identity_ok": self.identity_ok,
            "revoked": self.revoked,
            "trust": self.trust,
            "trust_ok": self.trust_ok,
            "authority_ok": self.authority_ok,
            "authority_reason": self.authority_reason,
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
    consequence: str = CONSEQUENCE_ROUTINE,
    last_seen_authority_epoch: Optional[int] = None,
    voucher_authority_epoch: Optional[int] = None,
    current_authority_status: Optional[str] = None,
    live_cosign_ok: Optional[bool] = None,
) -> TrustVerdict:
    """
    Check an incoming agent call end to end (synchronous).

    Args:
      credential: the caller's Vouch credential (dict or JSON string). Its
        delegation chain, if present, is verified by `verify`.
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
      consequence: the action's consequence tier (`routine`, `sensitive`,
        `critical`) driving Authority Freshness (`vouch.authority_state`).
        Defaults to `routine`, which is time-decay only and changes nothing.
      last_seen_authority_epoch: the highest authority epoch the verifier has
        learned (via a status-list refresh or the heartbeat channel). Compared
        against the voucher's epoch on a state-freshness tier.
      voucher_authority_epoch: the epoch the voucher was minted under. When
        None, it is read from `session_voucher.credentialSubject.authorityEpoch`.
      current_authority_status: the authority's current status if known from a
        verified AuthorityState. A non-active status fails a state-freshness tier.
      live_cosign_ok: for the `critical` tier, whether a live co-sign was
        supplied and verified fresh (see
        `authority_state.verify_live_authority_cosign`).
    """
    reasons: List[str] = []

    structurally_valid, passport = Verifier.verify(
        credential, public_key=public_key, clock_skew_seconds=clock_skew_seconds
    )
    # Identity is only established when a key was supplied AND the proof verified.
    # With no key, verify runs structural and temporal checks only, so
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

    # Authority Freshness: state change as a first-class input. For a
    # state-freshness consequence tier, a voucher minted under a stale authority
    # epoch is rejected even when its time-decay trust still passes. `routine`
    # (the default) is time-decay only, so this is a no-op unless the caller
    # opts a higher tier in.
    authority_ok: Optional[bool] = None
    authority_reason: Optional[str] = None
    if consequence != CONSEQUENCE_ROUTINE:
        v_epoch = voucher_authority_epoch
        if v_epoch is None and isinstance(session_voucher, dict):
            subject = session_voucher.get("credentialSubject")
            if isinstance(subject, dict):
                raw = subject.get("authorityEpoch")
                if isinstance(raw, int) and not isinstance(raw, bool):
                    v_epoch = raw
        verdict = evaluate_authority_freshness(
            tier=consequence,
            voucher_epoch=v_epoch,
            last_seen_epoch=last_seen_authority_epoch,
            current_status=current_authority_status,
            live_cosign_ok=live_cosign_ok,
        )
        authority_ok = verdict.allow
        authority_reason = verdict.reason
        if not verdict.allow:
            reasons.append(verdict.reason)

    ok = identity_ok and (not revoked) and (trust_ok is not False) and (authority_ok is not False)
    return TrustVerdict(
        ok=ok,
        identity_ok=identity_ok,
        revoked=revoked,
        trust=trust,
        trust_ok=trust_ok,
        authority_ok=authority_ok,
        authority_reason=authority_reason,
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
    consequence: str = CONSEQUENCE_ROUTINE,
    last_seen_authority_epoch: Optional[int] = None,
    voucher_authority_epoch: Optional[int] = None,
    current_authority_status: Optional[str] = None,
    live_cosign_ok: Optional[bool] = None,
) -> TrustVerdict:
    """
    Same as `verify_agent_call`, but checks revocation against a registry.

    Args:
      revocation: a RevocationRegistry (or anything with async is_revoked).
      issuer_did: DID to check for revocation. Defaults to the credential's
        `issuer` field.

    The Authority Freshness arguments (`consequence`,
    `last_seen_authority_epoch`, `voucher_authority_epoch`,
    `current_authority_status`, `live_cosign_ok`) are forwarded to
    `verify_agent_call`.
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
        consequence=consequence,
        last_seen_authority_epoch=last_seen_authority_epoch,
        voucher_authority_epoch=voucher_authority_epoch,
        current_authority_status=current_authority_status,
        live_cosign_ok=live_cosign_ok,
    )
