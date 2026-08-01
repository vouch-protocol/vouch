"""
Event-triggered intent recheck: bind seal freshness to the action, not the interval.

The Heartbeat Protocol (:mod:`vouch.heartbeat`) proves an agent is alive across an
interval. It does not prove the agent's *intent* is current at the moment of a
sensitive action. A justification sealed early in an interval still passes for an
action executed much later in the same interval, so a sophisticated actor can time
a sensitive action to land after a pulse boundary while reusing an intent sealed
before it. The heartbeat says "still here"; it does not say "still meaning this".

This module closes that gap. It composes with :mod:`vouch.reasoning` and reuses its
justification and escrow primitives, adding no new cryptography:

1. **Pulse-window awareness** (:func:`pulse_window`): given the last heartbeat
   boundary and an action's execution time, say whether the action falls inside the
   current window or in the gap past it.
2. **Intent-freshness policy** (:func:`default_requirement`, :class:`FreshnessRequirement`):
   a consequence-tier -> requirement map. A sensitive tier requires a seal made
   after the last pulse boundary and within a configurable max age, not merely a
   seal made before execution.
3. **Verify rule** (:func:`verify_intent_freshness`, :func:`check_seal_freshness`):
   reject a stale seal with a stable, structured reason string, following the
   convention in :mod:`vouch.reasoning`.
4. **Execution-time reseal** (:func:`reseal_intent`): a helper an agent calls right
   before a sensitive action to produce a fresh seal at that moment, so correct
   adoption is a one-liner.

The stable reason strings, the tier policy, the seal-timestamp resolution, and the
pulse-window arithmetic match the Rust core (``core/vouch-core/src/reasoning.rs``)
byte for byte, so a seal built in one language verifies in another and a stale-seal
case is rejected identically everywhere. This is the adversarial mirror of the
authority-freshness work, which approached the same interval gap from the
principal's side.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import reasoning
from .reasoning import ReasonedActionError, _iso, _parse_iso

# Intent-recheck reasons (stable prefixes; carry a structured suffix).
REASON_INTENT_SEAL_STALE = "intent_seal_stale"
REASON_INTENT_SEAL_EXPIRED = "intent_seal_expired"
REASON_INTENT_SEAL_MISSING = "intent_seal_missing"

# Consequence tiers, aligned with PAD-017 commitment levels (0..4) and the
# trust-entropy stakes bands. Higher tiers demand a fresher seal.
TIER_ROUTINE = 0
TIER_LOW = 1
TIER_MEDIUM = 2
TIER_HIGH = 3
TIER_CRITICAL = 4


@dataclass(frozen=True)
class PulseWindow:
    """Where an execution time falls relative to ``[last_pulse, last_pulse + interval)``."""

    in_window: bool
    in_gap: bool
    seconds_into_window: int


def pulse_window(last_pulse: datetime, interval_seconds: float, exec_time: datetime) -> PulseWindow:
    """
    Classify an action's execution time against the pulse schedule.

    Args:
        last_pulse: Issue time of the most recent heartbeat.
        interval_seconds: The heartbeat period.
        exec_time: When the action executes.

    Returns:
        A :class:`PulseWindow`. ``in_window`` is true when execution is inside the
        current window (no pulse is yet due); ``in_gap`` is true when execution is
        past the window's end (the next pulse is overdue).
    """
    delta = int((exec_time - last_pulse).total_seconds())
    return PulseWindow(
        in_window=0 <= delta < interval_seconds,
        in_gap=delta >= interval_seconds,
        seconds_into_window=delta,
    )


@dataclass(frozen=True)
class FreshnessRequirement:
    """The freshness a consequence tier imposes on an intent seal."""

    require_fresh_seal: bool
    max_age_seconds: Optional[int]  # None means no age bound.


#: The tier that imposes no freshness requirement.
REQUIREMENT_NONE = FreshnessRequirement(require_fresh_seal=False, max_age_seconds=None)


def default_requirement(tier: int) -> FreshnessRequirement:
    """
    Reference intent-freshness policy: routine, low, and medium tiers inherit the
    last pulse's assurance; high and critical tiers require a seal made after the
    last pulse boundary, within a tightening max age. Deployments substitute their
    own thresholds; these are reference values that match the Rust core.
    """
    if tier >= TIER_CRITICAL:
        return FreshnessRequirement(require_fresh_seal=True, max_age_seconds=60)
    if tier == TIER_HIGH:
        return FreshnessRequirement(require_fresh_seal=True, max_age_seconds=300)
    return REQUIREMENT_NONE


def seal_timestamp(credential: Dict[str, Any]) -> Optional[str]:
    """
    Read the seal timestamp from a reasoned-action credential: the justification's
    ``sealedAt`` if present, else the attached escrow receipt's ``depositedAt``.
    """
    jblock = (credential.get("credentialSubject") or {}).get("justification") or {}
    sealed = jblock.get("sealedAt")
    if sealed:
        return sealed
    receipt = jblock.get("escrowReceipt") or {}
    deposited = (receipt.get("credentialSubject") or {}).get("depositedAt")
    return deposited or None


def check_seal_freshness(
    sealed_at: str,
    exec_time: str,
    last_pulse: str,
    requirement: FreshnessRequirement,
) -> Optional[str]:
    """
    The core intent-recheck rule. Return ``None`` if the seal is fresh enough for
    the requirement, else a stable reason string:

    - ``intent_seal_stale:sealed_at=<t>,last_pulse=<t>`` when a pulse boundary
      elapsed between sealing and execution (the action inherited a prior pulse's
      assurance). This is the timing-the-gap case.
    - ``intent_seal_expired:sealed_at=<t>,max_age=<n>s`` when the seal is within the
      current window but older than the tier's max age.
    """
    if not requirement.require_fresh_seal:
        return None
    sealed = _parse_iso(sealed_at)
    executed = _parse_iso(exec_time)
    pulse = _parse_iso(last_pulse)
    if sealed < pulse:
        return f"{REASON_INTENT_SEAL_STALE}:sealed_at={sealed_at},last_pulse={last_pulse}"
    if requirement.max_age_seconds is not None:
        if (executed - sealed).total_seconds() > requirement.max_age_seconds:
            return f"{REASON_INTENT_SEAL_EXPIRED}:sealed_at={sealed_at},max_age={requirement.max_age_seconds}s"
    return None


def verify_intent_freshness(
    credential: Dict[str, Any],
    tier: int,
    last_pulse: str,
    requirement: Optional[FreshnessRequirement] = None,
) -> Optional[str]:
    """
    Verify intent freshness for a reasoned-action credential at a given tier.

    Returns ``None`` when the tier does not require a fresh seal or the seal is
    fresh; else a stable reason string. When the tier requires a fresh seal but the
    credential carries no seal timestamp, returns ``intent_seal_missing:tier=<n>``.

    ``requirement`` defaults to :func:`default_requirement` for the tier. This is a
    policy check over timestamps; run it alongside
    :func:`vouch.reasoning.check_reasoned_action`, which verifies the signature and
    the commitment.
    """
    req = requirement if requirement is not None else default_requirement(tier)
    if not req.require_fresh_seal:
        return None
    exec_time = credential.get("validFrom")
    if not exec_time:
        raise ReasonedActionError("credential has no validFrom")
    sealed_at = seal_timestamp(credential)
    if sealed_at is None:
        return f"{REASON_INTENT_SEAL_MISSING}:tier={tier}"
    return check_seal_freshness(sealed_at, exec_time, last_pulse, req)


def reseal_intent(
    signer: Any,
    *,
    intent: Dict[str, Any],
    anchors: List[Dict[str, Any]],
    commitment_level: Optional[int] = None,
    now: Optional[datetime] = None,
    credential_id: Optional[str] = None,
    include_reasoning: bool = True,
) -> Dict[str, Any]:
    """
    Execution-time reseal helper: seal the intent right now and issue a fresh
    ``ReasonedActionCredential`` whose ``sealedAt`` and ``validFrom`` are both
    ``now``, so a sensitive action carries a seal made in the current pulse window.

    Call this immediately before a sensitive action. It reuses
    :func:`vouch.reasoning.build_justification` and
    :func:`vouch.reasoning.sign_reasoned_action`; no new cryptography.
    """
    stamped = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    justification = reasoning.build_justification(
        intent, anchors, commitment_level=commitment_level
    )
    return reasoning.sign_reasoned_action(
        signer,
        intent=intent,
        justification=justification,
        include_reasoning=include_reasoning,
        valid_from=stamped,
        sealed_at=stamped,
        credential_id=credential_id,
    )


__all__ = [
    "REASON_INTENT_SEAL_STALE",
    "REASON_INTENT_SEAL_EXPIRED",
    "REASON_INTENT_SEAL_MISSING",
    "TIER_ROUTINE",
    "TIER_LOW",
    "TIER_MEDIUM",
    "TIER_HIGH",
    "TIER_CRITICAL",
    "PulseWindow",
    "pulse_window",
    "FreshnessRequirement",
    "REQUIREMENT_NONE",
    "default_requirement",
    "seal_timestamp",
    "check_seal_freshness",
    "verify_intent_freshness",
    "reseal_intent",
]
