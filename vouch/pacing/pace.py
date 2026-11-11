"""
Graduated Multilateral Pace Control (PAD-129).

Coordination proposals offer a switch: run or halt. A switch nobody dares pull
is not a control. This module supplies the dial. A quorum of holders drawn from
distinct governance domains endorses a pace epoch: a small state record carrying
a monotonically increasing epoch number, a continuous decay rate, an effective
time, and a scope.

Consumers already evaluate authority as a decaying function of time since a
grant was anchored. The epoch sets the rate in that function, so raising the
rate shortens the half-life of every outstanding grant inside the scope at once.
Autonomy contracts smoothly everywhere without any grant being revoked, without
enumerating the systems affected, and without any message having to reach them.

The quorum endorses a state transition and not an identity credential. The
record carries no subject, so the quorum's authority is confined to modifying
how standing is evaluated.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._common import (
    PacingError,
    base_credential,
    digest_of,
    iso,
    now_utc,
    parse_iso,
    subject_of,
    verify_credential,
)

ENDORSEMENT_TYPE = "VouchPaceEpochEndorsement"

CLASS_ROUTINE = "routine"
CLASS_ELEVATED = "elevated"
CLASS_CONSEQUENTIAL = "consequential"
CLASS_IRREVERSIBLE = "irreversible"

# Ordered from least to most consequential. Contraction runs in reverse.
CONSEQUENCE_ORDER: Tuple[str, ...] = (
    CLASS_ROUTINE,
    CLASS_ELEVATED,
    CLASS_CONSEQUENTIAL,
    CLASS_IRREVERSIBLE,
)

DEFAULT_THRESHOLDS: Dict[str, float] = {
    CLASS_ROUTINE: 0.20,
    CLASS_ELEVATED: 0.50,
    CLASS_CONSEQUENTIAL: 0.75,
    CLASS_IRREVERSIBLE: 0.90,
}

REASON_INVALID_ENDORSEMENT = "invalid_endorsement"
REASON_QUORUM_NOT_MET = "quorum_not_met"
REASON_DUPLICATE_HOLDER = "duplicate_holder"
REASON_NOT_A_HOLDER = "not_a_holder"
REASON_EPOCH_REGRESSION = "epoch_regression"
REASON_DIGEST_MISMATCH = "epoch_digest_mismatch"


def pace_epoch(
    *,
    epoch: int,
    pace_lambda: float,
    effective_from: Optional[datetime] = None,
    scope: Optional[Sequence[str]] = None,
    class_overrides: Optional[Dict[str, float]] = None,
    statement: str = "",
) -> Dict[str, Any]:
    """
    Build the unsigned pace epoch record.

    Args:
        epoch: A monotonically increasing epoch number.
        pace_lambda: The decay rate applied to authority standing, per second.
            Larger values contract authority faster.
        effective_from: When the epoch takes effect. Defaults to now.
        scope: Activity classes the epoch governs. Empty means all activity.
        class_overrides: Per-class rate overrides.
        statement: A short human-readable note carried with the record.
    """
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise PacingError("epoch must be a non-negative int")
    if not isinstance(pace_lambda, (int, float)) or pace_lambda < 0:
        raise PacingError("pace_lambda must be a non-negative number")
    effective = (effective_from or now_utc()).astimezone(timezone.utc)
    record: Dict[str, Any] = {
        "type": "VouchPaceEpoch",
        "epoch": int(epoch),
        "paceLambda": float(pace_lambda),
        "effectiveFrom": iso(effective),
        "scope": list(scope or []),
    }
    if class_overrides:
        record["classOverrides"] = {str(k): float(v) for k, v in class_overrides.items()}
    if statement:
        record["statement"] = statement
    return record


def epoch_digest(record: Dict[str, Any]) -> str:
    """Canonical digest of a pace epoch record."""
    return digest_of(record)


def endorse_epoch(holder_signer: Any, record: Dict[str, Any]) -> Dict[str, Any]:
    """One quorum holder's endorsement of a pace epoch record."""
    return base_credential(
        holder_signer,
        ENDORSEMENT_TYPE,
        {
            "id": epoch_digest(record),
            "holder": holder_signer.get_did(),
            "epoch": int(record.get("epoch", -1)),
        },
    )


@dataclass(frozen=True)
class QuorumPolicy:
    """Who holds shares of the pace control, and how many must agree."""

    holders: Tuple[str, ...]
    minimum: int

    def __post_init__(self) -> None:
        if self.minimum < 1:
            raise PacingError("quorum minimum must be at least 1")
        if self.minimum > len(self.holders):
            raise PacingError("quorum minimum exceeds the number of holders")
        if len(set(self.holders)) != len(self.holders):
            raise PacingError("holders must be distinct")


def verify_epoch(
    record: Dict[str, Any],
    endorsements: Sequence[Dict[str, Any]],
    policy: QuorumPolicy,
    holder_public_keys: Dict[str, Any],
) -> List[str]:
    """
    Check that a quorum of distinct holders endorsed this exact record.

    Returns the reasons the epoch is not in force. An empty list means the
    quorum is met by valid endorsements from distinct named holders over this
    record's digest.
    """
    reasons: List[str] = []
    digest = epoch_digest(record)
    seen: set = set()
    for endorsement in endorsements:
        subject = endorsement.get("credentialSubject") or {}
        holder = subject.get("holder")
        if holder not in policy.holders:
            reasons.append(REASON_NOT_A_HOLDER)
            continue
        if not verify_credential(endorsement, holder_public_keys.get(holder), ENDORSEMENT_TYPE):
            reasons.append(REASON_INVALID_ENDORSEMENT)
            continue
        if endorsement.get("issuer") != holder:
            reasons.append(REASON_INVALID_ENDORSEMENT)
            continue
        if subject.get("id") != digest:
            reasons.append(REASON_DIGEST_MISMATCH)
            continue
        if holder in seen:
            reasons.append(REASON_DUPLICATE_HOLDER)
            continue
        seen.add(holder)
    if len(seen) < policy.minimum:
        reasons.append(REASON_QUORUM_NOT_MET)
    return reasons


def select_epoch(
    records: Sequence[Dict[str, Any]],
    *,
    at_time: Optional[datetime] = None,
    floor_epoch: int = -1,
) -> Optional[Dict[str, Any]]:
    """
    Choose the epoch in force: the highest effective one, never regressing.

    A verifier that has already observed epoch N will not accept an older,
    slower epoch, so a prior rate cannot be replayed to restore authority.
    """
    moment = (at_time or now_utc()).astimezone(timezone.utc)
    best: Optional[Dict[str, Any]] = None
    for record in records:
        try:
            effective = parse_iso(str(record.get("effectiveFrom")))
        except PacingError:
            continue
        number = record.get("epoch")
        if not isinstance(number, int) or number <= floor_epoch:
            continue
        if effective > moment:
            continue
        if best is None or number > int(best.get("epoch", -1)):
            best = record
    return best


def effective_lambda(
    record: Optional[Dict[str, Any]],
    *,
    consequence_class: str = CLASS_ROUTINE,
    default_lambda: float = 0.0,
    last_observed: Optional[datetime] = None,
    max_age_seconds: Optional[int] = None,
    stale_lambda: Optional[float] = None,
    at_time: Optional[datetime] = None,
) -> float:
    """
    The decay rate a verifier should apply right now.

    Silence contracts authority. A verifier that has not observed a current
    epoch within ``max_age_seconds`` applies the more conservative of the last
    known rate and the declared stale rate, so a failure of the coordination
    channel is not the same as permission to continue at full authority.
    """
    base = float(default_lambda)
    if record is not None:
        base = float(record.get("paceLambda", default_lambda))
        overrides = record.get("classOverrides") or {}
        if consequence_class in overrides:
            base = float(overrides[consequence_class])
    if max_age_seconds is not None and stale_lambda is not None:
        moment = (at_time or now_utc()).astimezone(timezone.utc)
        if last_observed is None:
            return max(base, float(stale_lambda))
        age = (moment - last_observed.astimezone(timezone.utc)).total_seconds()
        if age > max_age_seconds:
            return max(base, float(stale_lambda))
    return base


def effective_standing(
    *,
    anchored_at: datetime,
    initial_standing: float,
    pace_lambda: float,
    at_time: Optional[datetime] = None,
) -> float:
    """
    Standing of a grant under the prevailing rate.

    ``standing(t) = initial * exp(-lambda * elapsed_seconds)``, the same decay
    model the protocol already uses for session trust, with the rate supplied by
    the pace epoch rather than by the grant.
    """
    if initial_standing < 0:
        raise PacingError("initial_standing must be non-negative")
    if pace_lambda < 0:
        raise PacingError("pace_lambda must be non-negative")
    moment = (at_time or now_utc()).astimezone(timezone.utc)
    elapsed = (moment - anchored_at.astimezone(timezone.utc)).total_seconds()
    if elapsed <= 0:
        return float(initial_standing)
    return float(initial_standing) * math.exp(-float(pace_lambda) * elapsed)


def permitted_classes(standing: float, thresholds: Optional[Dict[str, float]] = None) -> List[str]:
    """
    Which consequence classes remain available at this standing.

    Contraction is ordered by consequence as a consequence of the thresholds:
    raising the rate removes irreversible operations first, then consequential
    ones, and so on down.
    """
    table = thresholds or DEFAULT_THRESHOLDS
    return [name for name in CONSEQUENCE_ORDER if standing >= table.get(name, 1.0)]


def permits(
    consequence_class: str, standing: float, thresholds: Optional[Dict[str, float]] = None
) -> bool:
    """True if an operation of this class may proceed at this standing."""
    table = thresholds or DEFAULT_THRESHOLDS
    if consequence_class not in table:
        raise PacingError(f"unknown consequence class: {consequence_class!r}")
    return standing >= table[consequence_class]


def half_life_seconds(pace_lambda: float) -> float:
    """How long a grant takes to lose half its standing at this rate."""
    if pace_lambda <= 0:
        return float("inf")
    return math.log(2.0) / float(pace_lambda)
