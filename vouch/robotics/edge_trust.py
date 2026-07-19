"""
Edge trust-conditioning primitives:

  - PAD-115: attested time-quality as a trust input. A node signs its clock source
    and a bounded time uncertainty; a verifier admits a time-dependent decision only
    when the attested uncertainty is within a consequence-scaled budget.
  - PAD-117: connectivity-scaled autonomy envelope. A node's permitted authority
    envelope narrows as its time since last trusted contact grows, selected offline
    from a signed, attenuating decay schedule.
  - PAD-118: radiation/fault-aware key attestation. A node attests cumulative
    integrity risk to its key store; crossing thresholds narrows authority or flags
    the key as suspect for re-attestation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..status_list import (
    CONSEQUENCE_CRITICAL,
    CONSEQUENCE_ROUTINE,
    CONSEQUENCE_SENSITIVE,
    VALID_CONSEQUENCE_TIERS,
)
from .capability import PhysicalAction, attenuates, check_physical_action
from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
TIME_QUALITY_TYPE = "TimeQualityAttestation"
AUTONOMY_SCHEDULE_TYPE = "AutonomyDecaySchedule"
INTEGRITY_RISK_TYPE = "IntegrityRiskAttestation"


# --------------------------------------------------------------------------- #
# PAD-115: attested time-quality
# --------------------------------------------------------------------------- #

# Default maximum acceptable time uncertainty (seconds) per consequence tier.
DEFAULT_TIME_UNCERTAINTY_BUDGET: Dict[str, float] = {
    CONSEQUENCE_ROUTINE: 3600.0,
    CONSEQUENCE_SENSITIVE: 60.0,
    CONSEQUENCE_CRITICAL: 1.0,
}


def build_time_quality_attestation(
    signer: Any,
    *,
    source_class: str,
    since_discipline_s: float,
    uncertainty_s: float,
) -> Dict[str, Any]:
    """A node attests its clock source class and a bounded time uncertainty, bound to its identity."""
    if uncertainty_s < 0 or since_discipline_s < 0:
        raise RoboticsError("uncertainty_s and since_discipline_s must be non-negative")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", TIME_QUALITY_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": {
            "id": signer.get_did(),
            "sourceClass": source_class,
            "sinceDisciplineS": float(since_discipline_s),
            "uncertaintyS": float(uncertainty_s),
        },
    }
    return attach_proof(credential, signer)


def verify_time_quality_attestation(
    attestation: Dict[str, Any], public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(attestation, public_key, TIME_QUALITY_TYPE)
    return (subject is not None), subject


def time_quality_permits(
    subject: Dict[str, Any],
    *,
    tier: str = CONSEQUENCE_CRITICAL,
    budgets: Optional[Dict[str, float]] = None,
) -> bool:
    """
    Admit a time-dependent decision only if the attested uncertainty is within the
    consequence-scaled budget. Unknown tier is treated as critical (fail-closed).
    When this returns False the caller should fall back to epoch-based checks.
    """
    if tier not in VALID_CONSEQUENCE_TIERS:
        tier = CONSEQUENCE_CRITICAL
    unc = subject.get("uncertaintyS")
    if not isinstance(unc, (int, float)):
        return False
    budget = (budgets or DEFAULT_TIME_UNCERTAINTY_BUDGET).get(
        tier, DEFAULT_TIME_UNCERTAINTY_BUDGET[CONSEQUENCE_CRITICAL]
    )
    return float(unc) <= budget


# --------------------------------------------------------------------------- #
# PAD-117: connectivity-scaled autonomy envelope
# --------------------------------------------------------------------------- #


def build_autonomy_schedule(
    authority_signer: Any,
    *,
    subject_did: str,
    steps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    A signed decay schedule: `steps` is a list of
    {"maxStalenessEpochs": int, "physicalScope": {...}} ordered by ascending
    staleness, each scope attenuating the previous (widest first). Validated on build.
    """
    if not steps:
        raise RoboticsError("steps must be non-empty")
    prev_thresh = -1
    prev_scope: Optional[Dict[str, Any]] = None
    for st in steps:
        thresh = st.get("maxStalenessEpochs")
        scope = st.get("physicalScope")
        if not isinstance(thresh, int) or thresh <= prev_thresh:
            raise RoboticsError("maxStalenessEpochs must be strictly ascending integers")
        if not isinstance(scope, dict):
            raise RoboticsError("each step needs a physicalScope object")
        if prev_scope is not None and not attenuates(prev_scope, scope):
            raise RoboticsError("each step's scope must attenuate the previous (narrow only)")
        prev_thresh, prev_scope = thresh, scope
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", AUTONOMY_SCHEDULE_TYPE],
        "issuer": authority_signer.get_did(),
        "credentialSubject": {"id": subject_did, "steps": steps},
    }
    return attach_proof(credential, authority_signer)


def verify_autonomy_schedule(
    schedule: Dict[str, Any], authority_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(schedule, authority_public_key, AUTONOMY_SCHEDULE_TYPE)
    return (subject is not None), subject


def select_envelope(schedule_subject: Dict[str, Any], staleness_epochs: int) -> Optional[Dict[str, Any]]:
    """
    Select the applicable physical scope for the current staleness: the first step
    whose maxStalenessEpochs >= staleness. Beyond the last step (most stale), returns
    the tightest step's scope. Returns None if the schedule is empty.
    """
    steps = schedule_subject.get("steps") or []
    for st in steps:
        if staleness_epochs <= st.get("maxStalenessEpochs"):
            return st.get("physicalScope")
    return steps[-1].get("physicalScope") if steps else None


def autonomy_permits(
    schedule_subject: Dict[str, Any], staleness_epochs: int, action: PhysicalAction
) -> bool:
    """Admit an action only if it fits the envelope selected for the current staleness."""
    scope = select_envelope(schedule_subject, staleness_epochs)
    if not isinstance(scope, dict):
        return False
    return check_physical_action(scope, action).ok


# --------------------------------------------------------------------------- #
# PAD-118: radiation/fault-aware key attestation
# --------------------------------------------------------------------------- #

INTEGRITY_FULL = "full"
INTEGRITY_NARROWED = "narrowed"
INTEGRITY_SUSPECT = "suspect"


def build_integrity_risk_attestation(
    signer: Any,
    *,
    cumulative_risk: float,
    metrics: Optional[Dict[str, Any]] = None,
    prev_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    A node signs its cumulative key-store integrity risk (a normalized scalar),
    hash-linked to the prior attestation, bound to its identity.
    """
    if cumulative_risk < 0:
        raise RoboticsError("cumulative_risk must be non-negative")
    subject: Dict[str, Any] = {
        "id": signer.get_did(),
        "cumulativeRisk": float(cumulative_risk),
    }
    if metrics is not None:
        subject["metrics"] = metrics
    if prev_hash is not None:
        subject["prevHash"] = prev_hash
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", INTEGRITY_RISK_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": subject,
    }
    return attach_proof(credential, signer)


def verify_integrity_risk_attestation(
    attestation: Dict[str, Any], public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(attestation, public_key, INTEGRITY_RISK_TYPE)
    return (subject is not None), subject


def integrity_authority_level(
    cumulative_risk: float,
    *,
    narrow_threshold: float = 0.3,
    suspect_threshold: float = 0.7,
) -> str:
    """
    Deterministic risk-to-authority mapping: below `narrow_threshold` full authority;
    below `suspect_threshold` a narrowed envelope; at or above it the key is suspect
    and should be re-attested or rotated (PAD-116).
    """
    if cumulative_risk >= suspect_threshold:
        return INTEGRITY_SUSPECT
    if cumulative_risk >= narrow_threshold:
        return INTEGRITY_NARROWED
    return INTEGRITY_FULL


__all__ = [
    "TIME_QUALITY_TYPE",
    "AUTONOMY_SCHEDULE_TYPE",
    "INTEGRITY_RISK_TYPE",
    "DEFAULT_TIME_UNCERTAINTY_BUDGET",
    "INTEGRITY_FULL",
    "INTEGRITY_NARROWED",
    "INTEGRITY_SUSPECT",
    "build_time_quality_attestation",
    "verify_time_quality_attestation",
    "time_quality_permits",
    "build_autonomy_schedule",
    "verify_autonomy_schedule",
    "select_envelope",
    "autonomy_permits",
    "build_integrity_risk_attestation",
    "verify_integrity_risk_attestation",
    "integrity_authority_level",
]
