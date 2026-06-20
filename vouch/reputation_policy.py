"""
Reputation policy and token attachment (reputation Phase 4).

The consumer side. `evaluate_reputation` takes a ReputationScore or a signed
ReputationCredential snapshot and a `ReputationPolicy` (minimum composite,
per-dimension minimums, optional freshness) and returns an allow or deny
decision with reasons. This is the check a verifier runs after it has verified
the Vouch token itself, so trust becomes "authentic AND has standing."

`reputation_pointer` builds the small reference object an issuer embeds in a
token (at build time, before signing) to point at the agent's reputation record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from .reputation_aggregate import ReputationScore
from .reputation_ledger import REPUTATION_CREDENTIAL_TYPE, verify_reputation_credential


@dataclass
class ReputationPolicy:
    min_composite: float = 0.0
    min_dimensions: Dict[str, float] = field(default_factory=dict)
    max_age_seconds: Optional[int] = None


STAKES: Dict[str, ReputationPolicy] = {
    "high": ReputationPolicy(min_composite=75.0, min_dimensions={"compliance": 60.0}),
    "medium": ReputationPolicy(min_composite=60.0),
    "low": ReputationPolicy(min_composite=50.0),
}


def policy_for_stakes(level: str) -> ReputationPolicy:
    """A sensible default policy for high, medium, or low stakes decisions."""
    if level not in STAKES:
        raise ValueError(f"unknown stakes level: {level!r}")
    return STAKES[level]


@dataclass
class ReputationDecision:
    allowed: bool
    composite: float
    failures: List[str] = field(default_factory=list)


def _coerce(
    value: Union[ReputationScore, Dict[str, Any]],
    public_key: Any,
    policy: ReputationPolicy,
    at: Optional[datetime],
) -> "tuple[Optional[float], Dict[str, float], List[str]]":
    """Return (composite, dimensions, failures-from-snapshot-checks)."""
    if isinstance(value, ReputationScore):
        return value.composite, dict(value.dimensions), []

    if not isinstance(value, dict):
        return None, {}, ["unrecognized reputation value"]

    types = value.get("type")
    is_snapshot = isinstance(types, list) and REPUTATION_CREDENTIAL_TYPE in types
    if is_snapshot:
        if public_key is not None:
            ok, _ = verify_reputation_credential(value, public_key)
            if not ok:
                return None, {}, ["snapshot signature did not verify"]
        failures: List[str] = []
        if policy.max_age_seconds is not None and at is not None:
            try:
                issued = datetime.strptime(value.get("validFrom"), "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
                if (at.astimezone(timezone.utc) - issued).total_seconds() > policy.max_age_seconds:
                    failures.append("snapshot is stale")
            except (TypeError, ValueError):
                failures.append("snapshot has no usable validFrom")
        score = (value.get("credentialSubject") or {}).get("score") or {}
        return score.get("composite"), dict(score.get("dimensions") or {}), failures

    # plain {composite, dimensions}
    return value.get("composite"), dict(value.get("dimensions") or {}), []


def evaluate_reputation(
    value: Union[ReputationScore, Dict[str, Any]],
    policy: ReputationPolicy,
    *,
    public_key: Any = None,
    at: Optional[datetime] = None,
) -> ReputationDecision:
    """Decide whether a reputation meets a policy. Verifies a snapshot if a key is given."""
    composite, dimensions, failures = _coerce(value, public_key, policy, at)
    failures = list(failures)

    if composite is None:
        failures.append("no composite score available")
        return ReputationDecision(allowed=False, composite=0.0, failures=failures)

    if composite < policy.min_composite:
        failures.append(f"composite {composite} < required {policy.min_composite}")
    for dim, minimum in policy.min_dimensions.items():
        if dimensions.get(dim, 0.0) < minimum:
            failures.append(f"{dim} {dimensions.get(dim, 0.0)} < required {minimum}")

    return ReputationDecision(allowed=not failures, composite=composite, failures=failures)


def reputation_pointer(
    *,
    registry: str,
    record: Optional[str] = None,
    subject: Optional[str] = None,
    evidence_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an AccountabilityRecord pointer to an agent's reputation record, for
    embedding in a token's subject at build time (before signing).
    """
    if not registry:
        raise ValueError("registry is required")
    pointer: Dict[str, Any] = {
        "type": "AccountabilityRecord",
        "kind": "reputation",
        "ledger": registry,
    }
    if record is not None:
        pointer["record"] = record
    if subject is not None:
        pointer["subject"] = subject
    if evidence_root is not None:
        pointer["evidenceRoot"] = evidence_root
    return pointer


__all__ = [
    "ReputationPolicy",
    "ReputationDecision",
    "STAKES",
    "policy_for_stakes",
    "evaluate_reputation",
    "reputation_pointer",
]
