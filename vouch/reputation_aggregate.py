"""
Evidence-backed reputation aggregation (reputation Phase 2).

The deterministic, versioned function that turns normalized `Signal`s into a
multi-dimensional reputation score. It is pure: given the same signals, the same
evaluation time `at`, and the same configuration, any party computes the same
score, so a consumer can recompute and verify rather than trust a server.

Each signal contributes to its dimension with weight

    type_weight(source) * decay(age) * issuer_weight(issuer)

A dimension score is the baseline plus the weighted-mean signal value scaled
across the span, clamped to [0, 100]. The composite is the support-weighted mean
of the present dimensions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

from .receipts import Signal, normalize_receipt, receipt_subject

AGGREGATION_VERSION = "1.0"

DEFAULT_TYPE_WEIGHTS: Dict[str, float] = {
    "StateReceipt": 1.0,
    "OutcomeAttestationCredential": 1.0,
    "PenaltyReceipt": 1.0,
    "ReviewCredential": 0.4,
}
DEFAULT_HALF_LIFE_DAYS = 90.0
BASELINE = 50.0
SPAN = 50.0

IssuerWeight = Union[Callable[[str], float], Dict[str, float], None]


@dataclass
class ReputationScore:
    version: str
    dimensions: Dict[str, float] = field(default_factory=dict)
    composite: float = BASELINE
    support: Dict[str, float] = field(default_factory=dict)
    count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "composite": self.composite,
            "dimensions": self.dimensions,
            "support": self.support,
            "count": self.count,
        }


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _decay(age_days: float, half_life_days: float) -> float:
    if half_life_days <= 0:
        return 1.0
    return 0.5 ** (max(0.0, age_days) / half_life_days)


def _issuer_weight(iw: IssuerWeight, issuer: str) -> float:
    if iw is None:
        return 1.0
    if callable(iw):
        return float(iw(issuer))
    return float(iw.get(issuer, 1.0))


def aggregate(
    signals: Iterable[Signal],
    *,
    at: Optional[datetime] = None,
    type_weights: Optional[Dict[str, float]] = None,
    issuer_weight: IssuerWeight = None,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
    baseline: float = BASELINE,
    span: float = SPAN,
) -> ReputationScore:
    """Aggregate normalized signals into a multi-dimensional ReputationScore."""
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    tw = type_weights or DEFAULT_TYPE_WEIGHTS

    acc: Dict[str, List[float]] = {}  # dimension -> [weighted_value_sum, weight_sum]
    count = 0
    for s in signals:
        count += 1
        age_days = (now - s.timestamp.astimezone(timezone.utc)).total_seconds() / 86400.0
        w = (
            tw.get(s.source_type, 0.5)
            * _decay(age_days, half_life_days)
            * _issuer_weight(issuer_weight, s.issuer)
        )
        if w <= 0:
            continue
        a = acc.setdefault(s.dimension, [0.0, 0.0])
        a[0] += _clamp(s.value, -1.0, 1.0) * w
        a[1] += w

    dimensions: Dict[str, float] = {}
    support: Dict[str, float] = {}
    for dim, (num, den) in acc.items():
        support[dim] = round(den, 6)
        dimensions[dim] = (
            round(_clamp(baseline + span * (num / den), 0.0, 100.0), 2) if den > 0 else baseline
        )

    if support:
        total = sum(support.values())
        composite = (
            sum(dimensions[d] * support[d] for d in dimensions) / total if total > 0 else baseline
        )
    else:
        composite = baseline

    return ReputationScore(
        version=AGGREGATION_VERSION,
        dimensions=dimensions,
        composite=round(composite, 2),
        support=support,
        count=count,
    )


def aggregate_receipts(
    receipts: Iterable[Dict[str, Any]],
    *,
    agent: Optional[str] = None,
    **kwargs: Any,
) -> ReputationScore:
    """
    Convenience: normalize a list of receipt credentials and aggregate them. When
    `agent` is given, only receipts about that agent are included. Signature
    verification is the caller's responsibility (the service layer does it before
    calling this); this function trusts the receipts it is handed.
    """
    signals: List[Signal] = []
    for r in receipts:
        if agent is not None and receipt_subject(r) != agent:
            continue
        signals.extend(normalize_receipt(r))
    return aggregate(signals, **kwargs)


__all__ = [
    "AGGREGATION_VERSION",
    "DEFAULT_TYPE_WEIGHTS",
    "DEFAULT_HALF_LIFE_DAYS",
    "BASELINE",
    "SPAN",
    "ReputationScore",
    "aggregate",
    "aggregate_receipts",
]
