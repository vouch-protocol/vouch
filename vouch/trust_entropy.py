"""
Trust Entropy decay computation for SessionVoucher consumption.

Implements the verifier-side computation of time-decaying trust per
Specification §11.5. A SessionVoucher carries `initialTrust` and
`decayLambda` parameters; verifiers compute the current trust at the
moment of verification and compare against operation-specific
thresholds.

Formula (Specification §11.5):

  trust(t) = initialTrust * exp(-decayLambda * (t - issuedAt))

where t is the verification time, issuedAt is the SessionVoucher's
`validFrom`, and elapsed time is measured in seconds.

Typical threshold profile for a regulated-sector deployment:
- High-stakes operations (e.g., financial transfers): trust >= 0.9
- Medium-stakes operations (e.g., PHI reads): trust >= 0.75
- Low-stakes operations (e.g., status queries): trust >= 0.5

A SessionVoucher whose computed trust falls below the operation
threshold MUST be rejected, even if the credential's `validUntil` has
not yet passed. This is the "untrusted until renewed" half of the
Heartbeat Protocol contract.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


# Threshold band conventions described in Specification §11.5. Implementers MAY
# substitute their own per-operation thresholds; these are reference values.
TRUST_THRESHOLD_HIGH_STAKES = 0.9
TRUST_THRESHOLD_MEDIUM_STAKES = 0.75
TRUST_THRESHOLD_LOW_STAKES = 0.5

SESSION_VOUCHER_TYPE = "SessionVoucher"


class TrustEntropyError(Exception):
    """Raised when trust computation cannot proceed."""


@dataclass
class TrustEvaluation:
    """
    Result of evaluating a SessionVoucher's current trust value.

    Attributes:
      trust: Computed trust value in [0, initialTrust].
      threshold: Threshold the caller compared against.
      passed: True if trust >= threshold.
      elapsed_seconds: Seconds since the voucher's validFrom.
      initial_trust: The voucher's initialTrust parameter.
      decay_lambda: The voucher's decayLambda parameter.
      evaluated_at: UTC datetime of the evaluation.
    """

    trust: float
    threshold: float
    passed: bool
    elapsed_seconds: float
    initial_trust: float
    decay_lambda: float
    evaluated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trust": self.trust,
            "threshold": self.threshold,
            "passed": self.passed,
            "elapsed_seconds": self.elapsed_seconds,
            "initial_trust": self.initial_trust,
            "decay_lambda": self.decay_lambda,
            "evaluated_at": self.evaluated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


def compute_trust_at(
    session_voucher: Dict[str, Any],
    at_time: Optional[datetime] = None,
) -> float:
    """
    Compute the current trust value of `session_voucher` at `at_time`.

    Args:
      session_voucher: A signed or unsigned SessionVoucher VC dict.
        MUST have credentialSubject.initialTrust, credentialSubject.decayLambda,
        and the top-level validFrom field.
      at_time: Evaluation moment. Defaults to current UTC.

    Returns:
      Trust value in [0, initialTrust].

    Raises:
      TrustEntropyError: if the voucher is malformed or required fields are missing.
    """
    if not isinstance(session_voucher, dict):
        raise TrustEntropyError("session_voucher must be a dict")

    type_field = session_voucher.get("type", [])
    if isinstance(type_field, str):
        type_field = [type_field]
    if SESSION_VOUCHER_TYPE not in type_field:
        raise TrustEntropyError(
            f"credential type must include {SESSION_VOUCHER_TYPE}, got {type_field}"
        )

    subject = session_voucher.get("credentialSubject")
    if not isinstance(subject, dict):
        raise TrustEntropyError("credentialSubject is required")

    try:
        initial_trust = float(subject["initialTrust"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TrustEntropyError(f"credentialSubject.initialTrust must be a number: {exc}") from exc

    try:
        decay_lambda = float(subject["decayLambda"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TrustEntropyError(f"credentialSubject.decayLambda must be a number: {exc}") from exc

    if initial_trust < 0:
        raise TrustEntropyError(f"initialTrust must be non-negative, got {initial_trust}")
    if decay_lambda < 0:
        raise TrustEntropyError(f"decayLambda must be non-negative, got {decay_lambda}")

    valid_from_str = session_voucher.get("validFrom")
    if not valid_from_str:
        raise TrustEntropyError("validFrom is required")

    try:
        issued_at = _parse_iso_utc(valid_from_str)
    except ValueError as exc:
        raise TrustEntropyError(f"malformed validFrom: {exc}") from exc

    if at_time is None:
        at_time = datetime.now(timezone.utc)
    elif at_time.tzinfo is None:
        at_time = at_time.replace(tzinfo=timezone.utc)
    else:
        at_time = at_time.astimezone(timezone.utc)

    elapsed_seconds = (at_time - issued_at).total_seconds()
    if elapsed_seconds < 0:
        elapsed_seconds = 0.0

    # Guard against overflow in extreme inputs.
    exponent = -decay_lambda * elapsed_seconds
    if exponent < -700:
        return 0.0

    return initial_trust * math.exp(exponent)


def evaluate_trust(
    session_voucher: Dict[str, Any],
    threshold: float,
    at_time: Optional[datetime] = None,
) -> TrustEvaluation:
    """
    Compute the current trust and return a structured evaluation result.

    Convenience wrapper around `compute_trust_at` that also captures the
    parameters that produced the result, for logging and audit trails.
    """
    if threshold < 0:
        raise TrustEntropyError(f"threshold must be non-negative, got {threshold}")

    eval_time = at_time
    if eval_time is None:
        eval_time = datetime.now(timezone.utc)
    elif eval_time.tzinfo is None:
        eval_time = eval_time.replace(tzinfo=timezone.utc)

    trust = compute_trust_at(session_voucher, eval_time)

    subject = session_voucher["credentialSubject"]
    initial_trust = float(subject["initialTrust"])
    decay_lambda = float(subject["decayLambda"])
    issued_at = _parse_iso_utc(session_voucher["validFrom"])
    elapsed_seconds = max(0.0, (eval_time - issued_at).total_seconds())

    return TrustEvaluation(
        trust=trust,
        threshold=threshold,
        passed=trust >= threshold,
        elapsed_seconds=elapsed_seconds,
        initial_trust=initial_trust,
        decay_lambda=decay_lambda,
        evaluated_at=eval_time,
    )


def check_trust_threshold(
    session_voucher: Dict[str, Any],
    threshold: float,
    at_time: Optional[datetime] = None,
) -> bool:
    """
    Return True if the SessionVoucher's current trust >= threshold.

    Shorthand for `evaluate_trust(...).passed`.
    """
    return evaluate_trust(session_voucher, threshold, at_time).passed


def half_life_seconds(decay_lambda: float) -> float:
    """
    Return the half-life (in seconds) of a SessionVoucher with the given decayLambda.

    Useful for operators sizing heartbeat intervals: the heartbeat interval
    SHOULD be < half-life so renewal happens before trust degrades below
    the medium-stakes threshold.

    Half-life formula: t_half = ln(2) / decayLambda
    """
    if decay_lambda <= 0:
        raise TrustEntropyError(
            f"decayLambda must be positive to have a finite half-life, got {decay_lambda}"
        )
    return math.log(2) / decay_lambda


def time_until_threshold(
    session_voucher: Dict[str, Any],
    threshold: float,
    from_time: Optional[datetime] = None,
) -> Optional[timedelta]:
    """
    Return the timedelta until the SessionVoucher's trust decays to `threshold`.

    Solves: threshold = initialTrust * exp(-decayLambda * t)
    -> t = ln(initialTrust / threshold) / decayLambda

    Returns None if trust will never decay to the threshold (e.g., threshold
    is above initialTrust, or decayLambda is 0). Returns a zero timedelta
    if the threshold has already been crossed.
    """
    if not isinstance(session_voucher, dict):
        raise TrustEntropyError("session_voucher must be a dict")

    subject = session_voucher.get("credentialSubject") or {}
    try:
        initial_trust = float(subject["initialTrust"])
        decay_lambda = float(subject["decayLambda"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TrustEntropyError(
            f"credentialSubject.initialTrust and .decayLambda required: {exc}"
        ) from exc

    if threshold <= 0:
        return None  # trust never reaches zero
    if threshold > initial_trust:
        return timedelta(0)  # already below threshold from t=0
    if decay_lambda == 0:
        return None  # constant trust

    seconds_to_threshold = math.log(initial_trust / threshold) / decay_lambda

    if from_time is None:
        from_time = datetime.now(timezone.utc)
    elif from_time.tzinfo is None:
        from_time = from_time.replace(tzinfo=timezone.utc)

    issued_at = _parse_iso_utc(session_voucher["validFrom"])
    elapsed = max(0.0, (from_time - issued_at).total_seconds())
    remaining = seconds_to_threshold - elapsed
    if remaining <= 0:
        return timedelta(0)
    return timedelta(seconds=remaining)


def _parse_iso_utc(iso_str: str) -> datetime:
    """Parse -VC ISO timestamp format used in Vouch credentials."""
    if iso_str.endswith("Z"):
        return datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    # Fallback for full ISO-8601 with offset (e.g., +00:00).
    return datetime.fromisoformat(iso_str).astimezone(timezone.utc)


__all__ = [
    "TRUST_THRESHOLD_HIGH_STAKES",
    "TRUST_THRESHOLD_MEDIUM_STAKES",
    "TRUST_THRESHOLD_LOW_STAKES",
    "SESSION_VOUCHER_TYPE",
    "TrustEntropyError",
    "TrustEvaluation",
    "compute_trust_at",
    "evaluate_trust",
    "check_trust_threshold",
    "half_life_seconds",
    "time_until_threshold",
]
