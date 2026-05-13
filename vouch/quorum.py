"""
Validator Quorum coordination for the Heartbeat Protocol.

Extends the single-validator HeartbeatValidator with M-of-N federation
per Specification §11.6. A heartbeat request is validated by N
validators in parallel; the SessionVoucher is issued only if at least M
of them approve. Each approving validator's DID is recorded as a
co-issuer on the SessionVoucher, and each MAY attach its own Data
Integrity proof (signing is left to the caller).

Why quorum?

Single validators are single points of failure and single points of
trust. A regulated deployment SHOULD use multiple validators with
different operational responsibilities and (where possible) different
operators:

- Policy validators check the agent's authorization scope against
 organizational policy.
- Behavioral validators check the behavioralDigest against learned
 baselines and anomaly thresholds.
- Budget validators check that token / API-call counts remain within
 approved limits.

A 2-of-3 quorum lets one validator be unavailable or compromised
without halting the agent; a 3-of-5 quorum is even more tolerant.

Trust parameter aggregation:

When multiple validators agree but configure different initial_trust /
decay_lambda values, the quorum aggregates conservatively:
- initial_trust: minimum (most cautious).
- decay_lambda: maximum (fastest decay = shortest effective trust window).
- scope: intersection (only allow capabilities ALL approving validators allow).

These defaults are configurable via QuorumPolicy.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from .heartbeat import (
    HeartbeatError,
    HeartbeatRequest,
    HeartbeatValidationResult,
    HeartbeatValidator,
)
from .vc import build_session_voucher


# Roles for documentation / audit. The protocol treats all approving
# validators as equivalent for the M-of-N count regardless of role.
ROLE_GENERAL = "general"
ROLE_POLICY = "policy"
ROLE_BEHAVIORAL = "behavioral"
ROLE_BUDGET = "budget"


class QuorumError(Exception):
    """Raised on quorum configuration or coordination failures."""


@dataclass
class QuorumValidator:
    """
    One validator participant in a quorum.

    Attributes:
      validator: The underlying HeartbeatValidator instance.
      role: Documentation label (general, policy, behavioral, budget).
        Does not affect quorum counting.
      weight: For weighted quorum schemes. Default 1.0 means each
        validator counts as one vote toward the threshold.
        Set higher to give a validator more voting power (e.g., 2.0
        so its approval counts as two of the M threshold).
    """

    validator: HeartbeatValidator
    role: str = ROLE_GENERAL
    weight: float = 1.0

    def __post_init__(self) -> None:
        if self.weight <= 0:
            raise QuorumError(f"weight must be positive, got {self.weight}")


@dataclass
class QuorumPolicy:
    """
    Aggregation policy for trust parameters when multiple validators agree.

    Each setting is a callable so callers can plug in custom strategies.
    Defaults use the conservative aggregators described in the module
    docstring.
    """

    initial_trust_aggregator: Callable[[List[float]], float] = field(default_factory=lambda: min)
    decay_lambda_aggregator: Callable[[List[float]], float] = field(default_factory=lambda: max)
    max_ttl_aggregator: Callable[[List[int]], int] = field(default_factory=lambda: min)
    voucher_valid_seconds_aggregator: Callable[[List[int]], int] = field(
        default_factory=lambda: min
    )


@dataclass
class QuorumResult:
    """
    Outcome of evaluating a heartbeat request against a quorum.

    Attributes:
      ok: True if the number of approving votes >= threshold.
      threshold: The quorum's M value at evaluation time.
      votes_for: Sum of weights of approving validators.
      approving_dids: DIDs of validators that approved (preserves
        insertion order from the quorum's validators list).
      rejections: validator DID -> list of structured failure reasons,
        for validators that rejected.
      session_voucher: If ok=True, an unsigned aggregate SessionVoucher
        with `issuer` set to the list of approving DIDs. None when
        ok=False.
    """

    ok: bool
    threshold: float
    votes_for: float
    approving_dids: List[str] = field(default_factory=list)
    rejections: Dict[str, List[str]] = field(default_factory=dict)
    session_voucher: Optional[Dict[str, Any]] = None


@dataclass
class HeartbeatQuorum:
    """
    M-of-N validator coordinator for the Heartbeat Protocol.

    Validates a heartbeat request by dispatching to each constituent
    HeartbeatValidator in parallel (logical parallel; the reference impl
    iterates sequentially because per-validator work is in-process).
    Issues an aggregate SessionVoucher when the sum of approving
    validators' weights meets or exceeds the threshold.

    Attributes:
      validators: List of QuorumValidator participants.
      threshold: Minimum sum of approving weights required for the
        quorum to approve. Typically equal to a count of validators
        when all weights are 1.0 (e.g., threshold=2 with 3 unit-weight
        validators is a 2-of-3 quorum).
      policy: Aggregation policy for trust parameters.

    The quorum does NOT enforce per-role minimums (e.g., "must have at
    least one policy validator approve"). Callers wanting role-aware
    quorums can compose multiple HeartbeatQuorum instances or supply
    a custom aggregator that inspects the approving set.
    """

    validators: List[QuorumValidator]
    threshold: float
    policy: QuorumPolicy = field(default_factory=QuorumPolicy)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.validators:
            raise QuorumError("quorum requires at least one validator")
        total_weight = sum(v.weight for v in self.validators)
        if self.threshold <= 0:
            raise QuorumError(f"threshold must be positive, got {self.threshold}")
        if self.threshold > total_weight:
            raise QuorumError(
                f"threshold {self.threshold} exceeds total quorum weight {total_weight}: "
                f"the quorum can never approve"
            )

        seen_dids: Set[str] = set()
        for qv in self.validators:
            did = qv.validator.validator_did
            if did in seen_dids:
                raise QuorumError(f"duplicate validator DID in quorum: {did}")
            seen_dids.add(did)

    def validate(self, request: Dict[str, Any]) -> QuorumResult:
        """
        Validate a heartbeat request against the quorum.

        Each constituent validator processes the request and contributes
        its weight to the votes_for tally on approval. When votes_for >=
        threshold the aggregate SessionVoucher is built.
        """
        approving: List[QuorumValidator] = []
        approving_results: List[HeartbeatValidationResult] = []
        rejections: Dict[str, List[str]] = {}

        with self._lock:
            for qv in self.validators:
                result = qv.validator.validate(request)
                if result.ok:
                    approving.append(qv)
                    approving_results.append(result)
                else:
                    rejections[qv.validator.validator_did] = result.reasons

        votes_for = sum(qv.weight for qv in approving)

        if votes_for < self.threshold:
            return QuorumResult(
                ok=False,
                threshold=self.threshold,
                votes_for=votes_for,
                approving_dids=[qv.validator.validator_did for qv in approving],
                rejections=rejections,
                session_voucher=None,
            )

        try:
            req = HeartbeatRequest.from_dict(request)
        except HeartbeatError as exc:
            # This should not happen: every validator already accepted the
            # request, so its shape is good. But guard anyway.
            raise QuorumError(f"request shape changed between validator runs: {exc}") from exc

        aggregate_voucher = self._build_aggregate_voucher(approving, req)

        return QuorumResult(
            ok=True,
            threshold=self.threshold,
            votes_for=votes_for,
            approving_dids=[qv.validator.validator_did for qv in approving],
            rejections=rejections,
            session_voucher=aggregate_voucher,
        )

    def _build_aggregate_voucher(
        self,
        approving: List[QuorumValidator],
        req: HeartbeatRequest,
    ) -> Dict[str, Any]:
        initial_trusts = [qv.validator.initial_trust for qv in approving]
        decay_lambdas = [qv.validator.decay_lambda for qv in approving]
        max_ttls = [qv.validator.max_ttl_seconds for qv in approving]
        validity_windows = [qv.validator.voucher_valid_seconds for qv in approving]
        scopes = [set(qv.validator.scope) for qv in approving]

        aggregated_scope = scopes[0]
        for s in scopes[1:]:
            aggregated_scope = aggregated_scope.intersection(s)

        return build_session_voucher(
            subject_did=req.subject_did,
            validator_dids=[qv.validator.validator_did for qv in approving],
            decay_lambda=float(self.policy.decay_lambda_aggregator(decay_lambdas)),
            initial_trust=float(self.policy.initial_trust_aggregator(initial_trusts)),
            max_ttl_seconds=int(self.policy.max_ttl_aggregator(max_ttls)),
            scope=sorted(aggregated_scope),
            valid_seconds=int(self.policy.voucher_valid_seconds_aggregator(validity_windows)),
        )

    @property
    def total_weight(self) -> float:
        return sum(v.weight for v in self.validators)

    @property
    def validator_count(self) -> int:
        return len(self.validators)


__all__ = [
    "ROLE_GENERAL",
    "ROLE_POLICY",
    "ROLE_BEHAVIORAL",
    "ROLE_BUDGET",
    "QuorumError",
    "QuorumPolicy",
    "QuorumResult",
    "QuorumValidator",
    "HeartbeatQuorum",
]
