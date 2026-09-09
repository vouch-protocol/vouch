"""
Oversight Ratio Bound (PAD-132).

The worry most often stated about the pace of autonomous system development is
that oversight does not grow with capability. This module gives that worry an
enforceable form: a step is authorized only when the accumulated oversight
measure bound to that step's own artifacts stands in at least a committed ratio
to the step's compute measure.

Two rules give the predicate force. A receipt names the digests of the artifacts
the work examined and is consumed by nonce, so oversight applied to one artifact
set cannot be re-spent against another. And the ratio is committed in advance in
a tamper-evident record, so it cannot be lowered once a step fails the check.

The rule states in one line and verifies mechanically: capability may not scale
faster than the verified oversight bound to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from ._common import PacingError, base_credential, subject_of, verify_credential

RECEIPT_TYPE = "VouchOversightReceipt"
AUTHORIZATION_TYPE = "VouchOversightAuthorization"

WORK_INTERPRETABILITY = "interpretability"
WORK_ADVERSARIAL = "adversarial-evaluation"
WORK_COVERAGE = "coverage-evaluation"
WORK_HUMAN_REVIEW = "human-review"

INDEPENDENCE_INTERNAL = "internal"
INDEPENDENCE_EXTERNAL = "external"

DEFAULT_CLASS_WEIGHTS: Dict[str, float] = {
    WORK_INTERPRETABILITY: 1.0,
    WORK_ADVERSARIAL: 1.0,
    WORK_COVERAGE: 0.75,
    WORK_HUMAN_REVIEW: 1.0,
}

DEFAULT_INDEPENDENCE_WEIGHTS: Dict[str, float] = {
    INDEPENDENCE_INTERNAL: 1.0,
    INDEPENDENCE_EXTERNAL: 1.5,
}

REASON_INVALID_PROOF = "invalid_proof"
REASON_NO_ARTIFACT_OVERLAP = "no_artifact_overlap"
REASON_RECEIPT_CONSUMED = "receipt_already_consumed"
REASON_RATIO_NOT_MET = "oversight_ratio_not_met"
REASON_FLOOR_NOT_MET = "class_floor_not_met"
REASON_WRONG_PERIOD = "wrong_period"
REASON_UNKNOWN_CLASS = "unknown_work_class"


def oversight_receipt(
    signer: Any,
    *,
    work_class: str,
    measure: float,
    period: str,
    artifact_digests: Sequence[str],
    nonce: str,
    independence: str = INDEPENDENCE_INTERNAL,
    unit: str = "reviewer-hours",
) -> Dict[str, Any]:
    """
    Record oversight work as a signed, artifact-bound, non-reusable receipt.

    Args:
        signer: The party that performed the work.
        work_class: One of the module's work classes.
        measure: The measure in the unit declared for the class.
        period: The period the work belongs to.
        artifact_digests: The exact artifacts this work examined.
        nonce: A unique receipt identifier, consumed when relied upon.
        independence: The performing party's independence relative to the operator.
        unit: The unit the measure is expressed in.
    """
    if measure < 0:
        raise PacingError("measure must be non-negative")
    if not artifact_digests:
        raise PacingError("a receipt must name the artifacts it examined")
    if not nonce or not isinstance(nonce, str):
        raise PacingError("nonce is required")
    return base_credential(
        signer,
        RECEIPT_TYPE,
        {
            "id": nonce,
            "performedBy": signer.get_did(),
            "workClass": work_class,
            "independence": independence,
            "measure": float(measure),
            "unit": unit,
            "period": period,
            "artifacts": sorted(str(digest) for digest in artifact_digests),
        },
    )


@dataclass
class NonceLedger:
    """
    Which receipts have been spent, and how much of each remains.

    Partial consumption lets a receipt whose measure exceeds one step's
    requirement carry its remainder to a later step, while preventing the same
    measure from being counted twice.
    """

    remaining: Dict[str, float] = field(default_factory=dict)
    consumed: Set[str] = field(default_factory=set)

    def register(self, nonce: str, measure: float) -> None:
        """Record a receipt's full measure as available."""
        self.remaining.setdefault(nonce, float(measure))

    def available(self, nonce: str, measure: float) -> float:
        """How much of this receipt's measure is still unspent."""
        if nonce in self.consumed:
            return 0.0
        return float(self.remaining.get(nonce, measure))

    def spend(self, nonce: str, amount: float) -> None:
        """Spend part or all of a receipt's measure."""
        left = self.remaining.get(nonce, 0.0) - float(amount)
        if left <= 1e-9:
            self.remaining[nonce] = 0.0
            self.consumed.add(nonce)
        else:
            self.remaining[nonce] = left


@dataclass(frozen=True)
class Accumulation:
    """
    The weighted oversight measure available to one step.

    ``reasons`` holds blocking findings, which today means a receipt whose proof
    does not verify, because presenting a forged receipt in support of a step is
    a finding in its own right. ``skipped`` holds receipts that simply do not
    apply to this step: a different period, no artifact overlap, an unknown work
    class, or a measure already spent elsewhere.
    """

    total: float
    by_class: Dict[str, float]
    receipts_used: List[str]
    reasons: List[str]
    skipped: List[str] = field(default_factory=list)


def accumulate(
    receipts: Sequence[Dict[str, Any]],
    *,
    step_artifacts: Sequence[str],
    period: str,
    public_keys: Dict[str, Any],
    ledger: Optional[NonceLedger] = None,
    class_weights: Optional[Dict[str, float]] = None,
    independence_weights: Optional[Dict[str, float]] = None,
) -> Accumulation:
    """
    Sum the weighted oversight measure bound to a step's own artifacts.

    A receipt counts only where its artifact set intersects the step's, so work
    performed on a different version of an artifact does not carry over.
    """
    class_table = dict(DEFAULT_CLASS_WEIGHTS)
    class_table.update(class_weights or {})
    independence_table = dict(DEFAULT_INDEPENDENCE_WEIGHTS)
    independence_table.update(independence_weights or {})
    book = ledger or NonceLedger()
    wanted = set(str(digest) for digest in step_artifacts)

    total = 0.0
    by_class: Dict[str, float] = {}
    used: List[str] = []
    reasons: List[str] = []
    skipped: List[str] = []

    for receipt in receipts:
        subject = receipt.get("credentialSubject") or {}
        performer = subject.get("performedBy")
        if not verify_credential(receipt, public_keys.get(performer), RECEIPT_TYPE):
            reasons.append(REASON_INVALID_PROOF)
            continue
        if receipt.get("issuer") != performer:
            reasons.append(REASON_INVALID_PROOF)
            continue
        if subject.get("period") != period:
            skipped.append(REASON_WRONG_PERIOD)
            continue
        artifacts = set(str(item) for item in subject.get("artifacts") or [])
        if not artifacts & wanted:
            skipped.append(REASON_NO_ARTIFACT_OVERLAP)
            continue
        work_class = str(subject.get("workClass"))
        if work_class not in class_table:
            skipped.append(REASON_UNKNOWN_CLASS)
            continue
        nonce = str(subject.get("id"))
        raw = float(subject.get("measure", 0.0))
        book.register(nonce, raw)
        spendable = book.available(nonce, raw)
        if spendable <= 0:
            skipped.append(REASON_RECEIPT_CONSUMED)
            continue
        weight = class_table[work_class] * independence_table.get(
            str(subject.get("independence")), 1.0
        )
        contribution = spendable * weight
        total += contribution
        by_class[work_class] = by_class.get(work_class, 0.0) + contribution
        used.append(nonce)

    return Accumulation(
        total=total, by_class=by_class, receipts_used=used, reasons=reasons, skipped=skipped
    )


def check_ratio(
    *,
    compute_measure: float,
    accumulation: Accumulation,
    ratio: float,
    class_floors: Optional[Dict[str, float]] = None,
) -> List[str]:
    """
    Evaluate the authorization predicate.

    Returns the reasons the step is refused. An empty list means the accumulated
    oversight stands in at least the committed ratio to the compute measure, and
    every declared per-class floor is met.
    """
    reasons: List[str] = list(accumulation.reasons)
    if compute_measure < 0 or ratio < 0:
        raise PacingError("compute_measure and ratio must be non-negative")
    required = float(ratio) * float(compute_measure)
    if accumulation.total + 1e-9 < required:
        reasons.append(REASON_RATIO_NOT_MET)
    for work_class, floor in (class_floors or {}).items():
        if accumulation.by_class.get(work_class, 0.0) + 1e-9 < float(floor):
            reasons.append(REASON_FLOOR_NOT_MET)
    return reasons


def authorize_step(
    signer: Any,
    *,
    step_id: str,
    compute_measure: float,
    accumulation: Accumulation,
    ratio: float,
    policy_reference: Optional[str] = None,
    class_floors: Optional[Dict[str, float]] = None,
    ledger: Optional[NonceLedger] = None,
) -> Dict[str, Any]:
    """
    Issue the step's oversight authorization and consume the receipts relied on.

    Consumption happens at issuance, so a subsequent step must be supported by
    oversight work that has not already been spent.
    """
    refusals = check_ratio(
        compute_measure=compute_measure,
        accumulation=accumulation,
        ratio=ratio,
        class_floors=class_floors,
    )
    if refusals:
        raise PacingError(f"oversight predicate not satisfied: {sorted(set(refusals))}")
    book = ledger or NonceLedger()
    required = float(ratio) * float(compute_measure)
    outstanding = required
    for nonce in accumulation.receipts_used:
        if outstanding <= 0:
            break
        available = book.remaining.get(nonce, 0.0)
        spend = min(available, outstanding)
        book.spend(nonce, spend)
        outstanding -= spend
    subject: Dict[str, Any] = {
        "id": step_id,
        "operator": signer.get_did(),
        "computeMeasure": float(compute_measure),
        "oversightMeasure": float(accumulation.total),
        "requiredRatio": float(ratio),
        "receipts": list(accumulation.receipts_used),
        "oversightByClass": dict(accumulation.by_class),
    }
    if policy_reference:
        subject["policyReference"] = policy_reference
    if class_floors:
        subject["classFloors"] = {str(k): float(v) for k, v in class_floors.items()}
    return base_credential(signer, AUTHORIZATION_TYPE, subject)


def verify_authorization(
    authorization: Dict[str, Any],
    operator_public_key: Any,
    *,
    expected_ratio: Optional[float] = None,
) -> List[str]:
    """Re-check a published authorization against the ratio in force."""
    if not verify_credential(authorization, operator_public_key, AUTHORIZATION_TYPE):
        return [REASON_INVALID_PROOF]
    subject = subject_of(authorization)
    ratio = float(subject.get("requiredRatio", 0.0))
    if expected_ratio is not None and abs(ratio - float(expected_ratio)) > 1e-9:
        return [REASON_RATIO_NOT_MET]
    compute_measure = float(subject.get("computeMeasure", 0.0))
    oversight = float(subject.get("oversightMeasure", 0.0))
    if oversight + 1e-9 < ratio * compute_measure:
        return [REASON_RATIO_NOT_MET]
    return []


def receipt_nonces(receipts: Iterable[Dict[str, Any]]) -> List[str]:
    """The nonces a set of receipts carries, in order."""
    return [str((r.get("credentialSubject") or {}).get("id")) for r in receipts]
