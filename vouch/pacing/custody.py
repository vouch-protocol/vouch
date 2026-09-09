"""
Double-Entry Compute Custody (PAD-128).

Every account of how much compute an operator used is written by the operator.
This module adds the second book. A workload is admitted only against a signed
compute mandate, and the provider that admits it countersigns an allocation
receipt binding the mandate, the workload, the period, and the magnitude. At
period close the operator publishes its declared ledger, the provider publishes
its allocation ledger, and reconciliation over the two produces typed,
attributable divergences.

Neither book is trusted. The check is that two books kept by parties with
different interests agree, which is the discipline that made large-scale
commerce auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._common import PacingError, base_credential, subject_of, verify_credential

MANDATE_TYPE = "VouchComputeMandateCredential"
RECEIPT_TYPE = "VouchAllocationReceiptCredential"
LEDGER_TYPE = "VouchDeclaredLedgerCredential"
AGGREGATE_TYPE = "VouchProviderAggregateAttestation"

DIVERGENCE_UNBACKED_DECLARATION = "unbacked_declaration"
DIVERGENCE_UNDECLARED_ALLOCATION = "undeclared_allocation"
DIVERGENCE_MAGNITUDE_MISMATCH = "magnitude_mismatch"
DIVERGENCE_ENVELOPE_BREACH = "envelope_breach"
DIVERGENCE_INVALID_ENTRY = "invalid_entry"

REASON_INVALID_PROOF = "invalid_proof"
REASON_ENVELOPE_EXCEEDED = "envelope_exceeded"
REASON_CEILING_EXCEEDED = "per_workload_ceiling_exceeded"
REASON_WRONG_PERIOD = "wrong_period"
REASON_WRONG_OPERATOR = "wrong_operator"
REASON_UNKNOWN_MANDATE = "unknown_mandate"


def compute_mandate(
    signer: Any,
    *,
    operator_did: str,
    period: str,
    envelope: int,
    per_workload_ceiling: Optional[int] = None,
    provider_envelopes: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """
    Issue the authority under which workloads may be admitted for a period.

    Args:
        signer: The principal issuing the mandate, often the operator itself.
        operator_did: The operator the mandate authorizes.
        period: The period identifier.
        envelope: The total magnitude the operator may consume in the period.
        per_workload_ceiling: Optional maximum for any single workload.
        provider_envelopes: Optional per-provider sub-envelopes.
    """
    if envelope < 0:
        raise PacingError("envelope must be non-negative")
    subject: Dict[str, Any] = {
        "id": operator_did,
        "period": period,
        "envelope": int(envelope),
        "issuedBy": signer.get_did(),
    }
    if per_workload_ceiling is not None:
        subject["perWorkloadCeiling"] = int(per_workload_ceiling)
    if provider_envelopes:
        subject["providerEnvelopes"] = {str(k): int(v) for k, v in provider_envelopes.items()}
    return base_credential(signer, MANDATE_TYPE, subject)


def mandate_id(mandate: Dict[str, Any]) -> str:
    """The mandate's credential identifier, used to bind receipts to it."""
    identifier = mandate.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise PacingError("mandate has no credential id")
    return identifier


def allocation_receipt(
    provider_signer: Any,
    *,
    mandate: Dict[str, Any],
    workload_id: str,
    period: str,
    magnitude: int,
    magnitude_commitment: Optional[str] = None,
) -> Dict[str, Any]:
    """Countersign an admitted workload, creating the second book's entry."""
    if not workload_id or not isinstance(workload_id, str):
        raise PacingError("workload_id is required")
    if magnitude < 0:
        raise PacingError("magnitude must be non-negative")
    subject: Dict[str, Any] = {
        "id": workload_id,
        "mandate": mandate_id(mandate),
        "operator": subject_of(mandate).get("id"),
        "provider": provider_signer.get_did(),
        "period": period,
        "magnitude": int(magnitude),
    }
    if magnitude_commitment:
        subject["magnitudeCommitment"] = magnitude_commitment
    return base_credential(provider_signer, RECEIPT_TYPE, subject)


@dataclass
class AdmissionController:
    """
    A provider's running tally against one mandate.

    The envelope is enforced at the point the resource is granted, so a breach
    is refused rather than reported later.
    """

    mandate: Dict[str, Any]
    mandate_public_key: Any
    provider_did: str
    tally: int = 0
    admitted: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not verify_credential(self.mandate, self.mandate_public_key, MANDATE_TYPE):
            raise PacingError("mandate does not verify")

    @property
    def envelope(self) -> int:
        """The mandate's total envelope for the period."""
        return int(subject_of(self.mandate).get("envelope", 0))

    @property
    def ceiling(self) -> Optional[int]:
        """The mandate's per-workload ceiling, if it declares one."""
        value = subject_of(self.mandate).get("perWorkloadCeiling")
        return int(value) if isinstance(value, int) else None

    def admit(
        self, provider_signer: Any, *, workload_id: str, period: str, magnitude: int
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Admit a workload and issue its receipt, or refuse with a reason.

        Returns ``(receipt, None)`` on admission and ``(None, reason)`` on refusal.
        """
        subject = subject_of(self.mandate)
        if subject.get("period") != period:
            return None, REASON_WRONG_PERIOD
        ceiling = self.ceiling
        if ceiling is not None and magnitude > ceiling:
            return None, REASON_CEILING_EXCEEDED
        if self.tally + magnitude > self.envelope:
            return None, REASON_ENVELOPE_EXCEEDED
        receipt = allocation_receipt(
            provider_signer,
            mandate=self.mandate,
            workload_id=workload_id,
            period=period,
            magnitude=magnitude,
        )
        self.tally += int(magnitude)
        self.admitted[workload_id] = int(magnitude)
        return receipt, None


def declared_ledger(
    operator_signer: Any,
    *,
    period: str,
    entries: Sequence[Dict[str, Any]],
    mandate: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Publish the operator's own account of the period.

    Each entry names a workload identifier and a magnitude, and optionally the
    provider it ran with.
    """
    normalized: List[Dict[str, Any]] = []
    for entry in entries:
        workload_id = entry.get("workload")
        magnitude = entry.get("magnitude")
        if not isinstance(workload_id, str) or not isinstance(magnitude, int):
            raise PacingError("each ledger entry needs a workload string and an int magnitude")
        item: Dict[str, Any] = {"workload": workload_id, "magnitude": int(magnitude)}
        if entry.get("provider"):
            item["provider"] = str(entry["provider"])
        normalized.append(item)
    subject: Dict[str, Any] = {
        "id": operator_signer.get_did(),
        "period": period,
        "entries": sorted(normalized, key=lambda item: item["workload"]),
    }
    if mandate is not None:
        subject["mandate"] = mandate_id(mandate)
    return base_credential(operator_signer, LEDGER_TYPE, subject)


@dataclass(frozen=True)
class Divergence:
    """One typed, attributable disagreement between the two books."""

    kind: str
    workload: Optional[str]
    declared_magnitude: Optional[int]
    allocated_magnitude: Optional[int]
    operator: Optional[str]
    provider: Optional[str]
    period: str

    def to_dict(self) -> Dict[str, Any]:
        """The divergence as a plain JSON object."""
        return {
            "kind": self.kind,
            "workload": self.workload,
            "declaredMagnitude": self.declared_magnitude,
            "allocatedMagnitude": self.allocated_magnitude,
            "operator": self.operator,
            "provider": self.provider,
            "period": self.period,
        }


def reconcile(
    *,
    ledger: Dict[str, Any],
    receipts: Sequence[Dict[str, Any]],
    operator_public_key: Any,
    provider_public_keys: Dict[str, Any],
    mandate: Optional[Dict[str, Any]] = None,
    tolerance: int = 0,
) -> List[Divergence]:
    """
    Reconcile the operator's declared ledger against the provider receipts.

    Returns the typed divergences. An empty list means the two books agree
    within tolerance and no envelope was breached.
    """
    if not verify_credential(ledger, operator_public_key, LEDGER_TYPE):
        return [
            Divergence(
                DIVERGENCE_INVALID_ENTRY, None, None, None, None, None, str(ledger.get("id"))
            )
        ]
    ledger_subject = subject_of(ledger)
    period = str(ledger_subject.get("period"))
    operator = str(ledger_subject.get("id"))

    declared: Dict[str, int] = {}
    for entry in ledger_subject.get("entries") or []:
        workload = entry.get("workload")
        magnitude = entry.get("magnitude")
        if isinstance(workload, str) and isinstance(magnitude, int):
            declared[workload] = declared.get(workload, 0) + magnitude

    allocated: Dict[str, int] = {}
    providers: Dict[str, str] = {}
    divergences: List[Divergence] = []

    for receipt in receipts:
        subject = receipt.get("credentialSubject") or {}
        provider = subject.get("provider")
        key = provider_public_keys.get(provider)
        if not verify_credential(receipt, key, RECEIPT_TYPE) or receipt.get("issuer") != provider:
            divergences.append(
                Divergence(
                    DIVERGENCE_INVALID_ENTRY,
                    subject.get("id"),
                    None,
                    None,
                    operator,
                    provider,
                    period,
                )
            )
            continue
        if subject.get("period") != period or subject.get("operator") != operator:
            divergences.append(
                Divergence(
                    DIVERGENCE_INVALID_ENTRY,
                    subject.get("id"),
                    None,
                    None,
                    operator,
                    provider,
                    period,
                )
            )
            continue
        workload = subject.get("id")
        magnitude = subject.get("magnitude")
        if not isinstance(workload, str) or not isinstance(magnitude, int):
            divergences.append(
                Divergence(DIVERGENCE_INVALID_ENTRY, None, None, None, operator, provider, period)
            )
            continue
        allocated[workload] = allocated.get(workload, 0) + magnitude
        providers[workload] = str(provider)

    for workload in sorted(set(declared) | set(allocated)):
        left = declared.get(workload)
        right = allocated.get(workload)
        provider = providers.get(workload)
        if right is None:
            divergences.append(
                Divergence(
                    DIVERGENCE_UNBACKED_DECLARATION, workload, left, None, operator, None, period
                )
            )
        elif left is None:
            divergences.append(
                Divergence(
                    DIVERGENCE_UNDECLARED_ALLOCATION,
                    workload,
                    None,
                    right,
                    operator,
                    provider,
                    period,
                )
            )
        elif abs(left - right) > tolerance:
            divergences.append(
                Divergence(
                    DIVERGENCE_MAGNITUDE_MISMATCH,
                    workload,
                    left,
                    right,
                    operator,
                    provider,
                    period,
                )
            )

    if mandate is not None:
        envelope = int(subject_of(mandate).get("envelope", 0))
        total = max(sum(declared.values()), sum(allocated.values()))
        if total > envelope:
            divergences.append(
                Divergence(
                    DIVERGENCE_ENVELOPE_BREACH,
                    None,
                    sum(declared.values()),
                    sum(allocated.values()),
                    operator,
                    None,
                    period,
                )
            )

    return divergences


def provider_aggregate(
    provider_signer: Any,
    *,
    counterparty_did: str,
    period: str,
    total_magnitude: int,
    workload_count: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Attest a period aggregate for a counterparty that has not enrolled.

    The arrangement therefore produces a signal proportional to the
    participation of the providers rather than of the counterparties, without
    disclosing any workload-level detail.
    """
    if total_magnitude < 0:
        raise PacingError("total_magnitude must be non-negative")
    subject: Dict[str, Any] = {
        "id": counterparty_did,
        "provider": provider_signer.get_did(),
        "period": period,
        "totalMagnitude": int(total_magnitude),
    }
    if workload_count is not None:
        subject["workloadCount"] = int(workload_count)
    return base_credential(provider_signer, AGGREGATE_TYPE, subject)
