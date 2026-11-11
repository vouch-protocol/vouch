"""
Proof of Restraint: census-complete compute ceiling attestation (PAD-125).

An operator that has committed to a compute ceiling can produce an artifact
demonstrating it held to one. Every enrolled device emits a signed work record
per period carrying an additively homomorphic commitment to its magnitude. The
records accumulate into a period tree, and the operator publishes an attestation
of two predicates: that no single workload exceeded a declared ceiling, and that
the period total stayed within a declared quota.

What makes the attestation mean anything is completeness. Every device in the
census must contribute exactly one record, or be covered by a signed
decommission record for that period, so omitting work requires omitting a device
and omitting a device is itself a dated, attributable event.

Three disclosure modes are supported, and all three verify through the same
entry point:

``MODE_AGGREGATE_TOTAL``
    The operator opens the aggregate of every commitment. The verifier learns
    the period total and the per-workload aggregates, and learns nothing about
    the distribution within a workload.

``MODE_SAMPLED``
    The verifier's sample is derived deterministically from a published log
    root, so the operator cannot choose which workloads are opened. The verifier
    learns only the sampled aggregates.

``MODE_EXTERNAL_PROOF``
    A registered range-proof backend supplies and checks a proof over the
    committed values, so the verifier learns the truth of the predicates and
    nothing else. The registry is the extension point for a proving system.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import _pedersen as pedersen
from ._common import (
    PacingError,
    base_credential,
    digest_bytes,
    mb64,
    merkle_root,
    subject_of,
    verify_credential,
)
from .census import Census, DECOMMISSION_TYPE

WORK_RECORD_TYPE = "VouchWorkUnitRecord"
RESTRAINT_TYPE = "VouchRestraintAttestation"

MODE_AGGREGATE_TOTAL = "aggregate-total"
MODE_SAMPLED = "sampled-opening"
MODE_EXTERNAL_PROOF = "external-proof"

KNOWN_MODES = frozenset({MODE_AGGREGATE_TOTAL, MODE_SAMPLED, MODE_EXTERNAL_PROOF})

REASON_INVALID_PROOF = "invalid_proof"
REASON_NOT_IN_CENSUS = "device_not_in_census"
REASON_WRONG_CENSUS = "wrong_census_commitment"
REASON_WRONG_PERIOD = "wrong_period"
REASON_DUPLICATE_RECORD = "duplicate_device_record"
REASON_INCOMPLETE_CENSUS = "incomplete_census"
REASON_UNEXPLAINED_ABSENCE = "unexplained_device_absence"
REASON_PERIOD_ROOT_MISMATCH = "period_root_mismatch"
REASON_CEILING_EXCEEDED = "ceiling_exceeded"
REASON_QUOTA_EXCEEDED = "quota_exceeded"
REASON_BAD_OPENING = "bad_commitment_opening"
REASON_SAMPLE_MISMATCH = "sample_mismatch"
REASON_UNKNOWN_MODE = "unknown_disclosure_mode"
REASON_CHAIN_BROKEN = "device_continuity_chain_broken"
REASON_NO_PROOF_BACKEND = "no_proof_backend_registered"
REASON_PROOF_REJECTED = "predicate_proof_rejected"


# ---------------------------------------------------------------------------
# Work records
# ---------------------------------------------------------------------------


def workload_commitment(workload_id: str, salt: bytes) -> str:
    """
    A blinded, stable handle for a workload.

    Records belonging to the same workload carry the same handle so their
    magnitudes aggregate, while the workload identifier itself is not disclosed
    by the record.
    """
    if not workload_id or not isinstance(workload_id, str):
        raise PacingError("workload_id is required")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise PacingError("workload salt must be at least 16 bytes")
    payload = b"vouch-pacing-workload\x00" + bytes(salt) + b"\x00" + workload_id.encode("utf-8")
    return mb64(hashlib.sha256(payload).digest())


def work_record(
    device_signer: Any,
    *,
    census_commitment: str,
    period: str,
    workload: str,
    magnitude: int,
    blinding: Optional[int] = None,
    chain_commitment: Optional[str] = None,
    chain_reveal: Optional[str] = None,
) -> Tuple[Dict[str, Any], int]:
    """
    Emit one device's signed work record for a period.

    The magnitude is carried only as a homomorphic commitment. Returns the
    credential and the blinding scalar, which the operator retains in order to
    open aggregates later.

    Args:
        device_signer: The device's own ``Signer``, keyed from its hardware root.
        census_commitment: The census commitment digest this record is bound to.
        period: The period identifier.
        workload: The blinded workload handle from :func:`workload_commitment`.
        magnitude: The work units to commit to, a non-negative integer.
        blinding: An optional blinding scalar; a fresh one is drawn if omitted.
        chain_commitment: Commitment to this device's next continuity secret.
        chain_reveal: The previous period's continuity secret, revealed now.
    """
    if not census_commitment or not isinstance(census_commitment, str):
        raise PacingError("census_commitment is required")
    if not period or not isinstance(period, str):
        raise PacingError("period is required")
    if not workload or not isinstance(workload, str):
        raise PacingError("workload handle is required")
    scalar = pedersen.random_blinding() if blinding is None else int(blinding)
    commitment = pedersen.commit(int(magnitude), scalar)
    subject: Dict[str, Any] = {
        "id": device_signer.get_did(),
        "censusCommitment": census_commitment,
        "period": period,
        "workload": workload,
        "magnitudeCommitment": pedersen.encode(commitment),
    }
    if chain_commitment:
        subject["chainCommitment"] = chain_commitment
    if chain_reveal:
        subject["chainReveal"] = chain_reveal
    credential = base_credential(device_signer, WORK_RECORD_TYPE, subject)
    return credential, scalar


# ---------------------------------------------------------------------------
# Period accounting
# ---------------------------------------------------------------------------


@dataclass
class PeriodAccounting:
    """
    The verified set of records and absences for one operator period.

    Both the operator and any verifier build one of these from the same
    published records, so the attestation is checked against an independently
    constructed view rather than against the operator's own summary.
    """

    census: Census
    period: str
    records: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    absences: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def add_record(self, record: Dict[str, Any], device_public_key: Any) -> bool:
        """Verify and admit one device work record. Returns True when admitted."""
        if not verify_credential(record, device_public_key, WORK_RECORD_TYPE):
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        subject = subject_of(record)
        device_did = subject.get("id")
        if not isinstance(device_did, str) or not self.census.contains(device_did):
            self.reasons.append(REASON_NOT_IN_CENSUS)
            return False
        if record.get("issuer") != device_did:
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        if subject.get("censusCommitment") != self.census.commitment_digest:
            self.reasons.append(REASON_WRONG_CENSUS)
            return False
        if subject.get("period") != self.period:
            self.reasons.append(REASON_WRONG_PERIOD)
            return False
        if device_did in self.records:
            self.reasons.append(REASON_DUPLICATE_RECORD)
            return False
        self.records[device_did] = record
        return True

    def add_absence(self, decommission: Dict[str, Any], operator_public_key: Any) -> bool:
        """Verify and admit a decommission or maintenance record for the period."""
        if not verify_credential(decommission, operator_public_key, DECOMMISSION_TYPE):
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        subject = subject_of(decommission)
        device_did = subject.get("id")
        if not isinstance(device_did, str) or not self.census.contains(device_did):
            self.reasons.append(REASON_NOT_IN_CENSUS)
            return False
        if subject.get("period") != self.period:
            self.reasons.append(REASON_WRONG_PERIOD)
            return False
        self.absences[device_did] = decommission
        return True

    def check_continuity(self, prior_commitments: Dict[str, str]) -> List[str]:
        """
        Check each device's continuity chain against the prior period.

        A device whose record reveals a secret that does not hash to the
        commitment it made last period is discontinuous, which is what a device
        parked outside the census and later returned looks like.
        """
        from ..canary import verify_reveal

        broken: List[str] = []
        for device_did, prior in prior_commitments.items():
            record = self.records.get(device_did)
            if record is None:
                continue
            revealed = subject_of(record).get("chainReveal")
            if not isinstance(revealed, str) or not verify_reveal(revealed, prior):
                broken.append(device_did)
        return broken

    def completeness_reasons(self) -> List[str]:
        """
        Reasons why the period is not complete over its census.

        Empty means every enrolled device either contributed a record or is
        covered by a signed absence, and no device did both.
        """
        found: List[str] = []
        for device_did in self.census.device_dids:
            has_record = device_did in self.records
            has_absence = device_did in self.absences
            if has_record and has_absence:
                found.append(REASON_DUPLICATE_RECORD)
            elif not has_record and not has_absence:
                found.append(REASON_UNEXPLAINED_ABSENCE)
        covered = len(self.records) + len(self.absences)
        if covered != self.census.cardinality:
            found.append(REASON_INCOMPLETE_CENSUS)
        return found

    def leaves(self) -> List[bytes]:
        """Period tree leaves: every record and every absence, in device order."""
        ordered: List[bytes] = []
        for device_did in self.census.device_dids:
            entry = self.records.get(device_did) or self.absences.get(device_did)
            if entry is not None:
                ordered.append(digest_bytes(entry))
        return ordered

    def period_root(self) -> str:
        """The period accumulation root over records and absences."""
        return mb64(merkle_root(self.leaves()))

    def workload_aggregates(self) -> Dict[str, int]:
        """Per-workload aggregate commitments, keyed by blinded workload handle."""
        buckets: Dict[str, List[int]] = {}
        for record in self.records.values():
            subject = subject_of(record)
            handle = subject.get("workload")
            encoded = subject.get("magnitudeCommitment")
            if not isinstance(handle, str) or not isinstance(encoded, str):
                continue
            buckets.setdefault(handle, []).append(pedersen.decode(encoded))
        return {handle: pedersen.aggregate(values) for handle, values in sorted(buckets.items())}

    def total_commitment(self) -> int:
        """The aggregate commitment over every record in the period."""
        return pedersen.aggregate(self.workload_aggregates().values())


# ---------------------------------------------------------------------------
# Deterministic sampling
# ---------------------------------------------------------------------------


def sample_workloads(seed_root: str, handles: Sequence[str], sample_size: int) -> List[str]:
    """
    Select which workloads must be opened, deterministically from a log root.

    The operator cannot influence the selection, because the seed is a published
    log root fixed before the sample is drawn and the ordering is over the
    handles the operator has already committed to.
    """
    if not isinstance(seed_root, str) or not seed_root:
        raise PacingError("seed_root is required")
    ordered = sorted(set(handles))
    if sample_size <= 0:
        return []
    if sample_size >= len(ordered):
        return ordered
    scored = []
    for handle in ordered:
        payload = b"vouch-pacing-sample\x00" + seed_root.encode() + b"\x00" + handle.encode()
        scored.append((hashlib.sha256(payload).digest(), handle))
    scored.sort()
    return sorted(handle for _, handle in scored[:sample_size])


# ---------------------------------------------------------------------------
# Predicate proof backends (extension point for a proving system)
# ---------------------------------------------------------------------------

ProofVerifier = Callable[[Dict[str, Any], Dict[str, Any]], bool]

_PROOF_BACKENDS: Dict[str, ProofVerifier] = {}


def register_proof_backend(name: str, verifier: ProofVerifier) -> None:
    """
    Register a range-proof backend for ``MODE_EXTERNAL_PROOF``.

    The verifier receives the proof object and the predicate parameters
    (commitments, ceiling, quota) and returns whether the predicates hold.
    """
    if not name or not callable(verifier):
        raise PacingError("a proof backend needs a name and a callable verifier")
    _PROOF_BACKENDS[name] = verifier


def clear_proof_backends() -> None:
    """Remove every registered backend. Used by tests and by re-configuration."""
    _PROOF_BACKENDS.clear()


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


def attest_restraint(
    operator_signer: Any,
    accounting: PeriodAccounting,
    *,
    ceiling: int,
    quota: int,
    mode: str = MODE_AGGREGATE_TOTAL,
    openings: Optional[Dict[str, Tuple[int, int]]] = None,
    seed_root: Optional[str] = None,
    sample_size: int = 0,
    external_proof: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Publish the period's ceiling and quota attestation.

    Args:
        operator_signer: The operator's ``Signer``.
        accounting: The operator's own view of the period.
        ceiling: Maximum permitted aggregate for any single workload.
        quota: Maximum permitted period total.
        mode: One of the module's disclosure modes.
        openings: For the opening modes, ``{workload_handle: (magnitude, blinding)}``
            giving the aggregate opening of each workload that must be disclosed.
        seed_root: The published log root that seeds sampling.
        sample_size: How many workloads the sample opens.
        external_proof: The proof object for ``MODE_EXTERNAL_PROOF``.
    """
    if mode not in KNOWN_MODES:
        raise PacingError(f"unknown disclosure mode: {mode!r}")
    if ceiling < 0 or quota < 0:
        raise PacingError("ceiling and quota must be non-negative")

    subject: Dict[str, Any] = {
        "id": operator_signer.get_did(),
        "period": accounting.period,
        "censusCommitment": accounting.census.commitment_digest,
        "censusCardinality": accounting.census.cardinality,
        "periodRoot": accounting.period_root(),
        "recordCount": len(accounting.records),
        "absenceCount": len(accounting.absences),
        "ceiling": int(ceiling),
        "quota": int(quota),
        "disclosureMode": mode,
    }

    if mode == MODE_AGGREGATE_TOTAL:
        if not openings:
            raise PacingError("aggregate-total mode requires openings for every workload")
        subject["openings"] = _encode_openings(openings)
    elif mode == MODE_SAMPLED:
        if not seed_root:
            raise PacingError("sampled mode requires a seed_root")
        selected = sample_workloads(
            seed_root, list(accounting.workload_aggregates().keys()), sample_size
        )
        missing = [handle for handle in selected if handle not in (openings or {})]
        if missing:
            raise PacingError(f"sampled mode is missing openings for {missing}")
        subject["seedRoot"] = seed_root
        subject["sampleSize"] = int(sample_size)
        subject["openings"] = _encode_openings(
            {handle: (openings or {})[handle] for handle in selected}
        )
    else:
        if not isinstance(external_proof, dict) or not external_proof.get("backend"):
            raise PacingError("external-proof mode requires a proof object naming a backend")
        subject["predicateProof"] = dict(external_proof)

    return base_credential(operator_signer, RESTRAINT_TYPE, subject)


def build_openings(
    accounting: PeriodAccounting, per_record: Dict[str, Tuple[int, int]]
) -> Dict[str, Tuple[int, int]]:
    """
    Aggregate per-record magnitudes and blindings into per-workload openings.

    The operator holds each device record's magnitude and blinding scalar. This
    sums them per workload so a single opening covers every record in that
    workload, which is what the ceiling predicate is evaluated over.

    Args:
        accounting: The operator's period view.
        per_record: ``{device_did: (magnitude, blinding)}`` for every record.
    """
    magnitudes: Dict[str, int] = {}
    blindings: Dict[str, List[int]] = {}
    for device_did, record in accounting.records.items():
        if device_did not in per_record:
            raise PacingError(f"missing magnitude and blinding for {device_did}")
        handle = subject_of(record).get("workload")
        if not isinstance(handle, str):
            raise PacingError("record has no workload handle")
        magnitude, blinding = per_record[device_did]
        magnitudes[handle] = magnitudes.get(handle, 0) + int(magnitude)
        blindings.setdefault(handle, []).append(int(blinding))
    return {
        handle: (magnitudes[handle], pedersen.aggregate_blindings(blindings[handle]))
        for handle in magnitudes
    }


def _encode_openings(openings: Dict[str, Tuple[int, int]]) -> List[Dict[str, Any]]:
    """Encode workload aggregate openings for the wire, in stable handle order."""
    encoded: List[Dict[str, Any]] = []
    for handle in sorted(openings):
        magnitude, blinding = openings[handle]
        encoded.append(
            {
                "workload": handle,
                "magnitude": int(magnitude),
                "blinding": pedersen.encode(int(blinding)),
            }
        )
    return encoded


def verify_restraint(
    attestation: Dict[str, Any],
    operator_public_key: Any,
    accounting: PeriodAccounting,
) -> List[str]:
    """
    Check a restraint attestation against an independently built period view.

    Returns the list of reasons the attestation fails. An empty list means the
    census was complete for the period, the period root matches, and the ceiling
    and quota predicates hold under the attestation's disclosure mode.
    """
    reasons: List[str] = []
    if not verify_credential(attestation, operator_public_key, RESTRAINT_TYPE):
        return [REASON_INVALID_PROOF]
    subject = subject_of(attestation)

    if subject.get("censusCommitment") != accounting.census.commitment_digest:
        reasons.append(REASON_WRONG_CENSUS)
    if subject.get("period") != accounting.period:
        reasons.append(REASON_WRONG_PERIOD)
    if subject.get("periodRoot") != accounting.period_root():
        reasons.append(REASON_PERIOD_ROOT_MISMATCH)

    reasons.extend(accounting.completeness_reasons())
    reasons.extend(accounting.reasons)

    ceiling = subject.get("ceiling")
    quota = subject.get("quota")
    if not isinstance(ceiling, int) or not isinstance(quota, int):
        return reasons + [REASON_UNKNOWN_MODE]

    mode = subject.get("disclosureMode")
    aggregates = accounting.workload_aggregates()

    if mode == MODE_AGGREGATE_TOTAL:
        reasons.extend(_verify_openings(subject, aggregates, ceiling, require_all=True))
        reasons.extend(_verify_quota(subject, aggregates, quota))
    elif mode == MODE_SAMPLED:
        seed_root = subject.get("seedRoot")
        sample_size = subject.get("sampleSize")
        if not isinstance(seed_root, str) or not isinstance(sample_size, int):
            reasons.append(REASON_SAMPLE_MISMATCH)
        else:
            expected = sample_workloads(seed_root, list(aggregates.keys()), sample_size)
            opened = sorted(entry.get("workload") for entry in subject.get("openings") or [])
            if opened != expected:
                reasons.append(REASON_SAMPLE_MISMATCH)
            reasons.extend(_verify_openings(subject, aggregates, ceiling, require_all=False))
    elif mode == MODE_EXTERNAL_PROOF:
        proof = subject.get("predicateProof")
        backend = _PROOF_BACKENDS.get((proof or {}).get("backend", ""))
        if backend is None:
            reasons.append(REASON_NO_PROOF_BACKEND)
        else:
            params = {
                "aggregates": {k: pedersen.encode(v) for k, v in aggregates.items()},
                "ceiling": ceiling,
                "quota": quota,
            }
            try:
                accepted = bool(backend(dict(proof or {}), params))
            except Exception:
                accepted = False
            if not accepted:
                reasons.append(REASON_PROOF_REJECTED)
    else:
        reasons.append(REASON_UNKNOWN_MODE)

    return reasons


def _verify_openings(
    subject: Dict[str, Any],
    aggregates: Dict[str, int],
    ceiling: int,
    *,
    require_all: bool,
) -> List[str]:
    """Check each disclosed workload aggregate opening against the ceiling."""
    reasons: List[str] = []
    entries = subject.get("openings")
    if not isinstance(entries, list):
        return [REASON_BAD_OPENING]
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            reasons.append(REASON_BAD_OPENING)
            continue
        handle = entry.get("workload")
        magnitude = entry.get("magnitude")
        blinding = entry.get("blinding")
        if handle not in aggregates or not isinstance(magnitude, int) or magnitude < 0:
            reasons.append(REASON_BAD_OPENING)
            continue
        try:
            scalar = pedersen.decode(str(blinding))
        except PacingError:
            reasons.append(REASON_BAD_OPENING)
            continue
        if not pedersen.verify_opening(aggregates[handle], magnitude, scalar):
            reasons.append(REASON_BAD_OPENING)
            continue
        if magnitude > ceiling:
            reasons.append(REASON_CEILING_EXCEEDED)
        seen.add(handle)
    if require_all and seen != set(aggregates):
        reasons.append(REASON_BAD_OPENING)
    return reasons


def _verify_quota(subject: Dict[str, Any], aggregates: Dict[str, int], quota: int) -> List[str]:
    """Check the period total against the quota, using the disclosed openings."""
    entries = subject.get("openings")
    if not isinstance(entries, list):
        return [REASON_BAD_OPENING]
    total = 0
    for entry in entries:
        magnitude = (entry or {}).get("magnitude")
        if not isinstance(magnitude, int) or magnitude < 0:
            return [REASON_BAD_OPENING]
        total += magnitude
    return [REASON_QUOTA_EXCEEDED] if total > quota else []
