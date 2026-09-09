"""
Immutable Red Line Commitment (PAD-131).

An operator's published safety thresholds are a document, and a document can be
edited. This module makes them an object whose history cannot be rewritten. Each
threshold is committed individually under its own blinding value, the
commitments accumulate into a counted tree, and the tree root is appended to an
append-only log before any measurement against it occurs.

Priority in time then rests on the log index rather than on the operator's clock
or its word. Amendment stays possible, because a superseding commitment names
the prior one, and the log's consistency proofs show the version chain is
complete. What is foreclosed is silent amendment: a threshold relaxed after a
result is visible as a dated amendment ordered after that result.

Selective reveal keeps the mechanism usable when the thresholds are themselves
sensitive. One threshold can be opened while the rest stay closed, and the
published count establishes how many exist.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..transparency import inclusion_proof, verify_inclusion
from ._common import (
    PacingError,
    base_credential,
    blinded_commitment,
    constant_time_eq,
    mb64,
    merkle_root,
    subject_of,
    unmb64,
    verify_credential,
)

POLICY_TYPE = "VouchThresholdPolicyCommitment"
MEASUREMENT_TYPE = "VouchMeasurementRecord"

OP_AT_LEAST = ">="
OP_AT_MOST = "<="
OP_ABOVE = ">"
OP_BELOW = "<"
KNOWN_OPERATORS = frozenset({OP_AT_LEAST, OP_AT_MOST, OP_ABOVE, OP_BELOW})

CONSEQUENCE_HALT = "halt"
CONSEQUENCE_NARROW = "narrow-deployment"
CONSEQUENCE_ESCALATE = "escalate"

REASON_INVALID_PROOF = "invalid_proof"
REASON_UNKNOWN_THRESHOLD = "unknown_threshold"
REASON_BAD_OPENING = "bad_threshold_opening"
REASON_INCLUSION_FAILED = "inclusion_proof_failed"
REASON_ORDER_VIOLATION = "policy_not_committed_before_measurement"
REASON_COUNT_MISMATCH = "threshold_count_mismatch"
REASON_CHAIN_BROKEN = "amendment_chain_broken"


@dataclass(frozen=True)
class Threshold:
    """One named red line: what is measured, the comparison, and what follows."""

    name: str
    measurement: str
    comparison: str
    value: float
    consequence: str

    def __post_init__(self) -> None:
        if not self.name or not self.measurement:
            raise PacingError("a threshold needs a name and a measurement reference")
        if self.comparison not in KNOWN_OPERATORS:
            raise PacingError(f"unknown comparison operator: {self.comparison!r}")

    def to_dict(self) -> Dict[str, Any]:
        """The threshold's canonical form, which is what gets committed."""
        return {
            "name": self.name,
            "measurement": self.measurement,
            "comparison": self.comparison,
            "value": float(self.value),
            "consequence": self.consequence,
        }

    def crossed(self, measured: float) -> bool:
        """True if a measurement crosses this red line."""
        value = float(self.value)
        if self.comparison == OP_AT_LEAST:
            return float(measured) >= value
        if self.comparison == OP_AT_MOST:
            return float(measured) <= value
        if self.comparison == OP_ABOVE:
            return float(measured) > value
        return float(measured) < value


@dataclass
class PolicyCommitment:
    """
    A committed threshold set, held by the operator.

    The leaves are ordered by threshold name so the root is reproducible, and the
    blinding values stay with the operator until a threshold is opened.
    """

    thresholds: Tuple[Threshold, ...]
    blindings: Dict[str, bytes] = field(default_factory=dict)

    @property
    def names(self) -> List[str]:
        """Threshold names in committed order."""
        return sorted(threshold.name for threshold in self.thresholds)

    def _ordered(self) -> List[Threshold]:
        return sorted(self.thresholds, key=lambda threshold: threshold.name)

    def leaf(self, name: str) -> bytes:
        """The committed leaf value for one threshold."""
        for threshold in self._ordered():
            if threshold.name == name:
                return unmb64(blinded_commitment(threshold.to_dict(), self.blindings[name]))
        raise PacingError(f"unknown threshold: {name!r}")

    def leaves(self) -> List[bytes]:
        """Every committed leaf, in committed order."""
        return [self.leaf(threshold.name) for threshold in self._ordered()]

    @property
    def root(self) -> str:
        """The policy commitment root."""
        return mb64(merkle_root(self.leaves()))

    @property
    def cardinality(self) -> int:
        """How many thresholds the committed set contains."""
        return len(self.thresholds)

    def index_of(self, name: str) -> int:
        """The committed position of a named threshold."""
        for position, threshold in enumerate(self._ordered()):
            if threshold.name == name:
                return position
        raise PacingError(f"unknown threshold: {name!r}")


def commit_policy(
    thresholds: Sequence[Threshold], blindings: Optional[Dict[str, bytes]] = None
) -> PolicyCommitment:
    """Commit a threshold set, drawing a fresh blinding value for each threshold."""
    if not thresholds:
        raise PacingError("a policy must contain at least one threshold")
    names = [threshold.name for threshold in thresholds]
    if len(set(names)) != len(names):
        raise PacingError("threshold names must be distinct")
    chosen = dict(blindings or {})
    for name in names:
        chosen.setdefault(name, secrets.token_bytes(32))
    return PolicyCommitment(thresholds=tuple(thresholds), blindings=chosen)


def publish_policy(
    signer: Any,
    commitment: PolicyCommitment,
    *,
    log_index: Optional[int] = None,
    supersedes: Optional[str] = None,
    supersedes_index: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Publish the policy commitment, without disclosing any threshold.

    Args:
        signer: The operator's ``Signer``.
        commitment: The committed threshold set.
        log_index: The append-only log index this commitment occupies.
        supersedes: The root of the commitment this one replaces.
        supersedes_index: That commitment's log index.
    """
    subject: Dict[str, Any] = {
        "id": commitment.root,
        "operator": signer.get_did(),
        "root": commitment.root,
        "cardinality": commitment.cardinality,
    }
    if log_index is not None:
        subject["logIndex"] = int(log_index)
    if supersedes:
        subject["supersedes"] = supersedes
        if supersedes_index is not None:
            subject["supersedesLogIndex"] = int(supersedes_index)
    return base_credential(signer, POLICY_TYPE, subject)


def measurement_record(
    signer: Any,
    *,
    measurement: str,
    value: float,
    subject_of_measurement: str,
    log_index: Optional[int] = None,
) -> Dict[str, Any]:
    """An independently signed evaluation result, appended to the same log."""
    subject: Dict[str, Any] = {
        "id": subject_of_measurement,
        "evaluator": signer.get_did(),
        "measurement": measurement,
        "value": float(value),
    }
    if log_index is not None:
        subject["logIndex"] = int(log_index)
    return base_credential(signer, MEASUREMENT_TYPE, subject)


def open_threshold(commitment: PolicyCommitment, name: str) -> Dict[str, Any]:
    """
    Selectively open one threshold, leaving the rest closed.

    The reveal carries the threshold's canonical form, its blinding value, its
    committed position, and an inclusion proof against the published root.
    """
    threshold = next((t for t in commitment.thresholds if t.name == name), None)
    if threshold is None:
        raise PacingError(f"unknown threshold: {name!r}")
    index = commitment.index_of(name)
    path = inclusion_proof(index, commitment.leaves())
    return {
        "threshold": threshold.to_dict(),
        "blinding": mb64(commitment.blindings[name]),
        "index": index,
        "treeSize": commitment.cardinality,
        "inclusionProof": [mb64(step) for step in path],
        "root": commitment.root,
    }


def verify_open(
    reveal: Dict[str, Any],
    policy_credential: Dict[str, Any],
    operator_public_key: Any,
) -> List[str]:
    """
    Check a selectively opened threshold against the published commitment.

    Returns the reasons the reveal fails. An empty list means the opened
    threshold really is one of the committed set, at the position claimed, under
    the published root.
    """
    if not verify_credential(policy_credential, operator_public_key, POLICY_TYPE):
        return [REASON_INVALID_PROOF]
    subject = subject_of(policy_credential)
    root = subject.get("root")
    cardinality = subject.get("cardinality")

    threshold = reveal.get("threshold")
    blinding = reveal.get("blinding")
    index = reveal.get("index")
    tree_size = reveal.get("treeSize")
    path = reveal.get("inclusionProof")
    if not isinstance(threshold, dict) or not isinstance(path, list):
        return [REASON_BAD_OPENING]
    if not isinstance(index, int) or not isinstance(tree_size, int):
        return [REASON_BAD_OPENING]
    if tree_size != cardinality:
        return [REASON_COUNT_MISMATCH]

    try:
        leaf = unmb64(blinded_commitment(threshold, unmb64(str(blinding))))
        steps = [unmb64(str(step)) for step in path]
        expected_root = unmb64(str(root))
    except PacingError:
        return [REASON_BAD_OPENING]

    if not verify_inclusion(leaf, index, tree_size, steps, expected_root):
        return [REASON_INCLUSION_FAILED]
    if not constant_time_eq(str(reveal.get("root")), str(root)):
        return [REASON_BAD_OPENING]
    return []


def check_ordering(
    policy_credential: Dict[str, Any],
    measurement: Dict[str, Any],
    operator_public_key: Any,
    evaluator_public_key: Any,
) -> List[str]:
    """
    Confirm the policy was committed before the measurement was recorded.

    Ordering comes from the log indices carried by both records, so neither
    party's clock is part of the trust base.
    """
    if not verify_credential(policy_credential, operator_public_key, POLICY_TYPE):
        return [REASON_INVALID_PROOF]
    if not verify_credential(measurement, evaluator_public_key, MEASUREMENT_TYPE):
        return [REASON_INVALID_PROOF]
    policy_index = subject_of(policy_credential).get("logIndex")
    measurement_index = subject_of(measurement).get("logIndex")
    if not isinstance(policy_index, int) or not isinstance(measurement_index, int):
        return [REASON_ORDER_VIOLATION]
    return [] if policy_index < measurement_index else [REASON_ORDER_VIOLATION]


def verify_amendment_chain(
    credentials: Sequence[Dict[str, Any]], operator_public_key: Any
) -> List[str]:
    """
    Walk a policy's version chain from oldest to newest.

    Each superseding commitment must name the prior one's root and sit at a
    strictly higher log index, so a version cannot be inserted, removed, or
    reordered without breaking the chain.
    """
    reasons: List[str] = []
    previous: Optional[Dict[str, Any]] = None
    for credential in credentials:
        if not verify_credential(credential, operator_public_key, POLICY_TYPE):
            reasons.append(REASON_INVALID_PROOF)
            continue
        subject = subject_of(credential)
        if previous is not None:
            previous_subject = subject_of(previous)
            if subject.get("supersedes") != previous_subject.get("root"):
                reasons.append(REASON_CHAIN_BROKEN)
            current_index = subject.get("logIndex")
            prior_index = previous_subject.get("logIndex")
            if isinstance(current_index, int) and isinstance(prior_index, int):
                if current_index <= prior_index:
                    reasons.append(REASON_CHAIN_BROKEN)
        previous = credential
    return reasons


def threshold_from_dict(value: Dict[str, Any]) -> Threshold:
    """Rebuild a Threshold from its canonical form."""
    try:
        return Threshold(
            name=str(value["name"]),
            measurement=str(value["measurement"]),
            comparison=str(value["comparison"]),
            value=float(value["value"]),
            consequence=str(value["consequence"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PacingError("malformed threshold object") from exc
