"""
Recursion Ceiling: bounding autonomy depth by human distance (PAD-126).

Every artifact entering a development pipeline carries a signed authorship
credential. Human distance is the minimum number of authorization hops from an
artifact to a credential signed by a key of an attested human custody class. A
pipeline step is authorized only when the maximum human distance across its
inputs is at or below a declared bound.

Derivation is non-decreasing: an artifact derived from another inherits at least
its parent's distance plus one, unless it carries its own human review edge over
its own digest. Autonomy therefore accumulates through transformation and across
model generations instead of resetting when an artifact is repackaged.

The bound is the pacing control. Lowering it forces more human authorization
edges into the loop, and because each edge is a real signature by a key under
human custody over an exact digest, lowering it lengthens the loop by
construction.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ._common import PacingError, base_credential, subject_of, verify_credential

AUTHORSHIP_TYPE = "VouchAuthorshipCredential"
REVIEW_TYPE = "VouchHumanReviewCredential"
STEP_TYPE = "VouchPipelineStepCredential"

CLASS_HUMAN = "human"
CLASS_AUTONOMOUS = "autonomous"
KNOWN_AUTHOR_CLASSES = frozenset({CLASS_HUMAN, CLASS_AUTONOMOUS})

CUSTODY_HUMAN_PRESENCE = "human-presence-authenticator"
CUSTODY_SOFTWARE = "software-held"
CUSTODY_HARDWARE_SERVICE = "hardware-service"

HUMAN_CUSTODY_CLASSES = frozenset({CUSTODY_HUMAN_PRESENCE})

UNBOUNDED = float("inf")

REASON_INVALID_PROOF = "invalid_proof"
REASON_UNKNOWN_ARTIFACT = "unknown_artifact"
REASON_BOUND_EXCEEDED = "human_distance_bound_exceeded"
REASON_NO_HUMAN_PATH = "no_path_to_human_custody"
REASON_WITNESS_MISMATCH = "witness_mismatch"


def authorship_credential(
    signer: Any,
    *,
    artifact_digest: str,
    author_class: str,
    custody_class: str = CUSTODY_SOFTWARE,
    authorized_by: Optional[str] = None,
    derived_from: Optional[Sequence[str]] = None,
    artifact_class: str = "source",
) -> Dict[str, Any]:
    """
    Sign an artifact's authorship.

    Args:
        signer: The author's ``Signer``.
        artifact_digest: The artifact's canonical digest, which the credential binds.
        author_class: ``CLASS_HUMAN`` or ``CLASS_AUTONOMOUS``.
        custody_class: How the signing key is held. Only a human presence
            authenticator terminates the distance computation.
        authorized_by: For an autonomous author, the artifact digest or identifier
            of the authority under which it acted.
        derived_from: Parent artifact digests this artifact was derived from.
        artifact_class: The artifact's class, used for class-specific bounds.
    """
    if author_class not in KNOWN_AUTHOR_CLASSES:
        raise PacingError(f"unknown author class: {author_class!r}")
    if not artifact_digest or not isinstance(artifact_digest, str):
        raise PacingError("artifact_digest is required")
    if author_class == CLASS_HUMAN and custody_class not in HUMAN_CUSTODY_CLASSES:
        raise PacingError("a human author must sign from a human presence authenticator")
    subject: Dict[str, Any] = {
        "id": artifact_digest,
        "author": signer.get_did(),
        "authorClass": author_class,
        "custodyClass": custody_class,
        "artifactClass": artifact_class,
    }
    if authorized_by:
        subject["authorizedBy"] = authorized_by
    if derived_from:
        subject["derivedFrom"] = list(derived_from)
    return base_credential(signer, AUTHORSHIP_TYPE, subject)


def human_review(
    signer: Any,
    *,
    artifact_digest: str,
    custody_class: str = CUSTODY_HUMAN_PRESENCE,
    statement: str = "",
) -> Dict[str, Any]:
    """
    Sign a human review edge over one artifact's exact digest.

    The edge binds the reviewing key to the reviewed bytes, so a review cannot be
    carried over to different content.
    """
    if custody_class not in HUMAN_CUSTODY_CLASSES:
        raise PacingError("a human review must be signed from a human presence authenticator")
    if not artifact_digest or not isinstance(artifact_digest, str):
        raise PacingError("artifact_digest is required")
    subject: Dict[str, Any] = {
        "id": artifact_digest,
        "reviewer": signer.get_did(),
        "custodyClass": custody_class,
    }
    if statement:
        subject["statement"] = statement
    return base_credential(signer, REVIEW_TYPE, subject)


@dataclass
class AuthorshipGraph:
    """
    The credential graph over which human distance is computed.

    Both the operator and any verifier build one of these from the same
    published credentials, so the metric a step declares is recomputable rather
    than asserted.
    """

    authorships: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    reviews: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def add_authorship(self, credential: Dict[str, Any], public_key: Any) -> bool:
        """Verify and admit an authorship credential."""
        if not verify_credential(credential, public_key, AUTHORSHIP_TYPE):
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        subject = subject_of(credential)
        artifact = subject.get("id")
        if not isinstance(artifact, str) or not artifact:
            self.reasons.append(REASON_UNKNOWN_ARTIFACT)
            return False
        if credential.get("issuer") != subject.get("author"):
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        self.authorships[artifact] = credential
        return True

    def add_review(self, credential: Dict[str, Any], public_key: Any) -> bool:
        """Verify and admit a human review edge."""
        if not verify_credential(credential, public_key, REVIEW_TYPE):
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        subject = subject_of(credential)
        artifact = subject.get("id")
        if not isinstance(artifact, str) or not artifact:
            self.reasons.append(REASON_UNKNOWN_ARTIFACT)
            return False
        if credential.get("issuer") != subject.get("reviewer"):
            self.reasons.append(REASON_INVALID_PROOF)
            return False
        self.reviews.setdefault(artifact, []).append(credential)
        return True

    def has_human_review(self, artifact: str) -> bool:
        """True if a valid human review edge covers this artifact's own digest."""
        for review in self.reviews.get(artifact, []):
            if subject_of(review).get("custodyClass") in HUMAN_CUSTODY_CLASSES:
                return True
        return False

    def _parents(self, artifact: str) -> List[str]:
        """Artifacts this one was derived from, plus the authority it acted under."""
        credential = self.authorships.get(artifact)
        if credential is None:
            return []
        subject = subject_of(credential)
        parents: List[str] = []
        derived = subject.get("derivedFrom")
        if isinstance(derived, list):
            parents.extend(str(item) for item in derived)
        authority = subject.get("authorizedBy")
        if isinstance(authority, str) and authority:
            parents.append(authority)
        return parents

    def human_distance(self, artifact: str) -> float:
        """
        Minimum authorization hops from an artifact to human custody.

        A human review edge over the artifact's own digest gives distance one. A
        human-authored artifact signed from a human presence authenticator also
        gives distance one, since the authorship signature is itself the human
        edge. Otherwise the distance is one more than the minimum over the
        artifact's parents. An artifact with no path to human custody is
        unbounded.
        """
        memo: Dict[str, float] = {}
        return self._distance(artifact, memo, set())

    def _distance(self, artifact: str, memo: Dict[str, float], stack: Set[str]) -> float:
        if artifact in memo:
            return memo[artifact]
        if artifact in stack:
            # A cycle contributes no shorter path than the one already being explored.
            return UNBOUNDED
        credential = self.authorships.get(artifact)
        if credential is None and not self.has_human_review(artifact):
            return UNBOUNDED

        if self.has_human_review(artifact):
            memo[artifact] = 1.0
            return 1.0
        subject = subject_of(credential) if credential else {}
        if (
            subject.get("authorClass") == CLASS_HUMAN
            and subject.get("custodyClass") in HUMAN_CUSTODY_CLASSES
        ):
            memo[artifact] = 1.0
            return 1.0

        stack.add(artifact)
        best = UNBOUNDED
        for parent in self._parents(artifact):
            candidate = self._distance(parent, memo, stack)
            if candidate + 1 < best:
                best = candidate + 1
        stack.discard(artifact)
        memo[artifact] = best
        return best

    def distances(self, artifacts: Iterable[str]) -> Dict[str, float]:
        """Human distance for each named artifact."""
        return {artifact: self.human_distance(artifact) for artifact in artifacts}


def step_credential(
    signer: Any,
    *,
    step_id: str,
    inputs: Sequence[str],
    graph: AuthorshipGraph,
    bound: int,
    class_bounds: Optional[Dict[str, int]] = None,
    policy_reference: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Declare a pipeline step and the human distance measured across its inputs.

    The credential carries the computed maximum and the per-artifact witness, so
    a verifier recomputes the metric rather than accepting the declaration.
    """
    if not step_id or not isinstance(step_id, str):
        raise PacingError("step_id is required")
    if not inputs:
        raise PacingError("a step must name at least one input artifact")
    measured = graph.distances(inputs)
    witness = {
        artifact: (None if value == UNBOUNDED else int(value))
        for artifact, value in measured.items()
    }
    finite = [value for value in measured.values() if value != UNBOUNDED]
    maximum = max(measured.values()) if measured else UNBOUNDED
    subject: Dict[str, Any] = {
        "id": step_id,
        "operator": signer.get_did(),
        "inputs": list(inputs),
        "humanDistanceWitness": witness,
        "maxHumanDistance": None if maximum == UNBOUNDED else int(maximum),
        "declaredBound": int(bound),
        "finiteInputCount": len(finite),
    }
    if class_bounds:
        subject["classBounds"] = {str(k): int(v) for k, v in class_bounds.items()}
    if policy_reference:
        subject["policyReference"] = policy_reference
    return base_credential(signer, STEP_TYPE, subject)


def check_step(
    step: Dict[str, Any],
    operator_public_key: Any,
    graph: AuthorshipGraph,
    *,
    bound: Optional[int] = None,
    class_bounds: Optional[Dict[str, int]] = None,
) -> List[str]:
    """
    Recompute the metric and decide whether the step may run.

    Returns the reasons the step is refused. An empty list means every input's
    human distance is finite and at or below the applicable bound, and the
    declared witness matches the recomputation.
    """
    reasons: List[str] = []
    if not verify_credential(step, operator_public_key, STEP_TYPE):
        return [REASON_INVALID_PROOF]
    subject = subject_of(step)
    inputs = subject.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        return [REASON_UNKNOWN_ARTIFACT]

    effective_bound = int(bound if bound is not None else subject.get("declaredBound", 0))
    declared_witness = subject.get("humanDistanceWitness") or {}
    effective_class_bounds = class_bounds or {
        str(k): int(v) for k, v in (subject.get("classBounds") or {}).items()
    }

    for artifact in inputs:
        measured = graph.human_distance(str(artifact))
        declared = declared_witness.get(str(artifact), "absent")
        expected = None if measured == UNBOUNDED else int(measured)
        if declared == "absent" or declared != expected:
            reasons.append(REASON_WITNESS_MISMATCH)
        if measured == UNBOUNDED:
            reasons.append(REASON_NO_HUMAN_PATH)
            continue
        artifact_bound = effective_bound
        authorship = graph.authorships.get(str(artifact))
        if authorship is not None:
            artifact_class = subject_of(authorship).get("artifactClass")
            if isinstance(artifact_class, str) and artifact_class in effective_class_bounds:
                artifact_bound = min(artifact_bound, effective_class_bounds[artifact_class])
        if measured > artifact_bound:
            reasons.append(REASON_BOUND_EXCEEDED)

    reasons.extend(graph.reasons)
    return reasons


def max_human_distance(graph: AuthorshipGraph, artifacts: Sequence[str]) -> float:
    """The maximum human distance across a set of artifacts."""
    if not artifacts:
        return UNBOUNDED
    return max(graph.human_distance(artifact) for artifact in artifacts)
