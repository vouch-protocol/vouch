"""
Multi-node perception and trust-graph primitives:

  - PAD-122: Byzantine sensor agreement. Nodes cross-check each other's signed
    perception of an overlapping observation; a node inconsistent with a threshold
    of independent peers is flagged.
  - PAD-123: mutual-attestation mesh. Peers sign pairwise interaction attestations,
    forming a live trust graph; a node's standing is derived from recent
    corroboration by distinct neighbors and decays when attestation lapses.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .freshness import decay_weight
from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
PERCEPTION_CLAIM_TYPE = "SharedPerceptionClaim"
INTERACTION_ATTESTATION_TYPE = "InteractionAttestation"


# --------------------------------------------------------------------------- #
# PAD-122: Byzantine sensor agreement
# --------------------------------------------------------------------------- #


def build_perception_claim(
    signer: Any,
    *,
    scene_nonce: str,
    feature: str,
    value: Any,
    epoch: int,
) -> Dict[str, Any]:
    """A node signs its perception of a shared feature (a scalar or numeric vector value)."""
    if not (scene_nonce and feature):
        raise RoboticsError("scene_nonce and feature are required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", PERCEPTION_CLAIM_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": {
            "id": signer.get_did(),
            "sceneNonce": scene_nonce,
            "feature": feature,
            "value": value,
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, signer)


def verify_perception_claim(
    claim: Dict[str, Any], public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(claim, public_key, PERCEPTION_CLAIM_TYPE)
    return (subject is not None), subject


def _value_distance(a: Any, b: Any) -> Optional[float]:
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(float(a) - float(b))
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)) and len(a) == len(b):
        return math.sqrt(sum((float(a[i]) - float(b[i])) ** 2 for i in range(len(a))))
    return None


def cross_check_perception(
    claim_subjects: List[Dict[str, Any]],
    *,
    tolerance: float,
    threshold: int,
) -> Dict[str, List[str]]:
    """
    Cross-check signed perception claims of one shared feature. A node is
    `corroborated` if at least `threshold` OTHER nodes agree with it within
    `tolerance`; otherwise `flagged`. Caller passes signature-verified subjects for
    the same scene/feature.
    """
    if threshold <= 0:
        raise RoboticsError("threshold must be positive")
    by_node = {s.get("id"): s for s in claim_subjects if s.get("id")}
    corroborated: List[str] = []
    flagged: List[str] = []
    for did, s in by_node.items():
        agree = 0
        for other_did, o in by_node.items():
            if other_did == did:
                continue
            d = _value_distance(s.get("value"), o.get("value"))
            if d is not None and d <= tolerance:
                agree += 1
        (corroborated if agree >= threshold else flagged).append(did)
    return {"corroborated": sorted(corroborated), "flagged": sorted(flagged)}


# --------------------------------------------------------------------------- #
# PAD-123: mutual-attestation mesh
# --------------------------------------------------------------------------- #


def build_interaction_attestation(
    signer: Any,
    *,
    peer_did: str,
    outcome: str,
    epoch: int,
) -> Dict[str, Any]:
    """A node signs that it successfully interacted with `peer_did` at `epoch`."""
    if not peer_did:
        raise RoboticsError("peer_did is required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", INTERACTION_ATTESTATION_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": {
            "id": peer_did,
            "attestor": signer.get_did(),
            "outcome": outcome,
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, signer)


def verify_interaction_attestation(
    attestation: Dict[str, Any], attestor_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(
        attestation, attestor_public_key, INTERACTION_ATTESTATION_TYPE
    )
    return (subject is not None), subject


def node_standing(
    attestation_subjects: List[Dict[str, Any]],
    *,
    node_did: str,
    current_epoch: int,
    half_life_epochs: float,
    positive_outcomes: Sequence[str] = ("ok", "success", "authenticated"),
) -> float:
    """
    Compute a node's cluster standing: the decay-weighted sum of the most recent
    positive interaction attestation from each DISTINCT neighbor (freshest per
    neighbor), so breadth and recency of corroboration raise standing and lapsed
    attestation decays it. Caller passes signature-verified subjects.
    """
    freshest: Dict[str, int] = {}
    for s in attestation_subjects:
        if s.get("id") != node_did:
            continue
        if s.get("outcome") not in positive_outcomes:
            continue
        attestor = s.get("attestor")
        e = s.get("epoch")
        if not attestor or not isinstance(e, int) or e > current_epoch:
            continue
        if attestor not in freshest or e > freshest[attestor]:
            freshest[attestor] = e
    total = 0.0
    for e in freshest.values():
        total += decay_weight(elapsed_epochs=current_epoch - e, half_life_epochs=half_life_epochs)
    return total


__all__ = [
    "PERCEPTION_CLAIM_TYPE",
    "INTERACTION_ATTESTATION_TYPE",
    "build_perception_claim",
    "verify_perception_claim",
    "cross_check_perception",
    "build_interaction_attestation",
    "verify_interaction_attestation",
    "node_standing",
]
