"""
DTN revocation primitives:

  - PAD-112: conditional dead-man revocation. An authority pre-signs, while in
    contact, a revocation that becomes active offline if a renewal is not observed
    by a named epoch. Peers and the node itself enforce it.
  - PAD-120: carried proof of validity. The authority commits its set of valid
    credential ids to a signed Merkle root at an epoch; a node carries a compact
    inclusion witness proving its own credential is in the valid set, which a
    verifier checks while holding no status list. Epoch age is judged separately
    by the consequence-scaled staleness gate.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .. import merkle
from . import accumulator as _acc
from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
CONDITIONAL_REVOCATION_TYPE = "ConditionalRevocationCredential"
VALIDITY_ROOT_TYPE = "ValiditySetRootCredential"
REVOCATION_ACCUMULATOR_TYPE = "RevocationAccumulatorRoot"


# --------------------------------------------------------------------------- #
# PAD-112: conditional dead-man revocation
# --------------------------------------------------------------------------- #


def build_conditional_revocation(
    authority_signer: Any,
    *,
    target_credential_id: str,
    subject_did: str,
    deadline_epoch: int,
) -> Dict[str, Any]:
    """
    Pre-sign a revocation of `target_credential_id` that becomes active if no
    renewal at or beyond `deadline_epoch` is observed. Distribute with the node
    and its peers.
    """
    if not target_credential_id:
        raise RoboticsError("target_credential_id is required")
    if not isinstance(deadline_epoch, int) or deadline_epoch < 0:
        raise RoboticsError("deadline_epoch must be a non-negative integer")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONDITIONAL_REVOCATION_TYPE],
        "issuer": authority_signer.get_did(),
        "credentialSubject": {
            "id": subject_did,
            "targetCredentialId": target_credential_id,
            "deadlineEpoch": deadline_epoch,
            "renewalPredicate": "renewal_epoch_gte_deadline",
        },
    }
    return attach_proof(credential, authority_signer)


def verify_conditional_revocation(
    credential: Dict[str, Any], authority_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """Verify the authority's proof on a conditional revocation. Returns (ok, subject)."""
    subject = verify_typed_credential(credential, authority_public_key, CONDITIONAL_REVOCATION_TYPE)
    return (subject is not None), subject


def conditional_revocation_active(
    subject: Dict[str, Any],
    *,
    current_epoch: int,
    last_renewal_epoch: Optional[int] = None,
) -> bool:
    """
    True if the dead-man revocation has fired: the deadline has passed and no
    renewal at or beyond the deadline was observed. A node self-revokes and peers
    refuse it once this is true.
    """
    deadline = subject.get("deadlineEpoch")
    if not isinstance(deadline, int):
        raise RoboticsError("subject missing integer deadlineEpoch")
    if current_epoch <= deadline:
        return False  # deadline not yet reached
    renewed = last_renewal_epoch is not None and last_renewal_epoch >= deadline
    return not renewed


# --------------------------------------------------------------------------- #
# PAD-120: carried proof of validity (Merkle valid-set witness)
# --------------------------------------------------------------------------- #


def _sorted_leaves(valid_ids: List[str]) -> "Tuple[List[str], List[bytes]]":
    ordered = sorted(set(valid_ids))
    if not ordered:
        raise RoboticsError("valid_ids must be non-empty")
    return ordered, [cid.encode("utf-8") for cid in ordered]


def build_validity_root(
    authority_signer: Any,
    *,
    valid_ids: List[str],
    epoch: int,
) -> Dict[str, Any]:
    """
    Commit the authority's set of valid credential ids to a signed Merkle root at
    `epoch`. Published/distributed compactly (the root, not the whole set).
    """
    if not isinstance(epoch, int) or epoch < 0:
        raise RoboticsError("epoch must be a non-negative integer")
    ordered, leaves = _sorted_leaves(valid_ids)
    tree = merkle.MerkleTree(leaves=leaves)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", VALIDITY_ROOT_TYPE],
        "issuer": authority_signer.get_did(),
        "credentialSubject": {
            "id": authority_signer.get_did(),
            "epoch": epoch,
            "validSetRoot": tree.root_multibase(),
            "validSetSize": len(ordered),
        },
    }
    return attach_proof(credential, authority_signer)


def build_validity_witness(*, valid_ids: List[str], credential_id: str) -> Dict[str, Any]:
    """
    Build a compact inclusion witness proving `credential_id` is in the valid set.
    The node carries this and presents it; size is O(log n).
    """
    ordered, leaves = _sorted_leaves(valid_ids)
    if credential_id not in ordered:
        raise RoboticsError("credential_id is not in the valid set")
    index = ordered.index(credential_id)
    tree = merkle.MerkleTree(leaves=leaves)
    proof = tree.proof(index)
    return {
        "credentialId": credential_id,
        "leafIndex": proof.leaf_index,
        "steps": [
            {"sibling": merkle._encode_multibase(s.sibling), "isRight": s.is_right}
            for s in proof.steps
        ],
    }


def verify_validity_witness(
    *,
    witness: Dict[str, Any],
    signed_root_credential: Dict[str, Any],
    authority_public_key: Any,
) -> bool:
    """
    Verify, offline and holding no status list, that the witnessed credential is in
    the authority's signed valid set. The caller separately judges the root's epoch
    age via the consequence-scaled staleness gate.
    """
    subject = verify_typed_credential(
        signed_root_credential, authority_public_key, VALIDITY_ROOT_TYPE
    )
    if subject is None:
        return False
    root_mb = subject.get("validSetRoot")
    if not isinstance(root_mb, str):
        return False
    try:
        root = merkle._decode_multibase(root_mb)
        steps = [
            merkle.ProofStep(
                sibling=merkle._decode_multibase(s["sibling"]), is_right=bool(s["isRight"])
            )
            for s in witness.get("steps", [])
        ]
        proof = merkle.InclusionProof(leaf_index=int(witness["leafIndex"]), steps=steps)
        leaf = str(witness["credentialId"]).encode("utf-8")
        return merkle.verify_inclusion(leaf=leaf, proof=proof, root=root)
    except (KeyError, ValueError, TypeError, merkle.MerkleError):
        return False


# --------------------------------------------------------------------------- #
# PAD-120 (dynamic): revocation accumulator via a sparse Merkle tree.
# The authority revokes incrementally; a node carries a compact non-revocation
# proof a verifier checks against the signed root, holding no status list.
# --------------------------------------------------------------------------- #


def build_revocation_accumulator_root(
    authority_signer: Any,
    *,
    tree: "_acc.SparseMerkleTree",
    epoch: int,
) -> Dict[str, Any]:
    """Sign the current sparse-Merkle revocation root at `epoch` for distribution."""
    if not isinstance(epoch, int) or epoch < 0:
        raise RoboticsError("epoch must be a non-negative integer")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", REVOCATION_ACCUMULATOR_TYPE],
        "issuer": authority_signer.get_did(),
        "credentialSubject": {
            "id": authority_signer.get_did(),
            "epoch": epoch,
            "revocationRoot": tree.root_multibase(),
        },
    }
    return attach_proof(credential, authority_signer)


def build_non_revocation_proof(
    *, tree: "_acc.SparseMerkleTree", credential_id: str
) -> Dict[str, Any]:
    """Build a compact non-membership proof that `credential_id` is not in the revoked set."""
    return tree.non_revocation_proof(credential_id)


def verify_non_revocation(
    *,
    credential_id: str,
    proof: Dict[str, Any],
    signed_root_credential: Dict[str, Any],
    authority_public_key: Any,
) -> bool:
    """
    Verify, offline and holding no status list, that `credential_id` is not revoked
    as of the authority's signed accumulator root. The caller separately judges the
    root's epoch age via the consequence-scaled staleness gate.
    """
    subject = verify_typed_credential(
        signed_root_credential, authority_public_key, REVOCATION_ACCUMULATOR_TYPE
    )
    if subject is None:
        return False
    root_mb = subject.get("revocationRoot")
    if not isinstance(root_mb, str):
        return False
    try:
        root = merkle._decode_multibase(root_mb)
    except (ValueError, TypeError):
        return False
    return _acc.verify_non_revocation_proof(credential_id=credential_id, proof=proof, root=root)


__all__ = [
    "CONDITIONAL_REVOCATION_TYPE",
    "VALIDITY_ROOT_TYPE",
    "REVOCATION_ACCUMULATOR_TYPE",
    "build_conditional_revocation",
    "verify_conditional_revocation",
    "conditional_revocation_active",
    "build_validity_root",
    "build_validity_witness",
    "verify_validity_witness",
    "build_revocation_accumulator_root",
    "build_non_revocation_proof",
    "verify_non_revocation",
]
