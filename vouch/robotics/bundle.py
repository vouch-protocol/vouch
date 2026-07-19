"""
DTN Bundle Protocol trust binding (PAD-124).

Binds a Verifiable Credential (originator identity/authority) and its freshness to
a delay-tolerant-networking bundle, and models the per-hop custody-transfer chain as
attributable provenance. A recipient verifies origin, authority, payload binding, and
custody offline after arbitrary delay. Transport (Bundle Protocol / RFC 9171) is out
of scope; this provides the credential/freshness binding and the custody records.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
BUNDLE_CREDENTIAL_TYPE = "BundleTrustCredential"
CUSTODY_TRANSFER_TYPE = "BundleCustodyTransfer"


def bind_credential_to_bundle(
    originator_signer: Any,
    *,
    bundle_id: str,
    payload_hash: str,
    intent: Dict[str, Any],
) -> Dict[str, Any]:
    """Bind the originator's identity, intent/authority, and the payload hash to a bundle."""
    if not (bundle_id and payload_hash):
        raise RoboticsError("bundle_id and payload_hash are required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", BUNDLE_CREDENTIAL_TYPE],
        "issuer": originator_signer.get_did(),
        "credentialSubject": {
            "id": bundle_id,
            "originator": originator_signer.get_did(),
            "payloadHash": payload_hash,
            "intent": intent,
        },
    }
    return attach_proof(credential, originator_signer)


def verify_bundle_trust(
    bundle_credential: Dict[str, Any],
    originator_public_key: Any,
    *,
    payload_hash: str,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """Verify the originator's proof and that the bound payload hash matches on arrival."""
    subject = verify_typed_credential(bundle_credential, originator_public_key, BUNDLE_CREDENTIAL_TYPE)
    if subject is None:
        return False, None
    if subject.get("payloadHash") != payload_hash:
        return False, None
    return True, subject


def build_custody_transfer(
    relay_signer: Any,
    *,
    bundle_id: str,
    previous_custodian: Optional[str],
    epoch: int,
) -> Dict[str, Any]:
    """A relay signs acceptance of custody, linking to the previous custodian, forming a chain."""
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CUSTODY_TRANSFER_TYPE],
        "issuer": relay_signer.get_did(),
        "credentialSubject": {
            "id": bundle_id,
            "custodian": relay_signer.get_did(),
            "previousCustodian": previous_custodian,
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, relay_signer)


def verify_custody_transfer(
    transfer: Dict[str, Any], custodian_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(transfer, custodian_public_key, CUSTODY_TRANSFER_TYPE)
    return (subject is not None), subject


def custody_chain_ok(
    transfer_subjects: List[Dict[str, Any]],
    *,
    bundle_id: str,
    originator: str,
) -> bool:
    """
    Confirm a list of (signature-verified) custody transfers forms an unbroken chain
    for `bundle_id`: the first custodian's previousCustodian is the originator, and
    each subsequent transfer's previousCustodian is the prior custodian.
    """
    chain = [s for s in transfer_subjects if s.get("id") == bundle_id]
    if not chain:
        return False
    expected_prev = originator
    for s in chain:
        if s.get("previousCustodian") != expected_prev:
            return False
        custodian = s.get("custodian")
        if not custodian:
            return False
        expected_prev = custodian
    return True


__all__ = [
    "BUNDLE_CREDENTIAL_TYPE",
    "CUSTODY_TRANSFER_TYPE",
    "bind_credential_to_bundle",
    "verify_bundle_trust",
    "build_custody_transfer",
    "verify_custody_transfer",
    "custody_chain_ok",
]
