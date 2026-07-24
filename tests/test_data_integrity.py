"""Tests for the eddsa-jcs-2022 Data Integrity proof builder/verifier."""

import hashlib
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vouch import data_integrity, jcs, vc
from vouch.multikey import _b58decode


@pytest.fixture
def keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def credential():
    return vc.build_vouch_credential(
        issuer_did="did:web:agent.example.com",
        intent={
            "action": "read_database",
            "target": "users_table",
            "resource": "https://api.example.com/v1/users",
        },
        valid_seconds=300,
    )


def test_build_proof_returns_full_proof_object(keypair, credential):
    priv, _ = keypair
    proof = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    assert proof["type"] == "DataIntegrityProof"
    assert proof["cryptosuite"] == "eddsa-jcs-2022"
    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["verificationMethod"] == "did:web:agent.example.com#key-1"
    assert proof["proofValue"].startswith("z")
    assert "created" in proof


def test_signed_credential_verifies(keypair, credential):
    priv, pub = keypair
    proof = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    credential["proof"] = proof
    assert data_integrity.verify_proof(credential, pub) is True


def test_tampered_payload_fails_verification(keypair, credential):
    priv, pub = keypair
    proof = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    credential["proof"] = proof

    # Tamper with the resource AFTER signing
    credential["credentialSubject"]["intent"]["resource"] = "https://attacker.example.com/admin"
    assert data_integrity.verify_proof(credential, pub) is False


def test_tampered_proof_fails_verification(keypair, credential):
    priv, pub = keypair
    proof = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    credential["proof"] = proof

    # Flip a byte in the proof value
    pv = credential["proof"]["proofValue"]
    credential["proof"]["proofValue"] = pv[:5] + ("Z" if pv[5] != "Z" else "Y") + pv[6:]
    assert data_integrity.verify_proof(credential, pub) is False


def test_wrong_public_key_fails_verification(keypair, credential):
    priv, _ = keypair
    proof = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    credential["proof"] = proof

    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key()
    assert data_integrity.verify_proof(credential, other_pub) is False


def test_missing_proof_raises(keypair, credential):
    _, pub = keypair
    with pytest.raises(ValueError, match="no proof"):
        data_integrity.verify_proof(credential, pub)


def test_wrong_cryptosuite_raises(keypair, credential):
    _, pub = keypair
    credential["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-rdfc-2019",
        "proofValue": "zSomething",
    }
    with pytest.raises(ValueError, match="cryptosuite"):
        data_integrity.verify_proof(credential, pub)


# ---------------------------------------------------------------------------
# W3C Data Integrity signing input
# ---------------------------------------------------------------------------


def test_hash_data_is_config_hash_then_document_hash(credential):
    unsigned = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2026-04-26T10:00:00Z",
        "verificationMethod": "did:web:agent.example.com#key-1",
        "proofPurpose": "assertionMethod",
    }
    signing_input = data_integrity.hash_data(credential, unsigned)
    assert len(signing_input) == 64

    document = {k: v for k, v in credential.items() if k != "proof"}
    config = dict(unsigned)
    config["@context"] = document["@context"]
    assert signing_input[:32] == hashlib.sha256(jcs.canonicalize(config)).digest()
    assert signing_input[32:] == hashlib.sha256(jcs.canonicalize(document)).digest()


def test_hash_data_ignores_an_existing_proof(keypair, credential):
    priv, _ = keypair
    unsigned = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2026-04-26T10:00:00Z",
        "verificationMethod": "did:web:agent.example.com#key-1",
        "proofPurpose": "assertionMethod",
    }
    before = data_integrity.hash_data(credential, unsigned)
    credential["proof"] = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    assert data_integrity.hash_data(credential, unsigned) == before


def test_proof_configuration_carries_the_document_context(credential):
    unsigned = {"type": "DataIntegrityProof", "proofValue": "zdropme"}
    config = data_integrity.proof_configuration(credential, unsigned)
    assert "proofValue" not in config
    assert config["@context"] == credential["@context"]


def test_signature_covers_the_64_byte_signing_input(keypair, credential):
    priv, pub = keypair
    proof = data_integrity.build_proof(
        credential, priv, verification_method="did:web:agent.example.com#key-1"
    )
    signature = _b58decode(proof["proofValue"][1:])
    unsigned = {k: v for k, v in proof.items() if k != "proofValue"}
    # Verifying directly against hashData proves the new input is what was
    # signed, independent of verify_proof's legacy fallback.
    pub.verify(signature, data_integrity.hash_data(credential, unsigned))


def test_signing_callback_receives_the_64_byte_signing_input(credential):
    priv = Ed25519PrivateKey.generate()
    seen = []

    def sign_callback(signing_input: bytes) -> bytes:
        seen.append(signing_input)
        return priv.sign(signing_input)

    proof = data_integrity.build_proof(
        credential, sign_callback, verification_method="did:web:agent.example.com#key-1"
    )
    credential["proof"] = proof
    assert len(seen) == 1 and len(seen[0]) == 64
    assert data_integrity.verify_proof(credential, priv.public_key()) is True


# ---------------------------------------------------------------------------
# Backward compatibility with credentials issued before the alignment
# ---------------------------------------------------------------------------

# Fixed pre-alignment credential and key. Its signature covers the old signing
# input (a single SHA-256 over the JCS form of the credential with the unsigned
# proof attached), so it exercises the legacy verification path.
_PRE_ALIGNMENT_PUBLIC_KEY = bytes.fromhex(
    "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"
)

_PRE_ALIGNMENT_CREDENTIAL = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://vouch-protocol.com/contexts/v1",
    ],
    "type": ["VerifiableCredential", "VouchCredential"],
    "issuer": "did:web:test.example.com",
    "validFrom": "2026-04-26T10:00:00Z",
    "validUntil": "2026-04-26T10:05:00Z",
    "credentialSubject": {
        "id": "did:web:test.example.com",
        "vouchVersion": "1.0",
        "intent": {
            "action": "read_database",
            "target": "users_table",
            "resource": "https://api.example.com/v1/users",
        },
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2026-04-26T10:00:00Z",
        "verificationMethod": "did:web:test.example.com#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": (
            "z24FsZHuADF9uwHAfsjW3okmynrNCCN4QkQirEPfEy5MtcXzg4uhFqz4o3RVH57cFvVXg9oarC4m51YEmNu5UQRLQ"
        ),
    },
}


def _pre_alignment_credential():
    return json.loads(json.dumps(_PRE_ALIGNMENT_CREDENTIAL))


def test_pre_alignment_credential_still_verifies():
    pub = Ed25519PublicKey.from_public_bytes(_PRE_ALIGNMENT_PUBLIC_KEY)
    assert data_integrity.verify_proof(_pre_alignment_credential(), pub) is True


def test_pre_alignment_credential_signature_is_over_the_legacy_digest():
    cred = _pre_alignment_credential()
    unsigned = {k: v for k, v in cred["proof"].items() if k != "proofValue"}
    signature = _b58decode(cred["proof"]["proofValue"][1:])
    pub = Ed25519PublicKey.from_public_bytes(_PRE_ALIGNMENT_PUBLIC_KEY)

    digest = data_integrity.legacy_proof_digest(cred, unsigned)
    assert len(digest) == 32
    pub.verify(signature, digest)

    # ...and NOT over the aligned signing input, so the fallback is what makes
    # the credential verify.
    with pytest.raises(InvalidSignature):
        pub.verify(signature, data_integrity.hash_data(cred, unsigned))


def test_tampered_pre_alignment_credential_fails():
    cred = _pre_alignment_credential()
    cred["credentialSubject"]["intent"]["action"] = "delete_database"
    pub = Ed25519PublicKey.from_public_bytes(_PRE_ALIGNMENT_PUBLIC_KEY)
    assert data_integrity.verify_proof(cred, pub) is False
