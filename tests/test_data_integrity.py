"""Tests for the eddsa-jcs-2022 Data Integrity proof builder/verifier."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import data_integrity, vc


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
