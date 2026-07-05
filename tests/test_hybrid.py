"""
Tests for the hybrid Ed25519 + ML-DSA-44 cryptosuite (Specification §13.2).

Mirrors:
- go-sidecar/signer/data_integrity_hybrid_test.go
- typescript/tests/hybrid.test.ts

Skipped automatically if the optional `pqcrypto` package is not installed.
"""

from __future__ import annotations

import json

import pytest

# Skip the entire module if pqcrypto isn't available so the suite stays
# green in environments without the post-quantum dependency.
pqcrypto = pytest.importorskip("pqcrypto.sign.ml_dsa_44")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jwcrypto import jwk
from jwcrypto.common import base64url_decode

from vouch import data_integrity, data_integrity_hybrid, multikey, vc
from vouch.signer import Signer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_signer(did: str = "did:web:agent.example.com") -> Signer:
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    return Signer(private_key=key.export_private(), did=did)


def _ed25519_public_from_signer(signer: Signer) -> Ed25519PublicKey:
    pub_b64 = signer._key.get("x")
    return Ed25519PublicKey.from_public_bytes(base64url_decode(pub_b64))


def _intent() -> dict:
    return {
        "action": "read_database",
        "target": "users_table",
        "resource": "https://api.example.com/v1/users",
    }


# ---------------------------------------------------------------------------
# Multikey for ML-DSA-44
# ---------------------------------------------------------------------------


def test_encode_mldsa44_rejects_wrong_length():
    with pytest.raises(ValueError):
        multikey.encode_mldsa44_public(b"\x00" * 1311)
    with pytest.raises(ValueError):
        multikey.encode_mldsa44_public(b"\x00" * 1313)


def test_encode_mldsa44_roundtrip():
    raw = b"\x00" * 1312
    mk = multikey.encode_mldsa44_public(raw)
    assert mk.startswith("z")
    alg, decoded = multikey.decode(mk)
    assert alg == "ML-DSA-44"
    assert len(decoded) == 1312


# ---------------------------------------------------------------------------
# Direct primitive
# ---------------------------------------------------------------------------


def test_generate_mldsa44_keypair_sizes():
    pub, sec = data_integrity_hybrid.generate_mldsa44_keypair()
    assert len(pub) == 1312
    assert len(sec) == 2560


def test_build_and_verify_hybrid_direct():
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ml_pub, ml_sec = data_integrity_hybrid.generate_mldsa44_keypair()

    cred = vc.build_vouch_credential(
        issuer_did="did:web:test.example.com",
        intent=_intent(),
    )

    proof = data_integrity_hybrid.build_hybrid_proof(
        cred,
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        verification_method="did:web:test.example.com#key-1",
    )
    cred["proof"] = proof

    assert (
        data_integrity_hybrid.verify_hybrid_proof(
            cred,
            ed25519_public_key=ed_pub,
            mldsa44_public_key=ml_pub,
        )
        is True
    )


# ---------------------------------------------------------------------------
# Signer.sign_hybrid
# ---------------------------------------------------------------------------


def test_sign_hybrid_shape():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())

    proof = cred["proof"]
    assert proof["type"] == data_integrity.PROOF_TYPE
    assert proof["cryptosuite"] == data_integrity_hybrid.CRYPTOSUITE_HYBRID_EDDSA_MLDSA44
    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["verificationMethod"] == signer.verification_method_id()
    assert proof["proofValue"].startswith("z")


def test_sign_hybrid_proof_value_size():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())
    pv = cred["proof"]["proofValue"]
    decoded = multikey._b58decode(pv[1:])
    assert len(decoded) == data_integrity_hybrid.HYBRID_SIGNATURE_SIZE


def test_signer_exposes_mldsa44_multikey():
    signer = _new_signer()
    mk = signer.public_key_mldsa44_multikey()
    alg, raw = multikey.decode(mk)
    assert alg == "ML-DSA-44"
    assert len(raw) == 1312


# ---------------------------------------------------------------------------
# Verification roundtrip
# ---------------------------------------------------------------------------


def test_verify_hybrid_valid_credential():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())

    ok = data_integrity_hybrid.verify_hybrid_proof(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is True


def test_verify_hybrid_rejects_tampered_intent():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())
    cred["credentialSubject"]["intent"]["resource"] = "https://evil.example.com/x"

    ok = data_integrity_hybrid.verify_hybrid_proof(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_verify_hybrid_rejects_wrong_ed25519_key():
    signer = _new_signer()
    other = _new_signer("did:web:other.example.com")
    cred = signer.sign_hybrid(intent=_intent())

    ok = data_integrity_hybrid.verify_hybrid_proof(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(other),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_verify_hybrid_rejects_wrong_mldsa44_key():
    signer = _new_signer()
    other = _new_signer("did:web:other.example.com")
    cred = signer.sign_hybrid(intent=_intent())

    ok = data_integrity_hybrid.verify_hybrid_proof(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=other.public_key_mldsa44(),
    )
    assert ok is False


# ---------------------------------------------------------------------------
# Independence from eddsa-jcs-2022 path
# ---------------------------------------------------------------------------


def test_hybrid_and_eddsa_jcs_paths_coexist():
    signer = _new_signer()

    cred_ed = signer.sign(intent=_intent())
    assert data_integrity.verify_proof(cred_ed, _ed25519_public_from_signer(signer)) is True

    cred_hyb = signer.sign_hybrid(intent=_intent())
    assert (
        data_integrity_hybrid.verify_hybrid_proof(
            cred_hyb,
            ed25519_public_key=_ed25519_public_from_signer(signer),
            mldsa44_public_key=signer.public_key_mldsa44(),
        )
        is True
    )


def test_eddsa_jcs_verifier_rejects_hybrid_cryptosuite():
    """The eddsa-jcs-2022 verifier MUST refuse the hybrid cryptosuite identifier."""
    signer = _new_signer()
    cred_hyb = signer.sign_hybrid(intent=_intent())

    with pytest.raises(ValueError, match="cryptosuite"):
        data_integrity.verify_proof(cred_hyb, _ed25519_public_from_signer(signer))


# ---------------------------------------------------------------------------
# verificationMethod pair derivation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "input_vm,expected_ed,expected_mldsa",
    [
        (
            "did:web:agent.example.com#key-1",
            "did:web:agent.example.com#key-1",
            "did:web:agent.example.com#key-2",
        ),
        (
            "did:web:agent.example.com#abc",
            "did:web:agent.example.com#abc",
            "did:web:agent.example.com#key-2",
        ),
        (
            "did:web:agent.example.com",
            "did:web:agent.example.com",
            "did:web:agent.example.com#key-2",
        ),
    ],
)
def test_hybrid_verification_method_pair(input_vm, expected_ed, expected_mldsa):
    ed, mld = data_integrity_hybrid.hybrid_verification_method_pair(input_vm)
    assert ed == expected_ed
    assert mld == expected_mldsa


# ---------------------------------------------------------------------------
# JSON roundtrip
# ---------------------------------------------------------------------------


def test_hybrid_credential_serializes_and_verifies():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())
    text = json.dumps(cred)
    parsed = json.loads(text)

    ok = data_integrity_hybrid.verify_hybrid_proof(
        parsed,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is True
