"""
Tests for the hybrid Ed25519 + ML-DSA-44 cryptosuite (Specification §13.2).

Mirrors:
- go-sidecar/signer/data_integrity_hybrid_test.go
- typescript/tests/hybrid.test.ts

Skipped automatically if the optional `pqcrypto` package is not installed.
"""

from __future__ import annotations

import base64
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
    """sign_hybrid emits a proof SET, never the pre-alignment composite."""
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())

    proofs = cred["proof"]
    assert isinstance(proofs, list) and len(proofs) == 2
    ed_proof, ml_proof = proofs

    assert ed_proof["type"] == data_integrity.PROOF_TYPE
    assert ed_proof["cryptosuite"] == data_integrity.CRYPTOSUITE_ID
    assert ed_proof["proofPurpose"] == "assertionMethod"
    assert ed_proof["verificationMethod"] == signer.verification_method_id()
    assert ed_proof["proofValue"].startswith("z")

    assert ml_proof["type"] == data_integrity.PROOF_TYPE
    assert ml_proof["cryptosuite"] == data_integrity_hybrid.CRYPTOSUITE_MLDSA44
    assert ml_proof["proofPurpose"] == "assertionMethod"
    assert ml_proof["verificationMethod"] == signer.mldsa44_verification_method_id()
    assert ml_proof["proofValue"].startswith("u")

    suites = [p["cryptosuite"] for p in proofs]
    assert data_integrity_hybrid.CRYPTOSUITE_HYBRID_EDDSA_MLDSA44 not in suites


def test_sign_hybrid_proof_value_sizes():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())
    ed_proof, ml_proof = cred["proof"]

    ed_sig = multikey._b58decode(ed_proof["proofValue"][1:])
    assert len(ed_sig) == data_integrity_hybrid.ED25519_SIGNATURE_SIZE

    body = ml_proof["proofValue"][1:]
    ml_sig = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    assert len(ml_sig) == data_integrity_hybrid.MLDSA44_SIGNATURE_SIZE


def test_attach_hybrid_proof_emits_a_proof_set():
    """The pre-built-credential path emits a proof set as well."""
    signer = _new_signer()
    credential = vc.build_vouch_credential(
        issuer_did=signer.did,
        intent=_intent(),
    )
    signed = signer.attach_hybrid_proof(credential)
    assert isinstance(signed["proof"], list) and len(signed["proof"]) == 2
    assert (
        data_integrity_hybrid.verify_dual(
            signed,
            ed25519_public_key=_ed25519_public_from_signer(signer),
            mldsa44_public_key=signer.public_key_mldsa44(),
        )
        is True
    )


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

    ok = data_integrity_hybrid.verify_dual(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is True


def test_verify_hybrid_rejects_tampered_intent():
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())
    cred["credentialSubject"]["intent"]["resource"] = "https://evil.example.com/x"

    ok = data_integrity_hybrid.verify_dual(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_verify_hybrid_rejects_wrong_ed25519_key():
    signer = _new_signer()
    other = _new_signer("did:web:other.example.com")
    cred = signer.sign_hybrid(intent=_intent())

    ok = data_integrity_hybrid.verify_dual(
        cred,
        ed25519_public_key=_ed25519_public_from_signer(other),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_verify_hybrid_rejects_wrong_mldsa44_key():
    signer = _new_signer()
    other = _new_signer("did:web:other.example.com")
    cred = signer.sign_hybrid(intent=_intent())

    ok = data_integrity_hybrid.verify_dual(
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
        data_integrity_hybrid.verify_dual(
            cred_hyb,
            ed25519_public_key=_ed25519_public_from_signer(signer),
            mldsa44_public_key=signer.public_key_mldsa44(),
        )
        is True
    )


def test_eddsa_jcs_verifier_rejects_the_composite_cryptosuite():
    """The eddsa-jcs-2022 verifier MUST refuse the composite cryptosuite identifier."""
    ed_priv = Ed25519PrivateKey.generate()
    _ml_pub, ml_sec = data_integrity_hybrid.generate_mldsa44_keypair()
    cred = vc.build_vouch_credential(issuer_did="did:web:test.example.com", intent=_intent())
    cred["proof"] = data_integrity_hybrid.build_hybrid_proof(
        cred,
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        verification_method="did:web:test.example.com#key-1",
    )

    with pytest.raises(ValueError, match="cryptosuite"):
        data_integrity.verify_proof(cred, ed_priv.public_key())


def test_eddsa_jcs_verifier_refuses_a_proof_set():
    """A proof-set credential is not a single-proof document, so the
    eddsa-jcs-2022 verifier refuses it rather than checking one half."""
    signer = _new_signer()
    cred = signer.sign_hybrid(intent=_intent())

    with pytest.raises(ValueError, match="proof"):
        data_integrity.verify_proof(cred, _ed25519_public_from_signer(signer))


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

    ok = data_integrity_hybrid.verify_dual(
        parsed,
        ed25519_public_key=_ed25519_public_from_signer(signer),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is True


# ---------------------------------------------------------------------------
# Proof set (eddsa-jcs-2022 + mldsa44-jcs-2024)
# ---------------------------------------------------------------------------


def _dual_keys():
    ed_priv = Ed25519PrivateKey.generate()
    ml_pub, ml_sec = data_integrity_hybrid.generate_mldsa44_keypair()
    return ed_priv, ed_priv.public_key(), ml_pub, ml_sec


def _dual_credential():
    return vc.build_vouch_credential(
        issuer_did="did:web:test.example.com",
        intent=_intent(),
    )


def test_sign_dual_emits_two_independent_proofs():
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )

    proofs = signed["proof"]
    assert isinstance(proofs, list) and len(proofs) == 2

    ed_proof, ml_proof = proofs
    assert ed_proof["cryptosuite"] == "eddsa-jcs-2022"
    assert ed_proof["proofValue"].startswith("z")
    assert ed_proof["verificationMethod"] == "did:web:test.example.com#key-1"

    assert ml_proof["type"] == data_integrity.PROOF_TYPE
    assert ml_proof["cryptosuite"] == "mldsa44-jcs-2024"
    # The Quantum-Resistant Cryptosuites encoding: base64url-nopad multibase.
    assert ml_proof["proofValue"].startswith("u")
    assert "=" not in ml_proof["proofValue"]
    assert ml_proof["verificationMethod"] == "did:web:test.example.com#key-2"

    decoded = base64.urlsafe_b64decode(
        ml_proof["proofValue"][1:] + "=" * (-len(ml_proof["proofValue"][1:]) % 4)
    )
    assert len(decoded) == data_integrity_hybrid.MLDSA44_SIGNATURE_SIZE

    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is True
    )


def test_dual_eddsa_proof_verifies_on_its_own():
    """A verifier that understands only eddsa-jcs-2022 can still check that proof."""
    ed_priv, ed_pub, _ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    single = {k: v for k, v in signed.items() if k != "proof"}
    single["proof"] = signed["proof"][0]
    assert data_integrity.verify_proof(single, ed_pub) is True


def test_verify_dual_rejects_a_tampered_credential():
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    signed["credentialSubject"]["intent"]["action"] = "delete_database"
    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is False
    )


def test_verify_dual_rejects_wrong_mldsa44_key():
    ed_priv, ed_pub, _ml_pub, ml_sec = _dual_keys()
    other_pub, _other_sec = data_integrity_hybrid.generate_mldsa44_keypair()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=other_pub
        )
        is False
    )


def test_verify_dual_requires_both_proofs():
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    signed["proof"] = [signed["proof"][0]]
    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is False
    )


def test_verify_dual_accepts_pre_alignment_mldsa_proof():
    """The old cryptosuite id, the old base58btc proofValue, and the old signing
    input are all still accepted so credentials already issued keep verifying."""
    ml_dsa_44 = pqcrypto
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    base = _dual_credential()

    ed_proof = data_integrity.build_proof(
        base, ed_priv, verification_method="did:web:test.example.com#key-1"
    )
    ml_proof = {
        "type": data_integrity.PROOF_TYPE,
        "cryptosuite": data_integrity_hybrid.CRYPTOSUITE_MLDSA44_LEGACY,
        "created": ed_proof["created"],
        "verificationMethod": "did:web:test.example.com#key-2",
        "proofPurpose": "assertionMethod",
    }
    legacy_digest = data_integrity.legacy_proof_digest(base, ml_proof)
    ml_proof["proofValue"] = "z" + multikey._b58encode(ml_dsa_44.sign(ml_sec, legacy_digest))

    signed = dict(base)
    signed["proof"] = [ed_proof, ml_proof]
    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is True
    )


def test_composite_proof_value_is_over_the_legacy_digest():
    """The v1.6.x composite is verify-only and keeps its pre-alignment input."""
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    cred = _dual_credential()
    proof = data_integrity_hybrid.build_hybrid_proof(
        cred,
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        verification_method="did:web:test.example.com#key-1",
    )
    unsigned = {k: v for k, v in proof.items() if k != "proofValue"}
    combined = multikey._b58decode(proof["proofValue"][1:])
    digest = data_integrity.legacy_proof_digest(cred, unsigned)
    assert len(digest) == 32
    ed_pub.verify(combined[: data_integrity_hybrid.ED25519_SIGNATURE_SIZE], digest)
    assert pqcrypto.verify(ml_pub, digest, combined[data_integrity_hybrid.ED25519_SIGNATURE_SIZE :])


# ---------------------------------------------------------------------------
# Proof-set masking: a failing member must fail the whole set
# ---------------------------------------------------------------------------


def _corrupt_proof_value(proof):
    """Flip a character in the multibase body so the signature stays decodable
    but no longer verifies."""
    corrupted = dict(proof)
    pv = corrupted["proofValue"]
    body = pv[1:]
    swapped = "2" if body[3] != "2" else "3"
    corrupted["proofValue"] = pv[0] + body[:3] + swapped + body[4:]
    return corrupted


def test_verify_dual_rejects_a_masked_classical_proof():
    """A corrupted classical proof followed by a valid one of the same suite
    MUST NOT verify: a later proof cannot mask an earlier failure."""
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    ed_proof, ml_proof = signed["proof"]
    signed["proof"] = [_corrupt_proof_value(ed_proof), ml_proof, ed_proof]

    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is False
    )


def test_verify_dual_rejects_a_masked_mldsa_proof():
    """The same masking attempt against the post-quantum member MUST fail."""
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    ed_proof, ml_proof = signed["proof"]
    signed["proof"] = [ed_proof, _corrupt_proof_value(ml_proof), ml_proof]

    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is False
    )


def test_verify_dual_rejects_a_set_missing_the_mldsa_proof():
    """Dropping the post-quantum member MUST NOT leave the credential verifying
    on the strength of the classical proof alone."""
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    signed["proof"] = [p for p in signed["proof"] if p["cryptosuite"] != "mldsa44-jcs-2024"]
    assert len(signed["proof"]) == 1

    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is False
    )


def test_verify_dual_rejects_a_set_missing_the_classical_proof():
    ed_priv, ed_pub, ml_pub, ml_sec = _dual_keys()
    signed = data_integrity_hybrid.sign_dual(
        _dual_credential(),
        ed25519_private_key=ed_priv,
        mldsa44_secret_key=ml_sec,
        ed25519_verification_method="did:web:test.example.com#key-1",
    )
    signed["proof"] = [p for p in signed["proof"] if p["cryptosuite"] != "eddsa-jcs-2022"]

    assert (
        data_integrity_hybrid.verify_dual(
            signed, ed25519_public_key=ed_pub, mldsa44_public_key=ml_pub
        )
        is False
    )
