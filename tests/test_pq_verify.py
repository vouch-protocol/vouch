"""vouch.verify handles post-quantum dual-proof credentials.

A dual-proof credential carries a proof set: an eddsa-jcs-2022 proof and an
mldsa44-jcs-2024 proof. Both must verify. The ML-DSA-44 key comes from an
explicit `mldsa44_public_key=` or the issuer's DID document; did:key encodes
only the Ed25519 key. Without an ML-DSA-44 key the verifier says so clearly
instead of returning a bare False.
"""

from __future__ import annotations

import copy

import pytest

pytest.importorskip("pqcrypto", reason="pqcrypto not installed")

import vouch  # noqa: E402
from vouch import Signer, generate_identity, multikey  # noqa: E402
from vouch.did_web import DIDDocument  # noqa: E402
from vouch.verifier import MissingMLDSA44KeyError, Verifier  # noqa: E402

INTENT = {"action": "read", "target": "ledger", "resource": "https://bank.example.com/ledger"}


@pytest.fixture
def pq():
    ident = generate_identity(domain="pq-agent.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    cred = signer.sign_hybrid(intent=INTENT, valid_seconds=300)
    assert isinstance(cred["proof"], list)
    return signer, cred


def test_valid_dual_proof_verifies(pq):
    signer, cred = pq
    ok, passport = Verifier.verify(
        cred,
        public_key=signer.get_public_key_multikey(),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is True
    assert passport.resource == INTENT["resource"]
    # The one-line helper, with the ML-DSA-44 key as a Multikey string.
    ok, _ = vouch.verify(
        cred,
        signer.get_public_key_multikey(),
        mldsa44_public_key=signer.public_key_mldsa44_multikey(),
    )
    assert ok is True


def test_tampered_payload_fails(pq):
    signer, cred = pq
    bad = copy.deepcopy(cred)
    bad["credentialSubject"]["intent"]["resource"] = "https://bank.example.com/vault"
    ok, _ = Verifier.verify(
        bad,
        public_key=signer.get_public_key_multikey(),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_tampered_mldsa_proof_fails(pq):
    signer, cred = pq
    bad = copy.deepcopy(cred)
    for proof in bad["proof"]:
        if proof["cryptosuite"].startswith("mldsa44"):
            value = proof["proofValue"]
            proof["proofValue"] = value[:-4] + ("AAAA" if value[-4:] != "AAAA" else "BBBB")
    ok, _ = Verifier.verify(
        bad,
        public_key=signer.get_public_key_multikey(),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_wrong_mldsa_key_fails(pq):
    signer, cred = pq
    other = Signer(
        private_key=generate_identity(domain="x.example.com").private_key_jwk, did=signer.did
    )
    ok, _ = Verifier.verify(
        cred,
        public_key=signer.get_public_key_multikey(),
        mldsa44_public_key=other.public_key_mldsa44(),
    )
    assert ok is False


def test_missing_mldsa_key_is_a_clear_error(pq):
    signer, cred = pq
    with pytest.raises(MissingMLDSA44KeyError, match="ML-DSA-44"):
        Verifier.verify(cred, public_key=signer.get_public_key_multikey())
    with pytest.raises(MissingMLDSA44KeyError, match="mldsa44_public_key"):
        vouch.verify(cred, signer.get_public_key_multikey())


def test_stripped_proof_set_fails(pq):
    """Dropping the ML-DSA-44 proof from the set must not leave a valid credential."""
    signer, cred = pq
    stripped = copy.deepcopy(cred)
    stripped["proof"] = [p for p in stripped["proof"] if p["cryptosuite"] == "eddsa-jcs-2022"]
    ok, _ = Verifier.verify(
        stripped,
        public_key=signer.get_public_key_multikey(),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_classical_credential_refused_when_post_quantum_is_required(pq):
    signer, _ = pq
    classical = signer.sign(intent=INTENT)
    ok, _ = Verifier.verify(
        classical,
        public_key=signer.get_public_key_multikey(),
        mldsa44_public_key=signer.public_key_mldsa44(),
    )
    assert ok is False


def test_mldsa_key_resolves_from_did_document(pq, monkeypatch):
    signer, cred = pq
    doc = DIDDocument.from_json(
        {
            "id": signer.did,
            "verificationMethod": [
                {
                    "id": signer.verification_method_id(),
                    "type": "Multikey",
                    "controller": signer.did,
                    "publicKeyMultibase": signer.get_public_key_multikey(),
                },
                {
                    "id": signer.mldsa44_verification_method_id(),
                    "type": "Multikey",
                    "controller": signer.did,
                    "publicKeyMultibase": signer.public_key_mldsa44_multikey(),
                },
            ],
            "assertionMethod": [
                signer.verification_method_id(),
                signer.mldsa44_verification_method_id(),
            ],
        }
    )
    assert multikey.decode(doc.get_mldsa44_public_key_multibase())[0] == "ML-DSA-44"
    from vouch import did_web

    monkeypatch.setattr(did_web, "resolve_did_web_sync", lambda did, *a, **k: doc)
    ok, _ = Verifier(allow_did_resolution=True).check_vouch_credential(cred)
    assert ok is True
