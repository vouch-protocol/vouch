"""
Tests for the secure key-custody follow-up:

  - data_integrity.build_proof accepts a sign(digest) callback
  - Signer.from_backend signs without holding the raw key
  - KeyStore backends (memory, encrypted file) round-trip identities
  - Agent secure-by-default persistence and the private-key consent gate

These keep the credential wire format unchanged: a backend-signed credential
verifies with the ordinary public key, identical to a locally-signed one.
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto import jwk
from jwcrypto.common import base64url_decode

from vouch import (
    Agent,
    EncryptedFileKeyStore,
    MemoryKeyStore,
    Signer,
    Verifier,
    generate_identity,
)
from vouch import data_integrity, vc

INTENT = {"action": "read", "target": "did:web:files", "resource": "https://files/x"}


def _raw_private(keypair) -> Ed25519PrivateKey:
    priv = jwk.JWK.from_json(keypair.private_key_jwk)
    return Ed25519PrivateKey.from_private_bytes(base64url_decode(priv.get("d")))


# ---------------------------------------------------------------------------
# build_proof sign-callback
# ---------------------------------------------------------------------------


def test_build_proof_accepts_callback(keypair):
    raw = _raw_private(keypair)
    calls = []

    def sign(digest: bytes) -> bytes:
        calls.append(digest)
        return raw.sign(digest)

    cred = vc.build_vouch_credential(issuer_did=keypair.did, intent=INTENT)
    proof = data_integrity.build_proof(cred, sign, verification_method=f"{keypair.did}#key-1")
    cred["proof"] = proof
    assert len(calls) == 1
    assert proof["proofValue"].startswith("z")
    ok, _ = Verifier.verify(cred, public_key=keypair.public_key_jwk)
    assert ok


def test_build_proof_rejects_bad_signer(keypair):
    cred = vc.build_vouch_credential(issuer_did=keypair.did, intent=INTENT)
    with pytest.raises(TypeError):
        data_integrity.build_proof(cred, object(), verification_method="x")


# ---------------------------------------------------------------------------
# Signer.from_backend (key never in the Signer)
# ---------------------------------------------------------------------------


def test_signer_from_backend_jwk_public(keypair):
    raw = _raw_private(keypair)
    signer = Signer.from_backend(did=keypair.did, public_key=keypair.public_key_jwk, sign=raw.sign)
    assert signer._raw_priv is None  # the Signer does not hold the key
    cred = signer.sign(action="read", target="t", resource="https://x/r")
    ok, p = Verifier.verify(cred, public_key=keypair.public_key_jwk)
    assert ok
    assert p.issuer == keypair.did


def test_signer_from_backend_multikey_public(keypair):
    raw = _raw_private(keypair)
    local = Signer.from_keypair(keypair)
    signer = Signer.from_backend(
        did=keypair.did, public_key=local.get_public_key_multikey(), sign=raw.sign
    )
    cred = signer.sign(intent=INTENT)
    ok, _ = Verifier.verify(cred, public_key=keypair.public_key_jwk)
    assert ok


def test_backend_signer_signs_vc_but_blocks_hybrid(keypair):
    raw = _raw_private(keypair)
    signer = Signer.from_backend(did=keypair.did, public_key=keypair.public_key_jwk, sign=raw.sign)
    # A backend signer issues Data Integrity credentials (the modern path).
    cred = signer.sign(intent={"action": "a", "target": "b", "resource": "c"})
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    # Hybrid post-quantum signing needs the raw key, which a backend signer
    # does not hold, so it is blocked.
    with pytest.raises(NotImplementedError):
        signer.sign_hybrid(action="a", target="b", resource="c")


# ---------------------------------------------------------------------------
# Key stores
# ---------------------------------------------------------------------------


def test_memory_store_roundtrip(keypair):
    store = MemoryKeyStore()
    loc = store.save(keypair)
    assert "memory" in loc
    assert store.list() == [keypair.did]
    loaded = store.load(keypair.did)
    assert loaded.did == keypair.did
    assert loaded.private_key_jwk == keypair.private_key_jwk
    store.delete(keypair.did)
    assert store.list() == []


def test_encrypted_file_store_roundtrip(tmp_path, keypair):
    store = EncryptedFileKeyStore(key_dir=str(tmp_path), password="correct horse")
    loc = store.save(keypair)
    assert "encrypted" in loc
    assert keypair.did in store.list()
    loaded = store.load(keypair.did)
    assert loaded.private_key_jwk == keypair.private_key_jwk


def test_encrypted_file_store_wrong_password(tmp_path, keypair):
    EncryptedFileKeyStore(key_dir=str(tmp_path), password="right").save(keypair)
    with pytest.raises(ValueError):
        EncryptedFileKeyStore(key_dir=str(tmp_path), password="wrong").load(keypair.did)


# ---------------------------------------------------------------------------
# Agent secure-by-default persistence + consent gate
# ---------------------------------------------------------------------------


def test_agent_persists_to_given_store():
    store = MemoryKeyStore()
    agent = Agent("agent.example", store=store)
    assert store.list() == [agent.did]
    # The persisted identity can sign after reload.
    reloaded = Agent.from_store(agent.did, store)
    signed = reloaded.sign(intent=INTENT)
    ok, _ = reloaded.verify(signed)
    assert ok


def test_agent_private_key_gated_by_default():
    agent = Agent("agent.example", persist=False)
    with pytest.raises(PermissionError):
        _ = agent.private_key_jwk
    with pytest.raises(PermissionError):
        _ = agent.keypair


def test_agent_private_key_with_explicit_consent():
    agent = Agent("agent.example", persist=False, allow_key_export=True)
    assert agent.private_key_jwk  # no raise
    assert agent.keypair.did == agent.did


def test_agent_can_still_sign_without_key_access():
    agent = Agent("agent.example", persist=False)
    signed = agent.sign(intent=INTENT)
    ok, _ = agent.verify(signed)
    assert ok  # signing works even though the raw key is not exported


def test_agent_save_returns_location(tmp_path):
    agent = Agent("agent.example", persist=False)
    store = MemoryKeyStore()
    loc = agent.save(store)
    assert "memory" in loc
    assert store.list() == [agent.did]


def test_agent_from_store_keeps_key_gated():
    store = MemoryKeyStore()
    Agent("agent.example", store=store)
    did = store.list()[0]
    reloaded = Agent.from_store(did, store)
    with pytest.raises(PermissionError):
        _ = reloaded.private_key_jwk
