"""
Tests for the VC + Data Integrity verification path (Specification §8).

Covers:
- Verification roundtrip with Ed25519PublicKey, Multikey string, and JWK
- Tamper detection on credentialSubject, issuer, and proof
- Validity window and clock skew
- Required intent.resource binding
- Reputation and delegation chain extraction
- Async verifier mirror
- did:web resolution fallback to JWK for legacy documents
- Coexistence: legacy verify() and modern verify_credential() share state
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto import jwk
from jwcrypto.common import base64url_decode

from vouch import data_integrity, did_web, multikey, vc
from vouch.async_verifier import AsyncVerifier
from vouch.signer import Signer
from vouch.verifier import (
    CredentialPassport,
    Verifier,
)


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
# Static verification: happy path
# ---------------------------------------------------------------------------


def test_verify_credential_succeeds_for_valid_credential():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    pub = _ed25519_public_from_signer(signer)

    valid, passport = Verifier.verify_credential(cred, public_key=pub)
    assert valid is True
    assert isinstance(passport, CredentialPassport)
    assert passport.sub == signer.did
    assert passport.iss == signer.did
    assert passport.intent == _intent()
    assert passport.credential_id.startswith("urn:uuid:")


def test_verify_credential_accepts_multikey_string_as_key():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    multikey_str = signer.get_public_key_multikey()

    valid, passport = Verifier.verify_credential(cred, public_key=multikey_str)
    assert valid is True
    assert passport is not None


def test_verify_credential_accepts_jwk_string_as_key():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    jwk_str = signer.get_public_key_jwk()

    valid, passport = Verifier.verify_credential(cred, public_key=jwk_str)
    assert valid is True


def test_verify_credential_accepts_json_encoded_credential():
    signer = _new_signer()
    cred_json = signer.sign_credential_json(intent=_intent())
    pub = _ed25519_public_from_signer(signer)

    valid, passport = Verifier.verify_credential(cred_json, public_key=pub)
    assert valid is True


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_verify_credential_rejects_tampered_intent():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    cred["credentialSubject"]["intent"]["resource"] = "https://evil.example.com/x"
    pub = _ed25519_public_from_signer(signer)

    valid, passport = Verifier.verify_credential(cred, public_key=pub)
    assert valid is False
    assert passport is None


def test_verify_credential_rejects_tampered_issuer():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    cred["issuer"] = "did:web:attacker.example.com"
    pub = _ed25519_public_from_signer(signer)

    valid, passport = Verifier.verify_credential(cred, public_key=pub)
    assert valid is False


def test_verify_credential_rejects_tampered_proof_value():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    # Flip a character in the proofValue
    pv = cred["proof"]["proofValue"]
    cred["proof"]["proofValue"] = pv[:-2] + ("aA" if pv[-1] != "a" else "bB")
    pub = _ed25519_public_from_signer(signer)

    valid, _ = Verifier.verify_credential(cred, public_key=pub)
    assert valid is False


def test_verify_credential_rejects_wrong_public_key():
    signer = _new_signer()
    other = _new_signer("did:web:other.example.com")
    cred = signer.sign_credential(intent=_intent())

    valid, _ = Verifier.verify_credential(cred, public_key=_ed25519_public_from_signer(other))
    assert valid is False


# ---------------------------------------------------------------------------
# Temporal validation
# ---------------------------------------------------------------------------


def test_verify_credential_rejects_expired_credential():
    signer = _new_signer()
    long_ago = datetime.now(timezone.utc) - timedelta(seconds=600)
    cred = signer.sign_credential(
        intent=_intent(),
        valid_from=long_ago,
        valid_seconds=10,  # expired 590 seconds ago
    )
    pub = _ed25519_public_from_signer(signer)

    valid, _ = Verifier.verify_credential(cred, public_key=pub, clock_skew_seconds=30)
    assert valid is False


def test_verify_credential_rejects_not_yet_valid():
    signer = _new_signer()
    future = datetime.now(timezone.utc) + timedelta(seconds=600)
    cred = signer.sign_credential(intent=_intent(), valid_from=future)
    pub = _ed25519_public_from_signer(signer)

    valid, _ = Verifier.verify_credential(cred, public_key=pub, clock_skew_seconds=30)
    assert valid is False


def test_verify_credential_clock_skew_tolerance_applies():
    signer = _new_signer()
    just_expired = datetime.now(timezone.utc) - timedelta(seconds=320)
    cred = signer.sign_credential(
        intent=_intent(),
        valid_from=just_expired,
        valid_seconds=300,  # validUntil ~20 seconds in the past
    )
    pub = _ed25519_public_from_signer(signer)

    # 30s skew accepts a 20s-expired credential
    valid_with_skew, _ = Verifier.verify_credential(cred, public_key=pub, clock_skew_seconds=30)
    assert valid_with_skew is True

    # 5s skew does not
    valid_no_skew, _ = Verifier.verify_credential(cred, public_key=pub, clock_skew_seconds=5)
    assert valid_no_skew is False


# ---------------------------------------------------------------------------
# Resource binding (§5.4.1, §8.4)
# ---------------------------------------------------------------------------


def test_verify_credential_rejects_missing_resource_binding():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    # Strip the resource field after signing - signature still valid but
    # the structural rule says missing resource MUST be rejected at verify.
    cred["credentialSubject"]["intent"].pop("resource")

    valid, _ = Verifier.verify_credential(cred, public_key=None)
    # Without a key, only structural+temporal checks run, which include
    # the resource binding rule.
    assert valid is False


# ---------------------------------------------------------------------------
# Reputation and delegation extraction
# ---------------------------------------------------------------------------


def test_verify_credential_extracts_reputation_score():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent(), reputation_score=87)
    pub = _ed25519_public_from_signer(signer)

    valid, passport = Verifier.verify_credential(cred, public_key=pub)
    assert valid is True
    assert passport.reputation_score == 87


def test_verify_credential_extracts_delegation_chain():
    parent = _new_signer("did:web:alice.example.com")
    child = _new_signer("did:web:assistant.example.com")

    parent_cred = parent.sign_credential(
        intent={
            "action": "read",
            "target": "users",
            "resource": "https://api.example.com/v1/users",
        }
    )
    child_cred = child.sign_credential(
        intent={
            "action": "read",
            "target": "user_42",
            "resource": "https://api.example.com/v1/users/42",
        },
        parent_credential=parent_cred,
    )

    pub_child = _ed25519_public_from_signer(child)
    valid, passport = Verifier.verify_credential(child_cred, public_key=pub_child)
    assert valid is True
    assert len(passport.delegation_chain) == 1
    link = passport.delegation_chain[0]
    assert link.issuer == parent.did
    assert link.subject == child.did
    # The link records the child's authorized intent: what the child is doing
    # under the parent's delegation. The resource-narrowing rule (§9.3 step 5)
    # ensures it stays within the parent's scope.
    assert link.intent["resource"] == "https://api.example.com/v1/users/42"


# ---------------------------------------------------------------------------
# Coexistence: legacy and modern verifier paths share state
# ---------------------------------------------------------------------------


def test_legacy_and_modern_verifier_paths_coexist_for_one_signer():
    signer = _new_signer()

    legacy_token = signer.sign({"action": "ping"})
    legacy_valid, legacy_passport = Verifier.verify(
        legacy_token, public_key_jwk=signer.get_public_key_jwk()
    )
    assert legacy_valid is True
    assert legacy_passport.iss == signer.did

    modern_cred = signer.sign_credential(intent=_intent())
    modern_valid, modern_passport = Verifier.verify_credential(
        modern_cred, public_key=_ed25519_public_from_signer(signer)
    )
    assert modern_valid is True
    assert modern_passport.iss == signer.did


# ---------------------------------------------------------------------------
# DID document resolution helpers
# ---------------------------------------------------------------------------


def test_did_document_resolves_modern_multikey_to_ed25519():
    """A modern DID Document with Multikey should yield an Ed25519PublicKey."""
    signer = _new_signer("did:web:demo.example.com")
    multikey_str = signer.get_public_key_multikey()

    doc_data = {
        "id": "did:web:demo.example.com",
        "verificationMethod": [
            {
                "id": "did:web:demo.example.com#key-1",
                "type": "Multikey",
                "controller": "did:web:demo.example.com",
                "publicKeyMultibase": multikey_str,
            }
        ],
        "authentication": ["did:web:demo.example.com#key-1"],
        "assertionMethod": ["did:web:demo.example.com#key-1"],
    }

    doc = did_web.DIDDocument.from_json(doc_data)
    pub = doc.get_ed25519_public_key()
    assert isinstance(pub, Ed25519PublicKey)


def test_did_document_falls_back_to_legacy_jwk():
    """A legacy DID Document with publicKeyJwk should still resolve."""
    signer = _new_signer()
    jwk_str = signer.get_public_key_jwk()
    jwk_dict = json.loads(jwk_str)

    doc_data = {
        "id": "did:web:legacy.example.com",
        "verificationMethod": [
            {
                "id": "did:web:legacy.example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:legacy.example.com",
                "publicKeyJwk": jwk_dict,
            }
        ],
        "authentication": ["did:web:legacy.example.com#key-1"],
    }

    doc = did_web.DIDDocument.from_json(doc_data)
    pub = doc.get_ed25519_public_key()
    assert isinstance(pub, Ed25519PublicKey)


# ---------------------------------------------------------------------------
# Async verifier mirror
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_verify_credential_succeeds():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    pub = _ed25519_public_from_signer(signer)

    av = AsyncVerifier(allow_did_resolution=False)
    valid, passport = await av.verify_credential(cred, public_key=pub)
    assert valid is True
    assert passport.sub == signer.did


@pytest.mark.asyncio
async def test_async_verify_credential_rejects_tampered():
    signer = _new_signer()
    cred = signer.sign_credential(intent=_intent())
    cred["credentialSubject"]["intent"]["resource"] = "https://x.example.com/y"
    pub = _ed25519_public_from_signer(signer)

    av = AsyncVerifier(allow_did_resolution=False)
    valid, _ = await av.verify_credential(cred, public_key=pub)
    assert valid is False
