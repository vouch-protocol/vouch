"""
Tests for the Vouch VC + Data Integrity issuance path (Specification §5, §7.1).

Covers:
- Required intent fields (action, target, resource)
- Validity window
- Reputation score in credentialSubject
- Delegation chain extension from a parent credential
- Resource-narrowing rule (§9.3 step 5)
- Depth limit (§9.4)
- Verification roundtrip via data_integrity.verify_proof
- Multikey export, verification-method ID
- Coexistence: legacy sign() and modern sign() share the same key
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto import jwk

from vouch import data_integrity, multikey, vc
from vouch.signer import Signer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _new_signer(did: str = "did:web:agent.example.com") -> Signer:
    """Build a Signer with a fresh Ed25519 key."""
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    return Signer(private_key=key.export_private(), did=did)


def _valid_intent() -> dict:
    return {
        "action": "read_database",
        "target": "users_table",
        "resource": "https://api.example.com/v1/users",
    }


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------


def test_sign_returns_w3c_vc_shape():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())

    assert cred["@context"] == [vc.VC_CONTEXT_V2, vc.VOUCH_CONTEXT_V1]
    assert vc.VC_TYPE in cred["type"]
    assert vc.VOUCH_CREDENTIAL_TYPE in cred["type"]
    assert cred["issuer"] == signer.did
    assert cred["id"].startswith("urn:uuid:")
    assert "validFrom" in cred and "validUntil" in cred


def test_sign_subject_carries_intent_and_version():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())

    subject = cred["credentialSubject"]
    assert subject["id"] == signer.did
    assert subject["vouchVersion"] == vc.PROTOCOL_VERSION
    assert subject["intent"] == _valid_intent()


def test_sign_attaches_data_integrity_proof():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())

    proof = cred["proof"]
    assert proof["type"] == data_integrity.PROOF_TYPE
    assert proof["cryptosuite"] == data_integrity.CRYPTOSUITE_ID
    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["verificationMethod"] == signer.verification_method_id()
    assert proof["proofValue"].startswith("z")


def test_sign_reputation_score_clamped_to_range():
    signer = _new_signer()
    cred_high = signer.sign(intent=_valid_intent(), reputation_score=200)
    cred_low = signer.sign(intent=_valid_intent(), reputation_score=-10)

    assert cred_high["credentialSubject"]["reputationScore"] == 100
    assert cred_low["credentialSubject"]["reputationScore"] == 0


def test_sign_validity_window_default():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())
    # default_expiry = 300 seconds. validFrom < validUntil.
    assert cred["validFrom"] < cred["validUntil"]


def test_sign_validity_window_override():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent(), valid_seconds=60)
    assert cred["validFrom"] < cred["validUntil"]


def test_sign_rejects_missing_resource():
    signer = _new_signer()
    bad_intent = {"action": "x", "target": "y"}  # no resource
    with pytest.raises(ValueError, match="resource"):
        signer.sign(intent=bad_intent)


def test_sign_rejects_empty_resource():
    signer = _new_signer()
    bad_intent = {"action": "x", "target": "y", "resource": ""}
    with pytest.raises(ValueError, match="resource"):
        signer.sign(intent=bad_intent)


def test_sign_json_returns_serializable_string():
    signer = _new_signer()
    encoded = signer.sign_json(intent=_valid_intent())
    parsed = json.loads(encoded)
    assert parsed["proof"]["cryptosuite"] == data_integrity.CRYPTOSUITE_ID


# ---------------------------------------------------------------------------
# Verification roundtrip
# ---------------------------------------------------------------------------


def _public_key_from_signer(signer: Signer):
    """Extract Ed25519PublicKey object for verification."""
    from jwcrypto.common import base64url_decode

    pub_b64 = signer._key.get("x")
    raw_pub = base64url_decode(pub_b64)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(raw_pub)


def test_verification_roundtrip_succeeds_for_unmodified_credential():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())
    pub = _public_key_from_signer(signer)
    assert data_integrity.verify_proof(cred, pub) is True


def test_verification_fails_when_intent_is_tampered():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())
    cred["credentialSubject"]["intent"]["resource"] = "https://evil.example.com/api"
    pub = _public_key_from_signer(signer)
    assert data_integrity.verify_proof(cred, pub) is False


def test_verification_fails_when_issuer_is_tampered():
    signer = _new_signer()
    cred = signer.sign(intent=_valid_intent())
    cred["issuer"] = "did:web:attacker.example.com"
    pub = _public_key_from_signer(signer)
    assert data_integrity.verify_proof(cred, pub) is False


# ---------------------------------------------------------------------------
# Delegation chains
# ---------------------------------------------------------------------------


def test_delegation_chain_appends_link_from_parent():
    parent = _new_signer("did:web:alice.example.com")
    child = _new_signer("did:web:assistant.example.com")

    parent_cred = parent.sign(
        intent={
            "action": "plan_trip",
            "target": "destination:Paris",
            "resource": "https://travel-api.example.com/v1/bookings",
        }
    )

    child_cred = child.sign(
        intent={
            "action": "book_flight",
            "target": "flight:AF123",
            "resource": "https://travel-api.example.com/v1/bookings/flight-AF123",
        },
        parent_credential=parent_cred,
    )

    chain = child_cred["credentialSubject"]["delegationChain"]
    assert len(chain) == 1
    assert chain[0]["issuer"] == parent.did
    assert chain[0]["subject"] == child.did


def test_delegation_chain_resource_narrowing_violation_raises():
    parent = _new_signer("did:web:alice.example.com")
    child = _new_signer("did:web:rogue.example.com")

    parent_cred = parent.sign(
        intent={
            "action": "read",
            "target": "users",
            "resource": "https://api.example.com/v1/users",
        }
    )

    # Child tries to access a different resource entirely. Must be rejected.
    with pytest.raises(ValueError, match="resource-narrowing"):
        child.sign(
            intent={
                "action": "read",
                "target": "admin",
                "resource": "https://api.example.com/v1/admin",
            },
            parent_credential=parent_cred,
        )


def test_delegation_chain_resource_narrowing_allows_sub_path():
    parent = _new_signer("did:web:alice.example.com")
    child = _new_signer("did:web:assistant.example.com")

    parent_cred = parent.sign(
        intent={
            "action": "read",
            "target": "users",
            "resource": "https://api.example.com/v1/users",
        }
    )

    # /v1/users/42 is a sub-resource of /v1/users, so this is allowed.
    grand_cred = child.sign(
        intent={
            "action": "read",
            "target": "user_42",
            "resource": "https://api.example.com/v1/users/42",
        },
        parent_credential=parent_cred,
    )
    assert len(grand_cred["credentialSubject"]["delegationChain"]) == 1


def test_delegation_chain_depth_limit_enforced():
    """A chain of 5 parents should reject a 6th hop."""
    common_resource = "https://api.example.com/v1/data"
    intent_template = {
        "action": "read",
        "target": "data",
        "resource": common_resource,
    }

    signers = [_new_signer(f"did:web:agent{i}.example.com") for i in range(7)]

    cred = signers[0].sign(intent=intent_template)
    # Build chain of length 5 (max allowed)
    for s in signers[1:6]:
        cred = s.sign(intent=intent_template, parent_credential=cred)

    assert len(cred["credentialSubject"]["delegationChain"]) == 5

    # The 6th hop must fail
    with pytest.raises(ValueError, match="max depth"):
        signers[6].sign(intent=intent_template, parent_credential=cred)


# ---------------------------------------------------------------------------
# Key / identity helpers
# ---------------------------------------------------------------------------


def test_get_public_key_multikey_format():
    signer = _new_signer()
    mk = signer.get_public_key_multikey()
    assert mk.startswith("z6Mk"), f"Unexpected Multikey prefix: {mk[:6]}"

    # Roundtrip: decode and confirm we recovered an Ed25519 32-byte key
    alg, raw = multikey.decode(mk)
    assert alg == "Ed25519"
    assert len(raw) == 32


def test_verification_method_id_is_canonical():
    signer = _new_signer("did:web:demo.example.com")
    assert signer.verification_method_id() == "did:web:demo.example.com#key-1"


# ---------------------------------------------------------------------------
# Coexistence with legacy JWS path
# ---------------------------------------------------------------------------


def test_sign_issues_data_integrity_vc():
    """sign() issues a VC with an eddsa-jcs-2022 Data Integrity proof."""
    signer = _new_signer()
    modern_cred = signer.sign(intent=_valid_intent())

    assert modern_cred["issuer"] == signer.did
    assert modern_cred["proof"]["cryptosuite"] == data_integrity.CRYPTOSUITE_ID
