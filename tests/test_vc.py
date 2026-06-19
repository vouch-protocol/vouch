"""Tests for the VC envelope (vouch.vc)."""

import pytest

from vouch import vc


VALID_INTENT = {
    "action": "read_database",
    "target": "users_table",
    "resource": "https://api.example.com/v1/users",
}


def test_minimal_credential_shape():
    cred = vc.build_vouch_credential(issuer_did="did:web:agent.example.com", intent=VALID_INTENT)
    assert cred["@context"] == [
        "https://www.w3.org/ns/credentials/v2",
        "https://vouch-protocol.com/contexts/v1",
    ]
    assert cred["type"] == ["VerifiableCredential", "VouchCredential"]
    assert cred["issuer"] == "did:web:agent.example.com"
    assert cred["credentialSubject"]["id"] == "did:web:agent.example.com"
    assert cred["credentialSubject"]["vouchVersion"] == "1.0"
    assert cred["credentialSubject"]["intent"] == VALID_INTENT


def test_credential_id_is_uuid_urn():
    cred = vc.build_vouch_credential(issuer_did="did:web:agent.example.com", intent=VALID_INTENT)
    assert cred["id"].startswith("urn:uuid:")


def test_temporal_window_default():
    cred = vc.build_vouch_credential(issuer_did="did:web:agent.example.com", intent=VALID_INTENT)
    assert "validFrom" in cred
    assert "validUntil" in cred


def test_reputation_score_clamped():
    cred = vc.build_vouch_credential(
        issuer_did="did:web:a.example.com",
        intent=VALID_INTENT,
        reputation_score=150,
    )
    assert cred["credentialSubject"]["reputationScore"] == 100

    cred2 = vc.build_vouch_credential(
        issuer_did="did:web:a.example.com",
        intent=VALID_INTENT,
        reputation_score=-5,
    )
    assert cred2["credentialSubject"]["reputationScore"] == 0


def test_intent_missing_resource_rejected():
    with pytest.raises(ValueError, match="resource"):
        vc.build_vouch_credential(
            issuer_did="did:web:a.example.com",
            intent={"action": "read", "target": "x"},
        )


def test_intent_empty_resource_rejected():
    with pytest.raises(ValueError, match="resource"):
        vc.build_vouch_credential(
            issuer_did="did:web:a.example.com",
            intent={"action": "read", "target": "x", "resource": ""},
        )


def test_delegation_chain_attached():
    chain = [
        {
            "issuer": "did:web:alice.example.com",
            "subject": "did:web:agent.example.com",
            "intent": VALID_INTENT,
            "validFrom": "2026-04-26T09:00:00Z",
            "validUntil": "2026-04-26T11:00:00Z",
            "proof": {"type": "DataIntegrityProof", "proofValue": "zSig"},
        }
    ]
    cred = vc.build_vouch_credential(
        issuer_did="did:web:agent.example.com",
        intent=VALID_INTENT,
        delegation_chain=chain,
    )
    assert cred["credentialSubject"]["delegationChain"] == chain


def test_session_voucher_shape():
    voucher = vc.build_session_voucher(
        subject_did="did:key:z6MkAgent",
        validator_dids=["did:web:val-a", "did:web:val-b", "did:web:val-c"],
        decay_lambda=0.05,
        initial_trust=1.0,
        max_ttl_seconds=60,
        scope=["api:read", "api:write"],
    )
    assert voucher["type"] == ["VerifiableCredential", "SessionVoucher"]
    assert voucher["issuer"] == ["did:web:val-a", "did:web:val-b", "did:web:val-c"]
    assert voucher["credentialSubject"]["scope"] == ["api:read", "api:write"]
