"""Tests for the reference validator HTTP transport (vouch/validator_server.py)."""

import pytest
from fastapi.testclient import TestClient

from vouch import Signer, generate_identity
from vouch.heartbeat import HeartbeatSession, HeartbeatValidator
from vouch.quorum import HeartbeatQuorum, QuorumValidator
from vouch import data_integrity
from vouch.attribution import _pub_from_jwk  # reuse the Ed25519 JWK -> pubkey helper
from vouch.validator_server import create_validator_app

AGENT_DID = "did:web:agent.example.com"


@pytest.fixture
def signer_identity():
    ident = generate_identity(domain="validator.example.com")
    return ident, Signer(private_key=ident.private_key_jwk, did=ident.did)


def _quorum():
    validators = [
        QuorumValidator(validator=HeartbeatValidator(validator_did=f"did:web:v{i}.example.com"))
        for i in range(1, 4)
    ]
    return HeartbeatQuorum(validators=validators, threshold=2)  # 2-of-3


@pytest.fixture
def client(signer_identity):
    _, signer = signer_identity
    app = create_validator_app(coordinator=_quorum(), signer=signer)
    return TestClient(app)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_heartbeat_issues_signed_voucher(client, signer_identity):
    ident, _ = signer_identity
    req = HeartbeatSession(subject_did=AGENT_DID).build_request().to_dict()
    r = client.post("/heartbeat", json=req)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    voucher = body["session_voucher"]
    assert "proof" in voucher
    # The voucher proof verifies against the validator server's public key.
    assert data_integrity.verify_proof(voucher, _pub_from_jwk(ident.public_key_jwk))
    assert len(body["approving_dids"]) >= 2  # 2-of-3 quorum met


def test_voucher_published_with_cache_headers(client):
    req = HeartbeatSession(subject_did=AGENT_DID).build_request().to_dict()
    client.post("/heartbeat", json=req)
    r = client.get(f"/vouchers/{AGENT_DID}/{req['session_id']}")
    assert r.status_code == 200
    assert "ETag" in r.headers
    assert "max-age" in r.headers.get("Cache-Control", "")
    # Conditional GET returns 304.
    etag = r.headers["ETag"]
    r2 = client.get(
        f"/vouchers/{AGENT_DID}/{req['session_id']}",
        headers={"If-None-Match": etag},
    )
    assert r2.status_code == 304


def test_voucher_404_when_absent(client):
    r = client.get(f"/vouchers/{AGENT_DID}/no-such-session")
    assert r.status_code == 404


def test_session_status_reflects_voucher(client):
    req = HeartbeatSession(subject_did=AGENT_DID).build_request().to_dict()
    sid = req["session_id"]
    before = client.get(f"/sessions/{AGENT_DID}/{sid}").json()
    assert before["has_active_voucher"] is False
    client.post("/heartbeat", json=req)
    after = client.get(f"/sessions/{AGENT_DID}/{sid}").json()
    assert after["has_active_voucher"] is True
    assert after["revoked"] is False


def test_revoked_did_is_blocked(client):
    sess = HeartbeatSession(subject_did=AGENT_DID)
    # First heartbeat works.
    assert client.post("/heartbeat", json=sess.build_request().to_dict()).json()["ok"]
    # Revoke the agent.
    rv = client.post("/revoke", json={"did": AGENT_DID, "reason": "key leaked"})
    assert rv.status_code == 200 and rv.json()["revoked"] is True
    # Next heartbeat is refused with 403.
    r = client.post("/heartbeat", json=sess.build_request().to_dict())
    assert r.status_code == 403 and r.json()["revoked"] is True


def test_missing_fields_rejected(client):
    r = client.post("/heartbeat", json={"foo": "bar"})
    assert r.status_code == 400


def test_replayed_heartbeat_rejected(client):
    req = HeartbeatSession(subject_did=AGENT_DID).build_request().to_dict()
    assert client.post("/heartbeat", json=req).json()["ok"] is True
    # Replaying the exact same request is stale; quorum should not approve.
    replay = client.post("/heartbeat", json=req)
    assert replay.status_code == 200
    assert replay.json()["ok"] is False


def test_single_validator_coordinator(signer_identity):
    _, signer = signer_identity
    app = create_validator_app(
        coordinator=HeartbeatValidator(validator_did="did:web:solo.example.com"),
        signer=signer,
    )
    c = TestClient(app)
    req = HeartbeatSession(subject_did=AGENT_DID).build_request().to_dict()
    body = c.post("/heartbeat", json=req).json()
    assert body["ok"] is True
    assert "reasons" in body  # single-validator result shape
