"""
Tests for the server-side credential gate (vouch.gate.CredentialGate) and the
one-line FastAPI dependency (vouch.integrations.fastapi.VouchGate).

The gate is the receiving-side counterpart to vouch.protect: it verifies inbound
credentials, enforces optional intent policy, and never raises from check().
"""

import json

import pytest

from vouch import Signer, generate_identity
from vouch.gate import CredentialGate


@pytest.fixture
def issuer():
    return generate_identity(domain="agent.example.com")


@pytest.fixture
def signer(issuer):
    return Signer(private_key=issuer.private_key_jwk, did=issuer.did)


@pytest.fixture
def credential(signer):
    return signer.sign({"action": "charge", "target": "api.bank.example.com", "resource": "inv/42"})


class TestCredentialGateCore:
    def test_offline_with_public_key(self, issuer, credential):
        gate = CredentialGate(public_key=issuer.public_key_jwk)
        result = gate.check(credential)
        assert result.ok
        assert result.passport.iss == issuer.did

    def test_missing_credential(self, issuer):
        gate = CredentialGate(public_key=issuer.public_key_jwk)
        result = gate.check(None)
        assert result.ok is False
        assert result.passport is None
        assert "missing" in result.reason

    def test_accepts_json_string_and_dict(self, issuer, credential):
        gate = CredentialGate(public_key=issuer.public_key_jwk)
        assert gate.check(credential).ok
        assert gate.check(json.dumps(credential)).ok

    def test_trusted_keys_allowlist(self, issuer, credential):
        gate = CredentialGate(trusted_keys={issuer.did: issuer.public_key_jwk})
        assert gate.check(credential).ok

        # An issuer not in the allowlist is rejected (offline, no resolution).
        other = generate_identity(domain="evil.example.com")
        evil = Signer(private_key=other.private_key_jwk, did=other.did).sign(
            {"action": "x", "target": "t", "resource": "r"}
        )
        assert gate.check(evil).ok is False

    def test_tamper_rejected(self, issuer, signer):
        cred = signer.sign({"action": "a", "target": "t", "resource": "r"})
        cred["credentialSubject"]["intent"]["action"] = "STEAL"
        gate = CredentialGate(public_key=issuer.public_key_jwk)
        assert gate.check(cred).ok is False

    def test_intent_policy_match(self, issuer, credential):
        gate = CredentialGate(public_key=issuer.public_key_jwk, require_action="charge")
        assert gate.check(credential).ok

    def test_intent_policy_mismatch_keeps_passport(self, issuer, credential):
        gate = CredentialGate(public_key=issuer.public_key_jwk, require_action="refund")
        result = gate.check(credential)
        assert result.ok is False
        # The credential verified; it just is not allowed for this policy.
        assert result.passport is not None
        assert "action" in result.reason

    def test_malformed_input_does_not_raise(self, issuer):
        gate = CredentialGate(public_key=issuer.public_key_jwk)
        assert gate.check("not json at all").ok is False


# -- FastAPI adapter (skipped cleanly when fastapi is not installed) -----------

fastapi = pytest.importorskip("fastapi")


@pytest.fixture
def client(issuer):
    from typing import Annotated

    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from vouch.integrations.fastapi import VouchGate
    from vouch.verifier import CredentialPassport

    app = FastAPI()
    gate = VouchGate(public_key=issuer.public_key_jwk, require_action="charge")

    @app.post("/charge")
    async def charge(passport: Annotated[CredentialPassport, Depends(gate)]):
        return {"agent": passport.iss, "intent": passport.intent}

    return TestClient(app)


class TestVouchGateFastAPI:
    def test_valid_via_header(self, client, credential):
        resp = client.post("/charge", headers={"Vouch-Credential": json.dumps(credential)})
        assert resp.status_code == 200
        assert resp.json()["intent"]["action"] == "charge"

    def test_valid_via_body(self, client, credential):
        resp = client.post("/charge", content=json.dumps(credential))
        assert resp.status_code == 200

    def test_missing_is_401(self, client):
        assert client.post("/charge").status_code == 401

    def test_policy_violation_is_403(self, client, signer):
        bad = signer.sign({"action": "refund", "target": "t", "resource": "r"})
        resp = client.post("/charge", headers={"Vouch-Credential": json.dumps(bad)})
        assert resp.status_code == 403
