"""Tests for the FastAPI credential gate example (examples/fastapi_credential_gate.py).

Mirrors the fastapi-test convention used by test_validator_server.py: skip when
fastapi is not installed (e.g. on CI, which installs only the `dev` extra), run
otherwise. The test asserts HTTP behavior only; all verification logic lives in
Verifier.verify.
"""

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")
from fastapi.testclient import TestClient

from vouch import Signer, generate_identity

EXAMPLE_PATH = Path(__file__).resolve().parent.parent / "examples" / "fastapi_credential_gate.py"


def _load_example():
    spec = importlib.util.spec_from_file_location("fastapi_credential_gate", EXAMPLE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sign(signer: Signer, **kwargs) -> str:
    """Mint a signed Vouch Credential and return it as the header JSON string."""
    cred = signer.sign(
        intent={
            "action": "read",
            "target": "inbox",
            "resource": "https://example.com/api/inbox",
        },
        **kwargs,
    )
    return json.dumps(cred)


@pytest.fixture
def identity():
    return generate_identity(domain="example.com")


@pytest.fixture
def signer(identity):
    return Signer(private_key=identity.private_key_jwk, did=identity.did)


@pytest.fixture
def client(identity, monkeypatch):
    """TestClient whose gate trusts `identity` as the issuer.

    The example builds its VouchGate from VOUCH_PUBLIC_KEY at import time, so set
    the env var before loading the module.
    """
    monkeypatch.setenv("VOUCH_PUBLIC_KEY", identity.public_key_jwk)
    module = _load_example()
    return TestClient(module.app)


def test_signed_request_passes(client, signer, identity):
    resp = client.post(
        "/api/resource",
        headers={"Vouch-Credential": _sign(signer)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "verified"
    assert body["agent"] == identity.did
    assert body["intent"]["resource"] == "https://example.com/api/inbox"


def test_missing_header_returns_401(client):
    resp = client.post("/api/resource")
    assert resp.status_code == 401


def test_garbage_header_returns_401(client):
    resp = client.post("/api/resource", headers={"Vouch-Credential": "not-a-credential"})
    assert resp.status_code == 401


def test_wrong_issuer_key_returns_401(client):
    """A credential signed by a different identity than the trusted key is rejected."""
    other = generate_identity(domain="attacker.example.com")
    other_signer = Signer(private_key=other.private_key_jwk, did=other.did)
    resp = client.post(
        "/api/resource",
        headers={"Vouch-Credential": _sign(other_signer)},
    )
    assert resp.status_code == 401


def test_expired_credential_returns_401(client, signer):
    """A credential whose validUntil is well in the past is rejected."""
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    resp = client.post(
        "/api/resource",
        headers={"Vouch-Credential": _sign(signer, valid_from=past, valid_seconds=60)},
    )
    assert resp.status_code == 401
