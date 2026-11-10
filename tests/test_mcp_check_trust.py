"""The vouch-mcp `check_trust` tool only allows authentic, unexpired vouchers."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("mcp", reason="MCP SDK not installed")

from vouch import Signer, multikey  # noqa: E402
from vouch.autosign import reset_default_signer  # noqa: E402
from vouch.integrations.mcp import server as notary  # noqa: E402
from vouch.keys import generate_identity  # noqa: E402
from vouch.vc import build_session_voucher, sign_session_voucher  # noqa: E402


def _did_key_identity():
    keypair = generate_identity()
    raw = base64.urlsafe_b64decode(json.loads(keypair.public_key_jwk)["x"] + "==")
    did = "did:key:" + multikey.encode_ed25519_public(raw)
    return keypair, did


@pytest.fixture
def notary_env(monkeypatch):
    keypair, did = _did_key_identity()
    monkeypatch.setenv("VOUCH_DID", did)
    monkeypatch.setenv("VOUCH_PRIVATE_KEY", keypair.private_key_jwk)
    reset_default_signer()
    yield Signer(private_key=keypair.private_key_jwk, did=did)
    reset_default_signer()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_fresh_voucher_from_this_server_is_allowed(notary_env):
    voucher = notary.create_session("calendar", valid_seconds=3600)
    assert notary.check_trust(voucher, threshold=0.5).startswith("ALLOW")


def test_expired_voucher_is_denied_even_with_no_decay(notary_env):
    # decay_lambda=0 keeps trust at 1.0 forever; only validUntil can stop it.
    voucher = notary.create_session("calendar", valid_seconds=60, decay_lambda=0.0)
    issued = datetime.strptime(json.loads(voucher)["validFrom"], "%Y-%m-%dT%H:%M:%SZ")
    later = _iso(issued.replace(tzinfo=timezone.utc) + timedelta(hours=1))
    out = notary.check_trust(voucher, threshold=0.5, now_iso=later)
    assert out.startswith("DENY")
    assert "voucher_expired" in out


def test_voucher_signed_by_someone_else_is_denied(notary_env):
    other_kp, other_did = _did_key_identity()
    other = Signer(private_key=other_kp.private_key_jwk, did=other_did)
    voucher = sign_session_voucher(
        build_session_voucher(
            subject_did=other_did,
            validator_dids=[other_did],
            decay_lambda=0.0,
            initial_trust=1.0,
            max_ttl_seconds=3600,
            scope=["x"],
            valid_seconds=3600,
        ),
        other,
    )
    out = notary.check_trust(json.dumps(voucher), threshold=0.5)
    assert out.startswith("DENY")
    assert "voucher_signature_invalid" in out


def test_tampered_voucher_is_denied(notary_env):
    voucher = json.loads(notary.create_session("calendar", valid_seconds=3600, decay_lambda=0.5))
    voucher["credentialSubject"]["decayLambda"] = 0.0
    out = notary.check_trust(json.dumps(voucher), threshold=0.5)
    assert out.startswith("DENY")
    assert "voucher_signature_invalid" in out
