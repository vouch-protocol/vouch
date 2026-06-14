"""Tests for the composed agent-call trust check (vouch/trust_check.py)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.vc import build_session_voucher
from vouch.revocation import RevocationRegistry, MemoryRevocationStore
from vouch.trust_check import verify_agent_call, verify_agent_call_async

INTENT = {"action": "read", "target": "order:1", "resource": "https://api.example.com/orders/1"}


@pytest.fixture
def agent():
    ident = generate_identity(domain="caller.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    cred = signer.sign_credential(intent=INTENT, valid_seconds=300)
    return ident, signer, cred


def test_valid_call_passes(agent):
    ident, signer, cred = agent
    v = verify_agent_call(cred, public_key=signer.get_public_key_multikey())
    assert v.ok is True
    assert v.identity_ok is True
    assert v.revoked is False
    assert v.reasons == []


def test_no_key_means_identity_not_established(agent):
    _, _, cred = agent
    v = verify_agent_call(cred, public_key=None)
    # Without a key only structural checks run; identity cannot be relied on.
    assert v.identity_ok is False
    assert v.ok is False
    assert "no_public_key" in v.reasons


def test_revoked_caller_fails(agent):
    ident, signer, cred = agent
    v = verify_agent_call(cred, public_key=signer.get_public_key_multikey(), revoked=True)
    assert v.ok is False
    assert v.revoked is True
    assert "issuer_revoked" in v.reasons


def test_fresh_voucher_meets_threshold(agent):
    ident, signer, cred = agent
    voucher = build_session_voucher(
        subject_did=ident.did,
        validator_dids=["did:web:v.example.com"],
        decay_lambda=0.01,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["agent_actions"],
        valid_seconds=120,
    )
    v = verify_agent_call(
        cred, public_key=signer.get_public_key_multikey(),
        session_voucher=voucher, trust_threshold=0.5,
    )
    assert v.ok is True
    assert v.trust_ok is True
    assert v.trust is not None and v.trust > 0.5


def test_decayed_voucher_below_threshold_fails(agent):
    ident, signer, cred = agent
    voucher = build_session_voucher(
        subject_did=ident.did,
        validator_dids=["did:web:v.example.com"],
        decay_lambda=0.01,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["agent_actions"],
        valid_seconds=120,
    )
    # Evaluate far in the future: trust has decayed well below the threshold.
    future = datetime.now(timezone.utc) + timedelta(hours=10)
    v = verify_agent_call(
        cred, public_key=signer.get_public_key_multikey(),
        session_voucher=voucher, trust_threshold=0.5, at_time=future,
    )
    assert v.ok is False
    assert v.trust_ok is False
    assert any("trust_below_threshold" in r for r in v.reasons)


def test_async_checks_revocation_registry(agent):
    ident, signer, cred = agent
    registry = RevocationRegistry(local_store=MemoryRevocationStore(), check_remote=False)

    async def run():
        # Not revoked yet.
        v1 = await verify_agent_call_async(
            cred, public_key=signer.get_public_key_multikey(), revocation=registry
        )
        assert v1.ok is True and v1.revoked is False
        # Revoke the issuer, then re-check.
        await registry.revoke(did=ident.did, reason="leaked")
        v2 = await verify_agent_call_async(
            cred, public_key=signer.get_public_key_multikey(), revocation=registry
        )
        assert v2.ok is False and v2.revoked is True

    asyncio.run(run())
