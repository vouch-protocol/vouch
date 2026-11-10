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
    cred = signer.sign(intent=INTENT, valid_seconds=300)
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


def test_fresh_voucher_meets_threshold(agent, validator):
    ident, signer, cred = agent
    voucher = _signed_voucher(validator, ident.did)
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
        trust_threshold=0.5,
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
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        trust_threshold=0.5,
        at_time=future,
    )
    assert v.ok is False
    assert v.trust_ok is False
    assert any("trust_below_threshold" in r for r in v.reasons)


# ---------------------------------------------------------------------------
# SessionVoucher checks: proof, validity window, subject binding, safe default
# ---------------------------------------------------------------------------


@pytest.fixture
def validator():
    ident = generate_identity(domain="validator.example.com")
    return Signer(private_key=ident.private_key_jwk, did=ident.did)


def _signed_voucher(validator, subject_did, **kw):
    from vouch.vc import sign_session_voucher

    params = dict(
        subject_did=subject_did,
        validator_dids=[validator.did],
        decay_lambda=0.01,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["agent_actions"],
        valid_seconds=120,
    )
    params.update(kw)
    return sign_session_voucher(build_session_voucher(**params), validator)


def test_signed_fresh_voucher_passes(agent, validator):
    ident, signer, cred = agent
    voucher = _signed_voucher(validator, ident.did)
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
    )
    assert v.ok is True, v.reasons
    assert v.voucher_ok is True


def test_expired_voucher_is_refused(agent, validator):
    """A voucher whose validUntil passed long ago must not pass, at any threshold."""
    ident, signer, cred = agent
    voucher = _signed_voucher(
        validator, ident.did, issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc)
    )
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
        trust_threshold=0.0,
    )
    assert v.ok is False
    assert v.voucher_ok is False
    assert "voucher_expired" in v.reasons


def test_unsigned_voucher_is_refused(agent):
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
        cred, public_key=signer.get_public_key_multikey(), session_voucher=voucher
    )
    assert v.ok is False
    assert any(r.startswith("voucher_unverified") for r in v.reasons)


def test_tampered_voucher_is_refused(agent, validator):
    ident, signer, cred = agent
    voucher = _signed_voucher(validator, ident.did, decay_lambda=0.5)
    voucher["credentialSubject"]["decayLambda"] = 0.0  # try to stop the decay
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
    )
    assert v.ok is False
    assert "voucher_signature_invalid" in v.reasons


def test_voucher_from_wrong_validator_key_is_refused(agent, validator):
    ident, signer, cred = agent
    voucher = _signed_voucher(validator, ident.did)
    other = generate_identity(domain="other-validator.example.com")
    other_signer = Signer(private_key=other.private_key_jwk, did=other.did)
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=other_signer.get_public_key_multikey(),
    )
    assert v.ok is False
    assert "voucher_signature_invalid" in v.reasons


def test_voucher_for_another_agent_is_refused(agent, validator):
    ident, signer, cred = agent
    voucher = _signed_voucher(validator, "did:web:someone-else.example.com")
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
    )
    assert v.ok is False
    assert "voucher_subject_mismatch" in v.reasons


def test_default_threshold_is_not_zero(agent, validator):
    """With no explicit threshold, a decayed but still time-valid voucher fails."""
    from vouch.trust_check import DEFAULT_TRUST_THRESHOLDS

    assert DEFAULT_TRUST_THRESHOLDS == {"routine": 0.5, "sensitive": 0.75, "critical": 0.9}
    ident, signer, cred = agent
    voucher = _signed_voucher(validator, ident.did, valid_seconds=3600)
    issued = datetime.strptime(voucher["validFrom"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    # 120 s at lambda 0.01: trust = exp(-1.2) ~ 0.30, inside the validity window.
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
        at_time=issued + timedelta(seconds=120),
    )
    assert v.ok is False
    assert v.trust_ok is False
    assert any(r.startswith("trust_below_threshold") for r in v.reasons)


def test_malformed_voucher_is_a_reason_not_an_exception(agent, validator):
    ident, signer, cred = agent
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher={"type": ["VerifiableCredential"]},
        voucher_public_key=validator.get_public_key_multikey(),
    )
    assert v.ok is False
    assert any(r.startswith("voucher_malformed") for r in v.reasons)


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


def test_at_time_applies_to_the_credential_window_too(validator):
    """One evaluation time for the whole decision: credential and voucher."""
    ident = generate_identity(domain="caller.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    then = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    cred = signer.sign(intent=INTENT, valid_seconds=300, valid_from=then)
    voucher = _signed_voucher(validator, ident.did, issued_at=then)
    v = verify_agent_call(
        cred,
        public_key=signer.get_public_key_multikey(),
        session_voucher=voucher,
        voucher_public_key=validator.get_public_key_multikey(),
        at_time=then + timedelta(seconds=5),
    )
    assert v.ok is True, v.reasons
