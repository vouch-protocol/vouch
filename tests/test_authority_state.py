"""
Tests for Authority Freshness (vouch/authority_state.py) and its wiring into the
heartbeat channel, the SessionVoucher, and the composed trust check.

Authority Freshness treats freshness as f(elapsed_time, authority_epoch,
consequence). The heart of the suite is the collapse test: the SAME time-valid
voucher is accepted for a routine action and rejected for a state-freshness
action once the verifier has learned a newer authority epoch.
"""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import data_integrity
from vouch.multikey import encode_ed25519_public
from vouch.authority_state import (
    AUTHORITY_FRESHNESS_POLICY,
    STATUS_ACTIVE,
    STATUS_SUSPENDED,
    AuthorityStateError,
    build_authority_state,
    build_live_authority_cosign,
    cosign_signing_input,
    evaluate_authority_freshness,
    read_authority_epoch,
    verify_authority_state,
    verify_live_authority_cosign,
)
from vouch.status_list import (
    CONSEQUENCE_CRITICAL,
    CONSEQUENCE_ROUTINE,
    CONSEQUENCE_SENSITIVE,
)
from vouch.heartbeat import HeartbeatRequest, HeartbeatSession, HeartbeatValidator
from vouch.vc import build_session_voucher
from vouch.trust_check import verify_agent_call


AUTHORITY_DID = "did:web:treasury.example.com"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, priv.public_key(), encode_ed25519_public(raw_pub)


def _signed_authority_state(
    priv, epoch, *, status=STATUS_ACTIVE, issuer=AUTHORITY_DID, valid_from=None
):
    cred = build_authority_state(issuer, epoch, status=status, valid_from=valid_from)
    proof = data_integrity.build_proof(cred, priv, f"{issuer}#key-1")
    cred["proof"] = proof
    return cred


# --------------------------------------------------------------------------- #
# The AuthorityState credential
# --------------------------------------------------------------------------- #


def test_build_authority_state_shape():
    cred = build_authority_state(AUTHORITY_DID, 7, status=STATUS_ACTIVE)
    assert cred["type"] == ["VerifiableCredential", "AuthorityState"]
    assert cred["issuer"] == AUTHORITY_DID
    assert cred["credentialSubject"]["authorityEpoch"] == 7
    assert cred["credentialSubject"]["status"] == STATUS_ACTIVE


def test_build_rejects_bad_inputs():
    with pytest.raises(AuthorityStateError):
        build_authority_state(AUTHORITY_DID, -1)
    with pytest.raises(AuthorityStateError):
        build_authority_state(AUTHORITY_DID, True)  # bool is not a valid epoch
    with pytest.raises(AuthorityStateError):
        build_authority_state(AUTHORITY_DID, 1, status="bogus")


def test_verify_valid_authority_state():
    priv, pub, mk = _keypair()
    cred = _signed_authority_state(priv, 3)
    ok, passport = verify_authority_state(cred, pub)
    assert ok is True
    assert passport.authority_epoch == 3
    assert passport.is_active
    # Multikey string form also verifies.
    ok2, _ = verify_authority_state(cred, mk)
    assert ok2 is True


def test_verify_rejects_tamper_and_wrong_key():
    priv, pub, _ = _keypair()
    cred = _signed_authority_state(priv, 3)
    tampered = dict(cred)
    tampered["credentialSubject"] = dict(cred["credentialSubject"], authorityEpoch=9)
    ok, _ = verify_authority_state(tampered, pub)
    assert ok is False

    other_priv, other_pub, _ = _keypair()
    ok2, _ = verify_authority_state(cred, other_pub)
    assert ok2 is False


def test_verify_rejects_cross_issuer_vm():
    # A key signs a credential whose verificationMethod belongs to a different DID.
    priv, pub, _ = _keypair()
    cred = build_authority_state(AUTHORITY_DID, 1)
    cred["proof"] = data_integrity.build_proof(cred, priv, "did:web:someone-else.example.com#key-1")
    ok, _ = verify_authority_state(cred, pub)
    assert ok is False


def test_verify_rejects_expired():
    priv, pub, _ = _keypair()
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    cred = _signed_authority_state(priv, 1, valid_from=old)
    ok, _ = verify_authority_state(cred, pub)
    assert ok is False


def test_read_authority_epoch():
    cred = build_authority_state(AUTHORITY_DID, 42)
    assert read_authority_epoch(cred) == 42
    with pytest.raises(AuthorityStateError):
        read_authority_epoch({"credentialSubject": {}})


# --------------------------------------------------------------------------- #
# The collapse rule
# --------------------------------------------------------------------------- #


def test_routine_tier_is_time_decay_only():
    # A stale epoch does not matter at the routine tier.
    v = evaluate_authority_freshness(tier=CONSEQUENCE_ROUTINE, voucher_epoch=1, last_seen_epoch=9)
    assert v.allow is True


def test_sensitive_tier_allows_current_epoch():
    v = evaluate_authority_freshness(tier=CONSEQUENCE_SENSITIVE, voucher_epoch=9, last_seen_epoch=9)
    assert v.allow is True


def test_sensitive_tier_rejects_stale_epoch():
    v = evaluate_authority_freshness(tier=CONSEQUENCE_SENSITIVE, voucher_epoch=5, last_seen_epoch=7)
    assert v.allow is False
    assert v.reason == "authority_epoch_stale:seen=7,voucher=5"


def test_sensitive_tier_rejects_unknown_epoch():
    # An absent epoch renders as "?" so the reason code is identical in every
    # language binding. Pinned by the shared interop vector.
    v = evaluate_authority_freshness(
        tier=CONSEQUENCE_SENSITIVE, voucher_epoch=None, last_seen_epoch=3
    )
    assert v.allow is False
    assert v.reason == "authority_epoch_unknown:voucher=?,seen=3"

    v2 = evaluate_authority_freshness(
        tier=CONSEQUENCE_SENSITIVE, voucher_epoch=5, last_seen_epoch=None
    )
    assert v2.allow is False
    assert v2.reason == "authority_epoch_unknown:voucher=5,seen=?"


def test_non_active_status_fails_closed():
    v = evaluate_authority_freshness(
        tier=CONSEQUENCE_SENSITIVE,
        voucher_epoch=9,
        last_seen_epoch=9,
        current_status=STATUS_SUSPENDED,
    )
    assert v.allow is False
    assert v.reason == "authority_status_not_active:status=suspended"


def test_unknown_tier_coerces_to_critical():
    v = evaluate_authority_freshness(
        tier="made-up", voucher_epoch=9, last_seen_epoch=9, live_cosign_ok=None
    )
    assert v.tier == CONSEQUENCE_CRITICAL
    assert v.allow is False  # critical needs a live co-sign


def test_critical_tier_requires_live_cosign():
    denied = evaluate_authority_freshness(
        tier=CONSEQUENCE_CRITICAL, voucher_epoch=9, last_seen_epoch=9, live_cosign_ok=None
    )
    assert denied.allow is False
    assert denied.reason.startswith("live_cosign_required")

    allowed = evaluate_authority_freshness(
        tier=CONSEQUENCE_CRITICAL, voucher_epoch=9, last_seen_epoch=9, live_cosign_ok=True
    )
    assert allowed.allow is True


def test_policy_map_shape():
    assert AUTHORITY_FRESHNESS_POLICY[CONSEQUENCE_ROUTINE].enforce_epoch is False
    assert AUTHORITY_FRESHNESS_POLICY[CONSEQUENCE_SENSITIVE].enforce_epoch is True
    assert AUTHORITY_FRESHNESS_POLICY[CONSEQUENCE_CRITICAL].require_live_cosign is True


# --------------------------------------------------------------------------- #
# The live co-sign (zero-tolerance tier)
# --------------------------------------------------------------------------- #


def test_live_cosign_roundtrip():
    priv, pub, mk = _keypair()
    nonce = "action-nonce-1"
    cosign = build_live_authority_cosign(
        authority_did=AUTHORITY_DID, authority_epoch=9, sign=priv.sign, nonce=nonce
    )
    res = verify_live_authority_cosign(cosign, mk, expected_nonce=nonce)
    assert res.ok is True
    assert res.authority_epoch == 9


def test_live_cosign_nonce_mismatch_rejected():
    priv, _, mk = _keypair()
    cosign = build_live_authority_cosign(
        authority_did=AUTHORITY_DID, authority_epoch=9, sign=priv.sign, nonce="a"
    )
    res = verify_live_authority_cosign(cosign, mk, expected_nonce="b")
    assert res.ok is False
    assert res.reason == "cosign_nonce_mismatch"


def test_live_cosign_stale_rejected():
    priv, _, mk = _keypair()
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    cosign = build_live_authority_cosign(
        authority_did=AUTHORITY_DID, authority_epoch=9, sign=priv.sign, nonce="n", created=old
    )
    res = verify_live_authority_cosign(cosign, mk, expected_nonce="n", max_age_seconds=30)
    assert res.ok is False
    assert res.reason.startswith("cosign_stale")


def test_live_cosign_tamper_rejected():
    priv, _, mk = _keypair()
    cosign = build_live_authority_cosign(
        authority_did=AUTHORITY_DID, authority_epoch=9, sign=priv.sign, nonce="n"
    )
    cosign["authorityEpoch"] = 10  # tamper after signing
    res = verify_live_authority_cosign(cosign, mk, expected_nonce="n")
    assert res.ok is False
    assert res.reason == "cosign_signature_invalid"


def test_live_cosign_non_active_status_rejected():
    priv, _, mk = _keypair()
    cosign = build_live_authority_cosign(
        authority_did=AUTHORITY_DID,
        authority_epoch=9,
        sign=priv.sign,
        nonce="n",
        status=STATUS_SUSPENDED,
    )
    res = verify_live_authority_cosign(cosign, mk, expected_nonce="n")
    assert res.ok is False
    assert res.reason.startswith("cosign_status_not_active")


# --------------------------------------------------------------------------- #
# The heartbeat channel and the SessionVoucher carry the epoch
# --------------------------------------------------------------------------- #


def test_session_voucher_carries_epoch():
    v = build_session_voucher(
        subject_did="did:web:agent.example.com",
        validator_dids=["did:web:v.example.com"],
        decay_lambda=0.01,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["x"],
        authority_epoch=4,
    )
    assert v["credentialSubject"]["authorityEpoch"] == 4
    # Omitting it keeps the old shape.
    v0 = build_session_voucher(
        subject_did="did:web:agent.example.com",
        validator_dids=["did:web:v.example.com"],
        decay_lambda=0.01,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["x"],
    )
    assert "authorityEpoch" not in v0["credentialSubject"]


def test_heartbeat_request_roundtrips_epoch():
    session = HeartbeatSession(subject_did="did:web:agent.example.com", authority_epoch=6)
    req = session.build_request()
    assert req.authority_epoch == 6
    d = req.to_dict()
    assert d["authorityEpoch"] == 6
    back = HeartbeatRequest.from_dict(d)
    assert back.authority_epoch == 6


def test_heartbeat_validator_tracks_highest_epoch_and_mints_voucher():
    validator = HeartbeatValidator(validator_did="did:web:v.example.com")
    session = HeartbeatSession(subject_did="did:web:agent.example.com", authority_epoch=2)
    res = validator.validate(session.build_request().to_dict())
    assert res.ok
    assert res.session_voucher["credentialSubject"]["authorityEpoch"] == 2
    assert validator.highest_authority_epoch("did:web:agent.example.com") == 2

    # A later heartbeat under a newer epoch raises the high-water mark.
    session.authority_epoch = 5
    validator.validate(session.build_request().to_dict())
    assert validator.highest_authority_epoch("did:web:agent.example.com") == 5


# --------------------------------------------------------------------------- #
# The end-to-end collapse through verify_agent_call
# --------------------------------------------------------------------------- #


@pytest.fixture
def agent_call():
    from vouch import Signer, generate_identity

    ident = generate_identity(domain="caller.example.com")
    signer = Signer(private_key=ident.private_key_jwk, did=ident.did)
    intent = {"action": "transfer", "target": "vendor-1", "resource": "https://bank.example.com/x"}
    cred = signer.sign(intent=intent, valid_seconds=300)
    # A voucher minted under authority epoch 5, still well within its time window.
    voucher = build_session_voucher(
        subject_did=ident.did,
        validator_dids=["did:web:v.example.com"],
        decay_lambda=0.001,
        initial_trust=1.0,
        max_ttl_seconds=3600,
        scope=["agent_actions"],
        valid_seconds=300,
        authority_epoch=5,
    )
    return signer, cred, voucher


def test_same_voucher_accepted_routine_rejected_when_epoch_moves(agent_call):
    signer, cred, voucher = agent_call
    pub = signer.get_public_key_multikey()

    # Routine: time-decay only. The voucher is time-valid, so the call passes.
    routine = verify_agent_call(
        cred,
        public_key=pub,
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_ROUTINE,
    )
    assert routine.ok is True

    # Sensitive: the verifier has learned epoch 7 (a mandate suspension bumped
    # it). The SAME time-valid voucher, minted under epoch 5, now collapses.
    sensitive = verify_agent_call(
        cred,
        public_key=pub,
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_SENSITIVE,
        last_seen_authority_epoch=7,
    )
    assert sensitive.ok is False
    assert sensitive.authority_ok is False
    assert "authority_epoch_stale:seen=7,voucher=5" in sensitive.reasons
    # Time-decay trust itself still passed; only the state gate rejected it.
    assert sensitive.trust_ok is True


def test_sensitive_passes_when_epoch_current(agent_call):
    signer, cred, voucher = agent_call
    pub = signer.get_public_key_multikey()
    v = verify_agent_call(
        cred,
        public_key=pub,
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_SENSITIVE,
        last_seen_authority_epoch=5,
    )
    assert v.ok is True
    assert v.authority_ok is True


def test_critical_requires_live_cosign(agent_call):
    signer, cred, voucher = agent_call
    pub = signer.get_public_key_multikey()
    # Even with a current epoch, critical demands a live co-sign.
    without = verify_agent_call(
        cred,
        public_key=pub,
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_CRITICAL,
        last_seen_authority_epoch=5,
    )
    assert without.ok is False
    assert any(r.startswith("live_cosign_required") for r in without.reasons)

    with_cosign = verify_agent_call(
        cred,
        public_key=pub,
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_CRITICAL,
        last_seen_authority_epoch=5,
        live_cosign_ok=True,
    )
    assert with_cosign.ok is True
    assert with_cosign.authority_ok is True


def test_voucher_epoch_read_from_credential_subject(agent_call):
    signer, cred, voucher = agent_call
    pub = signer.get_public_key_multikey()
    # Do not pass voucher_authority_epoch explicitly; it is read from the voucher.
    v = verify_agent_call(
        cred,
        public_key=pub,
        session_voucher=voucher,
        trust_threshold=0.5,
        consequence=CONSEQUENCE_SENSITIVE,
        last_seen_authority_epoch=6,
    )
    assert v.ok is False
    assert "authority_epoch_stale:seen=6,voucher=5" in v.reasons


def test_cosign_signing_input_is_deterministic():
    now = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)
    a = cosign_signing_input(
        authority_did=AUTHORITY_DID, authority_epoch=9, status=STATUS_ACTIVE, nonce="n", created=now
    )
    b = cosign_signing_input(
        authority_did=AUTHORITY_DID, authority_epoch=9, status=STATUS_ACTIVE, nonce="n", created=now
    )
    assert a == b
    assert b'"authorityEpoch":9' in a
