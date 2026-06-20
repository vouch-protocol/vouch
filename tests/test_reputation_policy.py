"""Tests for reputation policy and token attachment (Phase 4)."""

from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity
from vouch.reputation_aggregate import ReputationScore
from vouch.reputation_ledger import build_reputation_credential
from vouch.reputation_policy import (
    ReputationPolicy,
    evaluate_reputation,
    policy_for_stakes,
    reputation_pointer,
)

AGENT = "did:web:agent.example.com"
AT = datetime(2026, 6, 17, tzinfo=timezone.utc)


def _score(composite, **dims):
    return ReputationScore(version="1.0", dimensions=dims, composite=composite, support={}, count=3)


def _svc():
    kp = generate_identity(domain="registry.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def test_allows_when_above_thresholds():
    d = evaluate_reputation(_score(85, reliability=90, compliance=80), policy_for_stakes("high"))
    assert d.allowed is True
    assert d.composite == 85


def test_denies_on_low_composite():
    d = evaluate_reputation(_score(55), policy_for_stakes("high"))
    assert d.allowed is False
    assert any("composite" in f for f in d.failures)


def test_denies_on_low_dimension():
    d = evaluate_reputation(
        _score(90, compliance=40),
        ReputationPolicy(min_composite=50, min_dimensions={"compliance": 60}),
    )
    assert d.allowed is False
    assert any("compliance" in f for f in d.failures)


def test_verifies_and_evaluates_snapshot():
    kp, svc = _svc()
    snap = build_reputation_credential(svc, AGENT, _score(80, compliance=70), valid_from=AT)
    d = evaluate_reputation(snap, policy_for_stakes("high"), public_key=kp.public_key_jwk)
    assert d.allowed is True
    assert d.composite == 80


def test_tampered_snapshot_denied():
    kp, svc = _svc()
    snap = build_reputation_credential(svc, AGENT, _score(80, compliance=70), valid_from=AT)
    snap["credentialSubject"]["score"]["composite"] = 99
    d = evaluate_reputation(snap, policy_for_stakes("low"), public_key=kp.public_key_jwk)
    assert d.allowed is False
    assert any("signature" in f for f in d.failures)


def test_stale_snapshot_denied():
    kp, svc = _svc()
    old = AT - timedelta(days=30)
    snap = build_reputation_credential(svc, AGENT, _score(90), valid_from=old)
    policy = ReputationPolicy(min_composite=50, max_age_seconds=3600)
    d = evaluate_reputation(snap, policy, public_key=kp.public_key_jwk, at=AT)
    assert d.allowed is False
    assert any("stale" in f for f in d.failures)


def test_reputation_pointer_shape():
    p = reputation_pointer(registry="https://registry.example.com", record="snap-1", subject=AGENT)
    assert p["type"] == "AccountabilityRecord"
    assert p["kind"] == "reputation"
    assert p["ledger"] == "https://registry.example.com"
    assert p["record"] == "snap-1"
