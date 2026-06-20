"""Tests for the reputation aggregation function (Phase 2)."""

from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity
from vouch.receipts import COMPLIANCE, PERFORMANCE, RELIABILITY, Signal, build_state_receipt
from vouch.reputation_aggregate import (
    AGGREGATION_VERSION,
    BASELINE,
    aggregate,
    aggregate_receipts,
)

AT = datetime(2026, 6, 17, 0, 0, 0, tzinfo=timezone.utc)


def _sig(dim, value, source="StateReceipt", issuer="did:web:rp.example.com", at=AT):
    return Signal(dim, value, source, issuer, "s1", at)


def test_empty_is_baseline():
    score = aggregate([], at=AT)
    assert score.composite == BASELINE
    assert score.dimensions == {}
    assert score.count == 0
    assert score.version == AGGREGATION_VERSION


def test_single_positive_maxes_dimension():
    score = aggregate([_sig(RELIABILITY, 1.0)], at=AT)
    assert score.dimensions[RELIABILITY] == 100.0
    assert score.composite == 100.0


def test_single_negative_zeroes_dimension():
    score = aggregate([_sig(RELIABILITY, -1.0)], at=AT)
    assert score.dimensions[RELIABILITY] == 0.0


def test_decay_lets_fresh_signal_dominate():
    fresh = _sig(RELIABILITY, 1.0, at=AT)
    old = _sig(RELIABILITY, -1.0, at=AT - timedelta(days=180))  # 2 half-lives, weight 0.25
    score = aggregate([fresh, old], at=AT, half_life_days=90)
    assert score.dimensions[RELIABILITY] > BASELINE  # the fresh positive wins


def test_objective_outweighs_review():
    state = _sig(RELIABILITY, 1.0, source="StateReceipt")
    review = _sig(RELIABILITY, -1.0, source="ReviewCredential")  # weight 0.4
    score = aggregate([state, review], at=AT)
    assert score.dimensions[RELIABILITY] > BASELINE


def test_issuer_weight_can_zero_out_a_source():
    good = _sig(RELIABILITY, 1.0, issuer="did:web:trusted.example.com")
    bad = _sig(RELIABILITY, -1.0, issuer="did:web:sybil.example.com")
    score = aggregate([good, bad], at=AT, issuer_weight={"did:web:sybil.example.com": 0.0})
    assert score.dimensions[RELIABILITY] == 100.0  # the sybil contributes nothing


def test_multidimensional_and_composite():
    score = aggregate(
        [
            _sig(RELIABILITY, 1.0),
            _sig(PERFORMANCE, 1.0),
            _sig(COMPLIANCE, -1.0, source="PenaltyReceipt"),
        ],
        at=AT,
    )
    assert score.dimensions[RELIABILITY] == 100.0
    assert score.dimensions[COMPLIANCE] == 0.0
    assert 0.0 < score.composite < 100.0
    assert set(score.support.keys()) == {RELIABILITY, PERFORMANCE, COMPLIANCE}


def test_to_dict_shape():
    d = aggregate([_sig(RELIABILITY, 1.0)], at=AT).to_dict()
    assert d["version"] == AGGREGATION_VERSION
    assert d["composite"] == 100.0
    assert d["count"] == 1


def test_aggregate_receipts_filters_by_agent():
    kp, rp = (lambda kp: (kp, Signer(private_key=kp.private_key_jwk, did=kp.did)))(
        generate_identity(domain="rp.example.com")
    )
    a = "did:web:agent-a.example.com"
    b = "did:web:agent-b.example.com"
    receipts = [
        build_state_receipt(
            rp, agent=a, interaction_id="1", action="x", result="success", valid_from=AT
        ),
        build_state_receipt(
            rp, agent=b, interaction_id="2", action="x", result="failure", valid_from=AT
        ),
    ]
    score_a = aggregate_receipts(receipts, agent=a, at=AT)
    assert score_a.dimensions[RELIABILITY] == 100.0  # only a's success counts
    assert score_a.count == 1
