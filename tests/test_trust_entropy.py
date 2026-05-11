"""
Unit tests for Trust Entropy decay computation (W3C CG Report §11.5).
"""

import math
from datetime import datetime, timedelta, timezone

import pytest

from vouch.trust_entropy import (
    TRUST_THRESHOLD_HIGH_STAKES,
    TRUST_THRESHOLD_LOW_STAKES,
    TRUST_THRESHOLD_MEDIUM_STAKES,
    TrustEntropyError,
    check_trust_threshold,
    compute_trust_at,
    evaluate_trust,
    half_life_seconds,
    time_until_threshold,
)
from vouch.vc import build_session_voucher


def _voucher(
    *,
    decay_lambda: float = 0.001,
    initial_trust: float = 1.0,
    validity_seconds: int = 300,
    issued_at: datetime = None,
):
    if issued_at is None:
        issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    vc = build_session_voucher(
        subject_did="did:web:agent.example.com",
        validator_dids=["did:web:validator.example.com"],
        decay_lambda=decay_lambda,
        initial_trust=initial_trust,
        max_ttl_seconds=3600,
        scope=["read", "write"],
        valid_seconds=validity_seconds,
    )
    # Override validFrom to a deterministic value for tests that need it.
    vc["validFrom"] = issued_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    return vc, issued_at


class TestComputeTrustAt:
    def test_trust_at_issue_time_equals_initial(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.01)
        trust = compute_trust_at(vc, t0)
        assert trust == pytest.approx(1.0, abs=1e-12)

    def test_trust_decays_exponentially(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.01)
        # After 100 seconds: trust = e^(-0.01*100) = e^-1 ~ 0.3679
        trust = compute_trust_at(vc, t0 + timedelta(seconds=100))
        assert trust == pytest.approx(math.exp(-1), abs=1e-9)

    def test_trust_at_half_life(self):
        decay_lambda = 0.005
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=decay_lambda)
        t_half = math.log(2) / decay_lambda
        trust = compute_trust_at(vc, t0 + timedelta(seconds=t_half))
        assert trust == pytest.approx(0.5, abs=1e-9)

    def test_trust_clamped_to_zero_for_extreme_elapsed(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=1.0)
        # 1000-second elapsed with lambda=1 -> exponent < -700 -> guard returns 0.0
        trust = compute_trust_at(vc, t0 + timedelta(seconds=2000))
        assert trust == 0.0

    def test_negative_elapsed_treated_as_zero(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.01)
        trust = compute_trust_at(vc, t0 - timedelta(seconds=60))
        assert trust == pytest.approx(1.0, abs=1e-12)

    def test_zero_decay_lambda_means_no_decay(self):
        vc, t0 = _voucher(initial_trust=0.8, decay_lambda=0.0)
        trust = compute_trust_at(vc, t0 + timedelta(days=30))
        assert trust == pytest.approx(0.8, abs=1e-12)

    def test_initial_trust_zero_stays_zero(self):
        vc, t0 = _voucher(initial_trust=0.0, decay_lambda=0.01)
        trust = compute_trust_at(vc, t0 + timedelta(seconds=10))
        assert trust == 0.0


class TestEvaluateTrust:
    def test_evaluation_passed_when_above_threshold(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.001)
        result = evaluate_trust(vc, threshold=0.9, at_time=t0 + timedelta(seconds=10))
        assert result.passed is True
        assert result.trust > 0.9

    def test_evaluation_failed_when_below_threshold(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.01)
        result = evaluate_trust(vc, threshold=0.9, at_time=t0 + timedelta(seconds=200))
        assert result.passed is False
        assert result.trust < 0.9

    def test_evaluation_serializes_to_dict(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.001)
        result = evaluate_trust(vc, threshold=TRUST_THRESHOLD_HIGH_STAKES, at_time=t0)
        d = result.to_dict()
        assert "trust" in d
        assert "threshold" in d
        assert "passed" in d
        assert d["threshold"] == TRUST_THRESHOLD_HIGH_STAKES

    def test_negative_threshold_rejected(self):
        vc, _ = _voucher()
        with pytest.raises(TrustEntropyError):
            evaluate_trust(vc, threshold=-0.1)


class TestCheckTrustThreshold:
    def test_passes_at_high_stakes_immediately(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.0001)
        assert check_trust_threshold(vc, TRUST_THRESHOLD_HIGH_STAKES, at_time=t0) is True

    def test_fails_at_high_stakes_after_long_decay(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.001)
        # After 200 seconds: e^(-0.2) ~ 0.819, below 0.9 high-stakes threshold
        assert (
            check_trust_threshold(
                vc,
                TRUST_THRESHOLD_HIGH_STAKES,
                at_time=t0 + timedelta(seconds=200),
            )
            is False
        )

    def test_low_stakes_threshold_more_forgiving(self):
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=0.001)
        # Same 200-second elapsed: 0.819 > 0.5 low-stakes threshold
        assert (
            check_trust_threshold(
                vc,
                TRUST_THRESHOLD_LOW_STAKES,
                at_time=t0 + timedelta(seconds=200),
            )
            is True
        )


class TestHalfLife:
    def test_half_life_inverse_decay_lambda(self):
        assert half_life_seconds(math.log(2)) == pytest.approx(1.0, abs=1e-12)
        assert half_life_seconds(math.log(2) / 60) == pytest.approx(60, abs=1e-9)

    def test_zero_lambda_raises(self):
        with pytest.raises(TrustEntropyError):
            half_life_seconds(0)

    def test_negative_lambda_raises(self):
        with pytest.raises(TrustEntropyError):
            half_life_seconds(-0.1)


class TestTimeUntilThreshold:
    def test_zero_elapsed_returns_full_decay_time(self):
        decay_lambda = 0.01
        vc, t0 = _voucher(initial_trust=1.0, decay_lambda=decay_lambda)
        result = time_until_threshold(vc, threshold=0.5, from_time=t0)
        expected_seconds = math.log(2) / decay_lambda
        assert result.total_seconds() == pytest.approx(expected_seconds, abs=1e-6)

    def test_already_below_threshold_returns_zero(self):
        vc, _ = _voucher(initial_trust=0.4, decay_lambda=0.01)
        result = time_until_threshold(vc, threshold=0.5)
        assert result == timedelta(0)

    def test_zero_threshold_returns_none(self):
        vc, _ = _voucher(initial_trust=1.0, decay_lambda=0.01)
        assert time_until_threshold(vc, threshold=0.0) is None

    def test_zero_decay_returns_none(self):
        vc, _ = _voucher(initial_trust=1.0, decay_lambda=0.0)
        assert time_until_threshold(vc, threshold=0.5) is None


class TestStructuralValidation:
    def test_rejects_non_session_voucher_type(self):
        vc = {
            "type": ["VerifiableCredential", "VouchCredential"],
            "credentialSubject": {"initialTrust": 1.0, "decayLambda": 0.01},
            "validFrom": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(TrustEntropyError):
            compute_trust_at(vc)

    def test_rejects_missing_initial_trust(self):
        vc = {
            "type": ["VerifiableCredential", "SessionVoucher"],
            "credentialSubject": {"decayLambda": 0.01},
            "validFrom": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(TrustEntropyError):
            compute_trust_at(vc)

    def test_rejects_negative_initial_trust(self):
        vc = {
            "type": ["VerifiableCredential", "SessionVoucher"],
            "credentialSubject": {"initialTrust": -1.0, "decayLambda": 0.01},
            "validFrom": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(TrustEntropyError):
            compute_trust_at(vc)

    def test_rejects_missing_valid_from(self):
        vc = {
            "type": ["VerifiableCredential", "SessionVoucher"],
            "credentialSubject": {"initialTrust": 1.0, "decayLambda": 0.01},
        }
        with pytest.raises(TrustEntropyError):
            compute_trust_at(vc)


class TestSessionVoucherBuilderIntegration:
    def test_compute_trust_from_real_voucher(self):
        vc = build_session_voucher(
            subject_did="did:web:agent.example.com",
            validator_dids=["did:web:validator.example.com"],
            decay_lambda=0.005,
            initial_trust=1.0,
            max_ttl_seconds=3600,
            scope=["read"],
            valid_seconds=120,
        )
        # Immediately after issuance trust should be ~initial.
        trust = compute_trust_at(vc, datetime.now(timezone.utc))
        assert 0.0 < trust <= 1.0
