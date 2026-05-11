"""
Unit tests for Behavioral Attestation digest builder (W3C CG Report §11.3).
"""

import pytest

from vouch.behavioral_attestation import (
    BehavioralAttestationError,
    BehavioralCollector,
    DEFAULT_MAX_RESOURCES,
    ewma_drift_scorer,
    max_drift_scorer,
    mean_drift_scorer,
    validate_behavioral_digest,
)


class TestDefaultCollector:
    def test_empty_collector_digest(self):
        c = BehavioralCollector()
        d = c.digest()
        assert d == {
            "apiCalls": 0,
            "tokensConsumed": 0,
            "resourcesAccessed": [],
            "intentDriftScore": 0.0,
        }

    def test_record_api_call_increments_counter(self):
        c = BehavioralCollector()
        c.record_api_call("https://api.example.com/orders", tokens=100)
        c.record_api_call("https://api.example.com/users", tokens=50)
        d = c.digest()
        assert d["apiCalls"] == 2
        assert d["tokensConsumed"] == 150

    def test_resource_access_dedup(self):
        c = BehavioralCollector()
        c.record_resource_access("order:1")
        c.record_resource_access("order:1")
        c.record_resource_access("order:2")
        d = c.digest()
        assert sorted(d["resourcesAccessed"]) == ["order:1", "order:2"]

    def test_record_api_call_with_resource(self):
        c = BehavioralCollector()
        c.record_api_call("https://api.example.com/orders/42", resource="order:42", tokens=10)
        d = c.digest()
        assert d["resourcesAccessed"] == ["order:42"]
        assert d["apiCalls"] == 1

    def test_reset_clears_state(self):
        c = BehavioralCollector()
        c.record_api_call("/x", tokens=5)
        c.record_resource_access("r:1")
        c.record_drift_sample(0.7)
        c.reset()
        d = c.digest()
        assert d == {
            "apiCalls": 0,
            "tokensConsumed": 0,
            "resourcesAccessed": [],
            "intentDriftScore": 0.0,
        }


class TestDriftScoring:
    def test_mean_default(self):
        c = BehavioralCollector()
        c.record_drift_sample(0.2)
        c.record_drift_sample(0.4)
        c.record_drift_sample(0.6)
        d = c.digest()
        assert d["intentDriftScore"] == pytest.approx(0.4)

    def test_max_scorer(self):
        c = BehavioralCollector(intent_drift_scorer=max_drift_scorer)
        c.record_drift_sample(0.2)
        c.record_drift_sample(0.9)
        c.record_drift_sample(0.4)
        d = c.digest()
        assert d["intentDriftScore"] == pytest.approx(0.9)

    def test_ewma_scorer_weights_recent_samples(self):
        c = BehavioralCollector(intent_drift_scorer=ewma_drift_scorer(alpha=0.5))
        c.record_drift_sample(0.0)
        c.record_drift_sample(0.0)
        c.record_drift_sample(1.0)  # spike at the end
        d = c.digest()
        # EWMA with alpha=0.5: 0 -> 0 -> 0.5
        assert d["intentDriftScore"] == pytest.approx(0.5, abs=1e-9)

    def test_drift_out_of_range_rejected(self):
        c = BehavioralCollector()
        with pytest.raises(BehavioralAttestationError):
            c.record_drift_sample(1.5)
        with pytest.raises(BehavioralAttestationError):
            c.record_drift_sample(-0.1)

    def test_scorer_clamped_to_unit_range(self):
        def bad_scorer(samples):
            return 1.5  # over the cap

        c = BehavioralCollector(intent_drift_scorer=bad_scorer)
        c.record_drift_sample(0.5)
        d = c.digest()
        # The collector clamps misbehaving scorers into [0, 1].
        assert d["intentDriftScore"] == 1.0


class TestResourceCap:
    def test_resources_capped_at_max(self):
        c = BehavioralCollector(max_resources=4)
        for i in range(10):
            c.record_resource_access(f"r:{i}")
        d = c.digest()
        assert len(d["resourcesAccessed"]) == 4
        # The cap preserves the FIRST distinct resources seen, not last.
        assert d["resourcesAccessed"] == ["r:0", "r:1", "r:2", "r:3"]

    def test_default_cap(self):
        c = BehavioralCollector()
        for i in range(DEFAULT_MAX_RESOURCES + 10):
            c.record_resource_access(f"r:{i}")
        d = c.digest()
        assert len(d["resourcesAccessed"]) == DEFAULT_MAX_RESOURCES


class TestValidation:
    def test_validate_accepts_well_formed_digest(self):
        validate_behavioral_digest({
            "apiCalls": 10,
            "tokensConsumed": 500,
            "resourcesAccessed": ["r:1"],
            "intentDriftScore": 0.2,
        })  # should not raise

    def test_validate_rejects_missing_field(self):
        with pytest.raises(BehavioralAttestationError):
            validate_behavioral_digest({
                "apiCalls": 10,
                "tokensConsumed": 500,
                # resourcesAccessed missing
                "intentDriftScore": 0.2,
            })

    def test_validate_rejects_negative_counter(self):
        with pytest.raises(BehavioralAttestationError):
            validate_behavioral_digest({
                "apiCalls": -1,
                "tokensConsumed": 0,
                "resourcesAccessed": [],
                "intentDriftScore": 0.0,
            })

    def test_validate_rejects_drift_out_of_range(self):
        with pytest.raises(BehavioralAttestationError):
            validate_behavioral_digest({
                "apiCalls": 0,
                "tokensConsumed": 0,
                "resourcesAccessed": [],
                "intentDriftScore": 1.5,
            })

    def test_validate_rejects_non_string_resource(self):
        with pytest.raises(BehavioralAttestationError):
            validate_behavioral_digest({
                "apiCalls": 0,
                "tokensConsumed": 0,
                "resourcesAccessed": ["r:1", 42],
                "intentDriftScore": 0.0,
            })


class TestSampleSnapshot:
    def test_snapshot_returns_samples(self):
        c = BehavioralCollector()
        c.record_api_call("/x", tokens=10, resource="r:1", drift=0.1)
        c.record_api_call("/y", tokens=20, drift=0.3)
        samples = c.snapshot_samples()
        assert len(samples) == 2
        assert samples[0].api_call == "/x"
        assert samples[0].tokens == 10
        assert samples[0].resource == "r:1"
        assert samples[1].api_call == "/y"


class TestScorerHelpers:
    def test_mean_drift_scorer_empty(self):
        assert mean_drift_scorer([]) == 0.0

    def test_max_drift_scorer_empty(self):
        assert max_drift_scorer([]) == 0.0

    def test_ewma_scorer_invalid_alpha(self):
        with pytest.raises(BehavioralAttestationError):
            ewma_drift_scorer(alpha=0.0)
        with pytest.raises(BehavioralAttestationError):
            ewma_drift_scorer(alpha=1.5)
