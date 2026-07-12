"""Tests for liveness-conformance-decaying recognition trust (PAD-073).

All times are passed explicitly; nothing here relies on the wall clock, so the
decay and revocation assertions are deterministic.
"""

from datetime import datetime, timedelta, timezone

import pytest

from vouch import generate_identity
from vouch.liveness_conformance import (
    CONFORMANCE_RECEIPT_TYPE,
    RESULT_FAIL,
    RESULT_PASS,
    LivenessError,
    build_conformance_receipt,
    consumable_trust,
    last_conformant,
    revocation_entry,
    should_revoke,
    verify_conformance_receipt,
)

HOLDER = "did:web:holder.example.com"
SURFACE = "https://holder.example.com/agent"
CRITERIA = "vouch-conformance-v1"

T0 = datetime(2026, 7, 3, 0, 0, 0, tzinfo=timezone.utc)


def _prober(domain: str = "prober.example.com"):
    kp = generate_identity(domain=domain)
    return kp


def _receipt(prober, result: str, observed_at: datetime, subject: str = HOLDER):
    return build_conformance_receipt(
        subject=subject,
        surface=SURFACE,
        criteria=CRITERIA,
        result=result,
        private_key=prober.private_key_jwk,
        did=prober.did,
        observed_at=observed_at,
    )


class TestReceipt:
    def test_build_and_verify_roundtrip(self):
        prober = _prober()
        receipt = _receipt(prober, RESULT_PASS, T0)

        assert CONFORMANCE_RECEIPT_TYPE in receipt["type"]
        assert receipt["issuer"] == prober.did
        subject = receipt["credentialSubject"]
        assert subject["id"] == HOLDER
        assert subject["surface"] == SURFACE
        assert subject["criteria"] == CRITERIA
        assert subject["result"] == RESULT_PASS
        assert subject["observedAt"] == "2026-07-03T00:00:00Z"

        ok, returned = verify_conformance_receipt(receipt, public_key=prober.public_key_jwk)
        assert ok is True
        assert returned["result"] == RESULT_PASS

    def test_wrong_key_fails(self):
        prober = _prober()
        other = _prober("other.example.com")
        receipt = _receipt(prober, RESULT_PASS, T0)
        ok, _ = verify_conformance_receipt(receipt, public_key=other.public_key_jwk)
        assert ok is False

    def test_tampered_result_fails_proof(self):
        prober = _prober()
        receipt = _receipt(prober, RESULT_PASS, T0)
        receipt["credentialSubject"]["result"] = RESULT_FAIL
        ok, _ = verify_conformance_receipt(receipt, public_key=prober.public_key_jwk)
        assert ok is False

    def test_invalid_result_rejected_at_build(self):
        prober = _prober()
        with pytest.raises(LivenessError):
            _receipt(prober, "maybe", T0)

    def test_missing_subject_rejected(self):
        prober = _prober()
        with pytest.raises(LivenessError):
            build_conformance_receipt(
                subject="",
                surface=SURFACE,
                criteria=CRITERIA,
                result=RESULT_PASS,
                private_key=prober.private_key_jwk,
                did=prober.did,
                observed_at=T0,
            )


class TestLastConformant:
    def test_latest_passing_observation(self):
        prober = _prober()
        receipts = [
            _receipt(prober, RESULT_PASS, T0),
            _receipt(prober, RESULT_PASS, T0 + timedelta(days=5)),
            _receipt(prober, RESULT_FAIL, T0 + timedelta(days=10)),
        ]
        assert last_conformant(receipts) == T0 + timedelta(days=5)

    def test_no_passing_receipt(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_FAIL, T0)]
        assert last_conformant(receipts) is None

    def test_empty_history(self):
        assert last_conformant([]) is None


class TestConsumableTrust:
    def test_zero_without_passing_receipt(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_FAIL, T0)]
        assert consumable_trust(receipts, at_time=T0) == 0.0

    def test_baseline_at_observation_time(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        assert consumable_trust(receipts, at_time=T0, baseline=100.0) == pytest.approx(100.0)

    def test_half_life_halves_trust(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        at = T0 + timedelta(days=30)
        assert consumable_trust(
            receipts, at_time=at, half_life_days=30.0, baseline=100.0
        ) == pytest.approx(50.0)

    def test_two_half_lives_quarters_trust(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        at = T0 + timedelta(days=60)
        assert consumable_trust(
            receipts, at_time=at, half_life_days=30.0, baseline=100.0
        ) == pytest.approx(25.0)

    def test_trust_strictly_decreases_as_time_advances(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        values = [
            consumable_trust(receipts, at_time=T0 + timedelta(days=d)) for d in (1, 10, 30, 60, 120)
        ]
        for earlier, later in zip(values, values[1:]):
            assert later < earlier

    def test_fresh_passing_receipt_raises_trust(self):
        prober = _prober()
        stale = [_receipt(prober, RESULT_PASS, T0)]
        at = T0 + timedelta(days=45)
        low = consumable_trust(stale, at_time=at)

        refreshed = stale + [_receipt(prober, RESULT_PASS, T0 + timedelta(days=44))]
        high = consumable_trust(refreshed, at_time=at)
        assert high > low

    def test_pre_observation_time_clamps_to_baseline(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        assert consumable_trust(
            receipts, at_time=T0 - timedelta(days=1), baseline=100.0
        ) == pytest.approx(100.0)

    def test_invalid_half_life_rejected(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        with pytest.raises(LivenessError):
            consumable_trust(receipts, at_time=T0, half_life_days=0.0)


class TestShouldRevoke:
    def test_false_right_after_a_pass(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        assert should_revoke(receipts, at_time=T0, lapse_threshold_days=7.0) is False

    def test_false_within_threshold(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        at = T0 + timedelta(days=5)
        assert should_revoke(receipts, at_time=at, lapse_threshold_days=7.0) is False

    def test_true_after_lapse_elapses(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        at = T0 + timedelta(days=10)
        assert should_revoke(receipts, at_time=at, lapse_threshold_days=7.0) is True

    def test_true_when_latest_is_a_fail(self):
        prober = _prober()
        receipts = [
            _receipt(prober, RESULT_PASS, T0),
            _receipt(prober, RESULT_FAIL, T0 + timedelta(days=1)),
        ]
        # Well within the lapse window, but the newest observation is a fail.
        assert should_revoke(receipts, at_time=T0 + timedelta(days=1), lapse_threshold_days=7.0)

    def test_true_when_no_passing_receipt(self):
        assert should_revoke([], at_time=T0, lapse_threshold_days=7.0) is True

    def test_negative_threshold_rejected(self):
        prober = _prober()
        receipts = [_receipt(prober, RESULT_PASS, T0)]
        with pytest.raises(LivenessError):
            should_revoke(receipts, at_time=T0, lapse_threshold_days=-1.0)


class TestRevocationEntry:
    def test_entry_shape(self):
        entry = revocation_entry(
            status_list_credential="https://issuer.example/status/1",
            status_list_index=42,
        )
        assert entry["type"] == "BitstringStatusListEntry"
        assert entry["statusPurpose"] == "revocation"
        assert entry["statusListIndex"] == "42"
        assert entry["statusListCredential"] == "https://issuer.example/status/1"
        assert entry["id"] == "https://issuer.example/status/1#42"

    def test_custom_entry_id(self):
        entry = revocation_entry(
            status_list_credential="https://issuer.example/status/1",
            status_list_index=7,
            entry_id="urn:entry:7",
        )
        assert entry["id"] == "urn:entry:7"
