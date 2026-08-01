"""Tests for event-triggered intent recheck (seal freshness bound to the action)."""

from datetime import datetime, timedelta, timezone

from vouch import Signer, generate_identity
from vouch.intent_recheck import (
    REASON_INTENT_SEAL_EXPIRED,
    REASON_INTENT_SEAL_MISSING,
    REASON_INTENT_SEAL_STALE,
    TIER_CRITICAL,
    TIER_HIGH,
    TIER_ROUTINE,
    default_requirement,
    pulse_window,
    reseal_intent,
    seal_timestamp,
    verify_intent_freshness,
)
from vouch.reasoning import (
    build_justification,
    check_reasoned_action,
    evidence_anchor,
    sign_reasoned_action,
)


def _identity(domain: str = "agent.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


USER_MSG = {"from": "did:web:alice.example", "text": "move $500 to savings"}
INTENT = {"action": "transfer_funds", "target": "account:9911", "resource": "/v1/xfer"}

PULSE = datetime(2026, 8, 2, 10, 0, 0, tzinfo=timezone.utc)  # last heartbeat boundary
INTERVAL = 60


def _anchor():
    return evidence_anchor("user asked", ref="msg:1", evidence=USER_MSG, anchor_type="user_message")


def _justification(level=TIER_HIGH):
    return build_justification(INTENT, [_anchor()], commitment_level=level)


def _sealed_action(signer, sealed_at, exec_at, level=TIER_HIGH):
    return sign_reasoned_action(
        signer,
        intent=INTENT,
        justification=_justification(level),
        valid_from=exec_at,
        sealed_at=sealed_at,
    )


class TestPulseWindow:
    def test_inside_window(self):
        w = pulse_window(PULSE, INTERVAL, PULSE + timedelta(seconds=30))
        assert w.in_window and not w.in_gap

    def test_in_gap_past_boundary(self):
        w = pulse_window(PULSE, INTERVAL, PULSE + timedelta(seconds=120))
        assert w.in_gap and not w.in_window


class TestIntentFreshnessMatrix:
    def test_fresh_seal_in_window_accepts(self):
        kp, signer = _identity()
        cred = _sealed_action(
            signer, PULSE + timedelta(seconds=10), PULSE + timedelta(seconds=20), TIER_HIGH
        )
        assert verify_intent_freshness(cred, TIER_HIGH, "2026-08-02T10:00:00Z") is None
        # signature and commitment still verify independently
        assert check_reasoned_action(cred, kp.public_key_jwk) is None

    def test_stale_seal_in_gap_rejects(self):
        # attacker times the action: sealed before the pulse, executed after it
        _, signer = _identity()
        cred = _sealed_action(
            signer, PULSE - timedelta(seconds=10), PULSE + timedelta(seconds=20), TIER_HIGH
        )
        reason = verify_intent_freshness(cred, TIER_HIGH, "2026-08-02T10:00:00Z")
        assert reason == (
            "intent_seal_stale:sealed_at=2026-08-02T09:59:50Z,last_pulse=2026-08-02T10:00:00Z"
        )
        assert reason.startswith(REASON_INTENT_SEAL_STALE)

    def test_fresh_reseal_in_gap_accepts(self):
        # executed deep in a later interval, but resealed at that moment
        kp, signer = _identity()
        now = datetime(2026, 8, 2, 10, 5, 0, tzinfo=timezone.utc)
        cred = reseal_intent(
            signer, intent=INTENT, anchors=[_anchor()], commitment_level=TIER_HIGH, now=now
        )
        # last pulse advanced to 10:05:00
        assert verify_intent_freshness(cred, TIER_HIGH, "2026-08-02T10:05:00Z") is None
        assert check_reasoned_action(cred, kp.public_key_jwk) is None
        assert seal_timestamp(cred) == "2026-08-02T10:05:00Z"

    def test_non_sensitive_tier_ignores_stale_seal(self):
        _, signer = _identity()
        cred = _sealed_action(
            signer, PULSE - timedelta(seconds=10), PULSE + timedelta(seconds=20), TIER_ROUTINE
        )
        assert verify_intent_freshness(cred, TIER_ROUTINE, "2026-08-02T10:00:00Z") is None

    def test_sensitive_tier_without_seal_is_missing(self):
        _, signer = _identity()
        cred = sign_reasoned_action(
            signer,
            intent=INTENT,
            justification=_justification(TIER_HIGH),
            valid_from=PULSE + timedelta(seconds=20),
        )
        reason = verify_intent_freshness(cred, TIER_HIGH, "2026-08-02T10:00:00Z")
        assert reason == f"{REASON_INTENT_SEAL_MISSING}:tier=3"

    def test_expired_within_window_rejects(self):
        # critical tier, 60s max age; sealed within the window but too old
        _, signer = _identity()
        pulse = datetime(2026, 8, 2, 10, 0, 0, tzinfo=timezone.utc)
        cred = _sealed_action(
            signer, pulse + timedelta(seconds=5), pulse + timedelta(seconds=90), TIER_CRITICAL
        )
        reason = verify_intent_freshness(cred, TIER_CRITICAL, "2026-08-02T10:00:00Z")
        assert reason is not None and reason.startswith(REASON_INTENT_SEAL_EXPIRED)


class TestAdversarialTiming:
    def test_action_timed_mid_interval_still_hits_the_seal(self):
        # A sophisticated actor seals a benign-looking intent at the start of an
        # interval, then waits and fires the sensitive action after the boundary,
        # hoping the heartbeat gap hides it. The recheck still rejects it.
        _, signer = _identity()
        for offset in range(65, 600, 45):  # sweep several gap positions
            sealed = PULSE - timedelta(seconds=5)
            exec_at = PULSE + timedelta(seconds=offset)
            # the last pulse boundary the attacker's clock has crossed by exec_at
            crossed = PULSE + timedelta(seconds=(offset // INTERVAL) * INTERVAL)
            cred = _sealed_action(signer, sealed, exec_at, TIER_HIGH)
            reason = verify_intent_freshness(
                cred, TIER_HIGH, crossed.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            assert reason is not None and reason.startswith(REASON_INTENT_SEAL_STALE)

    def test_policy_default_bands(self):
        assert not default_requirement(TIER_ROUTINE).require_fresh_seal
        assert default_requirement(TIER_HIGH).require_fresh_seal
        assert default_requirement(TIER_HIGH).max_age_seconds == 300
        assert default_requirement(TIER_CRITICAL).max_age_seconds == 60
