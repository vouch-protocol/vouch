"""
Tests for the robot accountable safety record: the incident/near-miss ledger and
the portable RobotSafetyRecordCredential.
"""

from datetime import datetime, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    SafetyEventLog,
    build_safety_record,
    summarize_entries,
    validate_safety_summary,
    verify_safety_log,
    verify_safety_record,
)
from vouch.robotics.identity import RoboticsError

ROBOT = "did:web:robot.example.com"


@pytest.fixture
def authority():
    kp = generate_identity(domain="fleet-auditor.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class TestSafetyEventLog:
    def test_append_and_chain_verifies(self):
        log = SafetyEventLog()
        log.append("near_miss", severity="low", details={"zone": "cell-3"})
        log.append("envelope_breach", severity="high", details={"maxForceN": 140})
        log.append("manual_override", severity="medium", actor="did:web:operator.example.com")
        entries = log.entries()
        assert len(entries) == 3
        assert entries[0]["seq"] == 0 and entries[2]["seq"] == 2
        ok, reason = verify_safety_log(entries)
        assert ok is True and reason is None

    def test_tamper_breaks_chain(self):
        log = SafetyEventLog()
        log.append("incident", severity="critical")
        log.append("near_miss", severity="low")
        entries = log.entries()
        entries[0]["severity"] = "info"  # alter a recorded event
        ok, reason = verify_safety_log(entries)
        assert ok is False
        assert "tampered" in reason or "link" in reason

    def test_removing_an_entry_breaks_chain(self):
        log = SafetyEventLog()
        log.append("incident", severity="high")
        log.append("near_miss", severity="low")
        log.append("maintenance", severity="info")
        entries = log.entries()
        del entries[1]  # drop the middle event
        ok, _ = verify_safety_log(entries)
        assert ok is False

    def test_rejects_unknown_event_type_and_severity(self):
        log = SafetyEventLog()
        with pytest.raises(RoboticsError):
            log.append("explosion")  # not a known type
        with pytest.raises(RoboticsError):
            log.append("incident", severity="catastrophic")  # not a known severity


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_counts_by_type_and_severity(self):
        log = SafetyEventLog()
        log.append("near_miss", severity="low")
        log.append("near_miss", severity="medium")
        log.append("envelope_breach", severity="high")
        summary = log.summarize()
        assert summary["totalEvents"] == 3
        assert summary["eventCounts"]["near_miss"] == 2
        assert summary["eventCounts"]["envelope_breach"] == 1
        assert summary["eventCounts"]["incident"] == 0
        assert summary["severityCounts"]["low"] == 1
        assert summary["severityCounts"]["high"] == 1
        assert summary["logHead"] == log.head()

    def test_summarize_entries_without_head(self):
        log = SafetyEventLog()
        log.append("incident", severity="critical")
        summary = summarize_entries(log.entries())
        assert summary["totalEvents"] == 1
        assert "logHead" not in summary


# ---------------------------------------------------------------------------
# Portable safety record credential
# ---------------------------------------------------------------------------


class TestSafetyRecord:
    def test_build_and_verify(self, authority):
        kp, s = authority
        log = SafetyEventLog()
        log.append("near_miss", severity="low")
        log.append("envelope_breach", severity="high")
        rec = build_safety_record(
            s,
            robot_did=ROBOT,
            summary=log.summarize(),
            period_start=datetime(2026, 6, 1, tzinfo=timezone.utc),
            period_end=datetime(2026, 6, 30, tzinfo=timezone.utc),
        )
        assert "RobotSafetyRecordCredential" in rec["type"]
        ok, subject = verify_safety_record(rec, kp.public_key_jwk)
        assert ok is True
        assert subject["id"] == ROBOT
        assert subject["totalEvents"] == 2
        assert subject["period"]["start"] == "2026-06-01T00:00:00Z"
        assert subject["logHead"] == log.head()

    def test_tampered_counts_fail_verification(self, authority):
        kp, s = authority
        log = SafetyEventLog()
        log.append("incident", severity="critical")
        rec = build_safety_record(s, robot_did=ROBOT, summary=log.summarize())
        rec["credentialSubject"]["severityCounts"]["critical"] = 0  # hide the incident
        ok, subject = verify_safety_record(rec, kp.public_key_jwk)
        assert ok is False
        assert subject is None

    def test_wrong_key_fails(self, authority):
        _, s = authority
        other = generate_identity(domain="other.example.com")
        log = SafetyEventLog()
        log.append("near_miss", severity="low")
        rec = build_safety_record(s, robot_did=ROBOT, summary=log.summarize())
        ok, _ = verify_safety_record(rec, other.public_key_jwk)
        assert ok is False


class TestValidateSummary:
    def test_accepts_well_formed(self):
        validate_safety_summary(SafetyEventLog().summarize())

    def test_rejects_negative_and_bool_counts(self):
        s = SafetyEventLog().summarize()
        s["eventCounts"]["incident"] = -1
        with pytest.raises(RoboticsError):
            validate_safety_summary(s)
        s2 = SafetyEventLog().summarize()
        s2["totalEvents"] = True
        with pytest.raises(RoboticsError):
            validate_safety_summary(s2)
