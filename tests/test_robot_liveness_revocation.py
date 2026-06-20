"""
Tests for robot liveness heartbeat with safety-envelope conformance and trust
decay (liveness) and for robot credential revocation (revocation).
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    MotionCollector,
    RevocationRegistry,
    attach_credential_status,
    build_physical_scope_credential,
    build_robot_heartbeat,
    build_status_list_credential,
    check_credential_status,
    is_live,
    validate_motion_digest,
    verify_robot_heartbeat,
)
from vouch.robotics.identity import RoboticsError
from vouch.status_list import StatusList

ROBOT = "did:web:robot.example.com"


@pytest.fixture
def robot():
    kp = generate_identity(domain="robot.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


@pytest.fixture
def authority():
    kp = generate_identity(domain="authority.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _scope():
    return {
        "maxForceN": 80.0,
        "maxSpeedMps": 1.5,
        "maxSpeedNearHumansMps": 0.25,
        "allowedZones": ["cell-3", "cell-4"],
    }


# ---------------------------------------------------------------------------
# Motion collector + digest
# ---------------------------------------------------------------------------


class TestMotionCollector:
    def test_in_envelope_digest(self):
        c = MotionCollector(scope=_scope())
        c.record(force_n=12.0, speed_mps=0.4, near_humans=False, zone="cell-3")
        c.record(force_n=20.0, speed_mps=0.2, near_humans=True, zone="cell-4")
        d = c.digest()
        assert d["samples"] == 2
        assert d["maxForceN"] == 20.0
        assert d["maxSpeedMps"] == 0.4
        assert d["maxSpeedNearHumansMps"] == 0.2
        assert d["breachCount"] == 0
        assert d["zoneBreaches"] == 0
        assert d["withinEnvelope"] is True

    def test_force_and_speed_breaches_counted(self):
        c = MotionCollector(scope=_scope())
        c.record(force_n=120.0, speed_mps=0.4, zone="cell-3")  # force over cap
        c.record(force_n=10.0, speed_mps=2.0, zone="cell-3")  # speed over cap
        c.record(force_n=10.0, speed_mps=0.5, near_humans=True, zone="cell-3")  # near-human speed
        d = c.digest()
        assert d["breachCount"] == 3
        assert d["withinEnvelope"] is False
        assert d["maxForceN"] == 120.0

    def test_zone_breach_counted_separately(self):
        c = MotionCollector(scope=_scope())
        c.record(force_n=10.0, speed_mps=0.4, zone="cell-9")  # not allowed
        d = c.digest()
        assert d["breachCount"] == 1
        assert d["zoneBreaches"] == 1
        assert d["withinEnvelope"] is False

    def test_without_scope_reports_maxima_but_no_judgement(self):
        c = MotionCollector()  # no scope
        c.record(force_n=999.0, speed_mps=9.0)
        d = c.digest()
        assert d["maxForceN"] == 999.0
        assert d["maxSpeedMps"] == 9.0
        assert d["breachCount"] == 0
        assert d["withinEnvelope"] is True

    def test_reset_clears(self):
        c = MotionCollector(scope=_scope())
        c.record(force_n=120.0, speed_mps=0.4, zone="cell-3")
        c.reset()
        d = c.digest()
        assert d == {
            "samples": 0,
            "maxForceN": 0.0,
            "maxSpeedMps": 0.0,
            "maxSpeedNearHumansMps": 0.0,
            "zoneBreaches": 0,
            "breachCount": 0,
            "withinEnvelope": True,
        }

    def test_negative_inputs_rejected(self):
        c = MotionCollector()
        with pytest.raises(RoboticsError):
            c.record(force_n=-1.0)
        with pytest.raises(RoboticsError):
            c.record(speed_mps=-0.1)


class TestValidateMotionDigest:
    def test_accepts_well_formed(self):
        validate_motion_digest(MotionCollector().digest())

    def test_rejects_missing_field(self):
        d = MotionCollector().digest()
        del d["withinEnvelope"]
        with pytest.raises(RoboticsError):
            validate_motion_digest(d)

    def test_rejects_bad_types(self):
        d = MotionCollector().digest()
        d["withinEnvelope"] = "yes"
        with pytest.raises(RoboticsError):
            validate_motion_digest(d)
        d2 = MotionCollector().digest()
        d2["breachCount"] = True  # bool is not a valid count
        with pytest.raises(RoboticsError):
            validate_motion_digest(d2)


# ---------------------------------------------------------------------------
# Heartbeat build / verify
# ---------------------------------------------------------------------------


class TestHeartbeat:
    def test_build_and_verify(self, robot):
        kp, s = robot
        c = MotionCollector(scope=_scope())
        c.record(force_n=12.0, speed_mps=0.4, zone="cell-3")
        hb = build_robot_heartbeat(
            s,
            session_id="urn:uuid:sess-1",
            interval_index=0,
            motion_digest=c.digest(),
            interval_seconds=30,
        )
        assert "RobotHeartbeatCredential" in hb["type"]
        ok, subject = verify_robot_heartbeat(hb, kp.public_key_jwk)
        assert ok is True
        assert subject["sessionId"] == "urn:uuid:sess-1"
        assert subject["intervalSeconds"] == 30

    def test_tampered_digest_fails_verification(self, robot):
        kp, s = robot
        hb = build_robot_heartbeat(
            s,
            session_id="s",
            interval_index=1,
            motion_digest=MotionCollector().digest(),
            interval_seconds=30,
        )
        hb["credentialSubject"]["motionDigest"]["maxForceN"] = 1.0
        ok, subject = verify_robot_heartbeat(hb, kp.public_key_jwk)
        assert ok is False
        assert subject is None

    def test_wrong_key_fails(self, robot):
        _, s = robot
        other = generate_identity(domain="other.example.com")
        hb = build_robot_heartbeat(
            s,
            session_id="s",
            interval_index=0,
            motion_digest=MotionCollector().digest(),
            interval_seconds=30,
        )
        ok, _ = verify_robot_heartbeat(hb, other.public_key_jwk)
        assert ok is False

    def test_build_rejects_bad_inputs(self, robot):
        _, s = robot
        good = MotionCollector().digest()
        with pytest.raises(RoboticsError):
            build_robot_heartbeat(
                s, session_id="s", interval_index=-1, motion_digest=good, interval_seconds=30
            )
        with pytest.raises(RoboticsError):
            build_robot_heartbeat(
                s, session_id="s", interval_index=0, motion_digest=good, interval_seconds=0
            )


# ---------------------------------------------------------------------------
# Trust decay (is_live)
# ---------------------------------------------------------------------------


class TestIsLive:
    def _hb(self, signer, *, issued_at, digest=None, interval_seconds=30):
        return build_robot_heartbeat(
            signer,
            session_id="s",
            interval_index=0,
            motion_digest=digest or MotionCollector(scope=_scope()).digest(),
            interval_seconds=interval_seconds,
            issued_at=issued_at,
        )

    def test_fresh_and_conformant_is_live(self, robot):
        _, s = robot
        now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
        hb = self._hb(s, issued_at=now)
        assert is_live(hb, now=now + timedelta(seconds=10)) is True

    def test_stale_is_not_live(self, robot):
        _, s = robot
        now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
        hb = self._hb(s, issued_at=now, interval_seconds=30)
        # 30s cadence, 2 grace intervals = 60s tolerance; 120s later is stale.
        assert is_live(hb, now=now + timedelta(seconds=120)) is False

    def test_breach_is_never_live_even_if_fresh(self, robot):
        _, s = robot
        now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
        c = MotionCollector(scope=_scope())
        c.record(force_n=999.0, speed_mps=0.1, zone="cell-3")  # force breach
        hb = self._hb(s, issued_at=now, digest=c.digest())
        assert is_live(hb, now=now + timedelta(seconds=1)) is False

    def test_future_heartbeat_rejected(self, robot):
        _, s = robot
        now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
        hb = self._hb(s, issued_at=now + timedelta(hours=1))
        assert is_live(hb, now=now, interval_seconds=30) is False

    def test_grace_intervals_extends_tolerance(self, robot):
        _, s = robot
        now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
        hb = self._hb(s, issued_at=now, interval_seconds=30)
        # 100s later: stale at 2 grace intervals, live at 4.
        assert is_live(hb, now=now + timedelta(seconds=100), grace_intervals=2) is False
        assert is_live(hb, now=now + timedelta(seconds=100), grace_intervals=4) is True


# ---------------------------------------------------------------------------
# Revocation: surgical per-credential status
# ---------------------------------------------------------------------------


class TestCredentialStatus:
    LIST_URL = "https://authority.example.com/status/robots/1"

    def _status_list_cred(self, issuer_did, *, set_index=None):
        sl = StatusList(status_list_id=self.LIST_URL)
        if set_index is not None:
            sl.set_status(set_index, True)
        return build_status_list_credential(issuer_did=issuer_did, status_list=sl)

    def test_attach_status_resigns_and_verifies(self, robot, authority):
        kp, s = robot
        scope_cred = build_physical_scope_credential(s, subject_did=ROBOT, max_force_n=80.0)
        with_status = attach_credential_status(
            scope_cred,
            s,
            status_list_credential=self.LIST_URL,
            status_list_index=42,
        )
        assert with_status["credentialSubject"]["id"] == ROBOT
        cs = with_status["credentialStatus"]
        assert cs["statusListIndex"] == "42"
        # Proof still verifies after re-signing over the added status.
        from vouch import data_integrity
        from vouch.verifier import _coerce_ed25519_public_key

        assert data_integrity.verify_proof(
            with_status, _coerce_ed25519_public_key(kp.public_key_jwk)
        )

    def test_not_revoked_when_bit_unset(self, robot, authority):
        _, s = robot
        akp, a = authority
        cred = build_physical_scope_credential(s, subject_did=ROBOT, max_force_n=80.0)
        cred = attach_credential_status(
            cred, s, status_list_credential=self.LIST_URL, status_list_index=42
        )
        sl_cred = self._status_list_cred(a.get_did(), set_index=None)
        assert check_credential_status(cred, sl_cred) is False

    def test_revoked_when_bit_set(self, robot, authority):
        _, s = robot
        akp, a = authority
        cred = build_physical_scope_credential(s, subject_did=ROBOT, max_force_n=80.0)
        cred = attach_credential_status(
            cred, s, status_list_credential=self.LIST_URL, status_list_index=42
        )
        sl_cred = self._status_list_cred(a.get_did(), set_index=42)
        assert check_credential_status(cred, sl_cred) is True

    def test_no_status_entry_reads_as_not_revoked(self, robot, authority):
        _, s = robot
        _, a = authority
        cred = build_physical_scope_credential(s, subject_did=ROBOT, max_force_n=80.0)
        sl_cred = self._status_list_cred(a.get_did(), set_index=42)
        assert check_credential_status(cred, sl_cred) is False

    def test_multiple_status_entries_appended(self, robot):
        _, s = robot
        cred = build_physical_scope_credential(s, subject_did=ROBOT, max_force_n=80.0)
        cred = attach_credential_status(
            cred, s, status_list_credential=self.LIST_URL, status_list_index=1
        )
        cred = attach_credential_status(
            cred,
            s,
            status_list_credential=self.LIST_URL,
            status_list_index=2,
            status_purpose="suspension",
        )
        assert isinstance(cred["credentialStatus"], list)
        assert len(cred["credentialStatus"]) == 2


# ---------------------------------------------------------------------------
# Revocation: whole-DID kill via the existing registry
# ---------------------------------------------------------------------------


class TestDidLevelRevocation:
    def test_robot_did_revokes_and_checks(self):
        async def run():
            registry = RevocationRegistry(check_remote=False)
            assert await registry.is_revoked(ROBOT) is False
            await registry.revoke(ROBOT, reason="hardware captured", revoked_by="did:web:fleet.op")
            assert await registry.is_revoked(ROBOT) is True

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run())
        finally:
            loop.close()
            # Leave a usable current event loop behind. On Python 3.9, asyncio.run
            # (and a bare close) would set the current loop to None, after which a
            # later test calling the deprecated asyncio.get_event_loop() raises.
            asyncio.set_event_loop(asyncio.new_event_loop())
