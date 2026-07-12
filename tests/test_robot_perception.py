"""
Tests for robot perception provenance: the sensor-frame provenance log and the
PerceptionProvenanceCredential.
"""

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    PerceptionLog,
    build_perception_attestation,
    hash_frame,
    verify_perception_attestation,
    verify_perception_log,
)
from vouch.robotics.identity import RoboticsError

ROBOT = "did:web:robot.example.com"


@pytest.fixture
def robot():
    kp = generate_identity(domain="robot.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


# ---------------------------------------------------------------------------
# Frame hashing
# ---------------------------------------------------------------------------


class TestHashFrame:
    def test_deterministic_and_multibase(self):
        h1 = hash_frame(b"camera-frame-bytes")
        h2 = hash_frame(b"camera-frame-bytes")
        assert h1 == h2
        assert h1.startswith("u")

    def test_different_frames_differ(self):
        assert hash_frame(b"a") != hash_frame(b"b")

    def test_rejects_non_bytes(self):
        with pytest.raises(RoboticsError):
            hash_frame("not-bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Perception log (hash chain)
# ---------------------------------------------------------------------------


class TestPerceptionLog:
    def test_record_and_chain_verifies(self):
        log = PerceptionLog()
        log.record(sensor_id="cam-front", modality="camera", frame=b"frame-0")
        log.record(sensor_id="lidar-top", modality="lidar", frame=b"scan-0")
        entries = log.entries()
        assert len(entries) == 2
        assert entries[0]["seq"] == 0
        assert entries[0]["frameHash"] == hash_frame(b"frame-0")
        ok, reason = verify_perception_log(entries)
        assert ok is True and reason is None

    def test_record_with_precomputed_hash(self):
        log = PerceptionLog()
        fh = hash_frame(b"audio-0")
        entry = log.record(sensor_id="mic-1", modality="audio", frame_hash=fh)
        assert entry["frameHash"] == fh

    def test_tamper_breaks_chain(self):
        log = PerceptionLog()
        log.record(sensor_id="cam-front", modality="camera", frame=b"frame-0")
        log.record(sensor_id="cam-front", modality="camera", frame=b"frame-1")
        entries = log.entries()
        entries[0]["frameHash"] = hash_frame(b"substituted")
        ok, _ = verify_perception_log(entries)
        assert ok is False

    def test_rejects_bad_modality_and_missing_inputs(self):
        log = PerceptionLog()
        with pytest.raises(RoboticsError):
            log.record(sensor_id="x", modality="ultrasound", frame=b"f")  # not a known modality
        with pytest.raises(RoboticsError):
            log.record(sensor_id="x", modality="camera")  # neither frame nor hash
        with pytest.raises(RoboticsError):
            log.record(sensor_id="x", modality="camera", frame=b"f", frame_hash=hash_frame(b"f"))


# ---------------------------------------------------------------------------
# Perception attestation credential
# ---------------------------------------------------------------------------


class TestPerceptionAttestation:
    def test_build_and_verify(self, robot):
        kp, s = robot
        fh = hash_frame(b"frame-bytes")
        att = build_perception_attestation(
            s, robot_did=ROBOT, sensor_id="cam-front", modality="camera", frame_hash=fh
        )
        assert "PerceptionProvenanceCredential" in att["type"]
        ok, subject = verify_perception_attestation(att, kp.public_key_jwk)
        assert ok is True
        assert subject["sensorId"] == "cam-front"
        assert subject["frameHash"] == fh

    def test_verify_reproduces_frame_hash(self, robot):
        kp, s = robot
        frame = b"the-actual-frame"
        att = build_perception_attestation(
            s, robot_did=ROBOT, sensor_id="cam", modality="camera", frame_hash=hash_frame(frame)
        )
        ok, _ = verify_perception_attestation(att, kp.public_key_jwk, frame=frame)
        assert ok is True

    def test_wrong_frame_fails(self, robot):
        kp, s = robot
        att = build_perception_attestation(
            s, robot_did=ROBOT, sensor_id="cam", modality="camera", frame_hash=hash_frame(b"real")
        )
        ok, subject = verify_perception_attestation(att, kp.public_key_jwk, frame=b"fake")
        assert ok is False
        assert subject is None

    def test_tampered_credential_fails(self, robot):
        kp, s = robot
        att = build_perception_attestation(
            s, robot_did=ROBOT, sensor_id="cam", modality="camera", frame_hash=hash_frame(b"real")
        )
        att["credentialSubject"]["frameHash"] = hash_frame(b"swapped")
        ok, _ = verify_perception_attestation(att, kp.public_key_jwk)
        assert ok is False

    def test_wrong_key_fails(self, robot):
        _, s = robot
        other = generate_identity(domain="other.example.com")
        att = build_perception_attestation(
            s, robot_did=ROBOT, sensor_id="cam", modality="camera", frame_hash=hash_frame(b"real")
        )
        ok, _ = verify_perception_attestation(att, other.public_key_jwk)
        assert ok is False

    def test_anchors_log_head(self, robot):
        kp, s = robot
        log = PerceptionLog()
        log.record(sensor_id="cam", modality="camera", frame=b"f0")
        last = log.record(sensor_id="cam", modality="camera", frame=b"f1")
        att = build_perception_attestation(
            s,
            robot_did=ROBOT,
            sensor_id="cam",
            modality="camera",
            frame_hash=last["frameHash"],
            log_head=log.head(),
        )
        ok, subject = verify_perception_attestation(att, kp.public_key_jwk)
        assert ok is True
        assert subject["logHead"] == log.head()
