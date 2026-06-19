"""
Tests for model/config provenance (5.2) and physical capability scope (5.3).
"""

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    PhysicalAction,
    attenuates,
    build_physical_scope_credential,
    build_provenance_attestation,
    check_physical_action,
    config_hash,
    verify_provenance_attestation,
)

ROBOT = "did:web:robot.example.com"


@pytest.fixture
def builder():
    kp = generate_identity(domain="builder.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestProvenance:
    def test_build_and_verify_with_config(self, builder):
        kp, s = builder
        config = {"temperature": 0.0, "max_torque": 12.5, "guardrails": ["no_humans_zone"]}
        att = build_provenance_attestation(
            s,
            robot_did=ROBOT,
            model_name="OpenVLA-7B",
            weights_hash="uWEIGHTS",
            safety_policy="uPOLICY",
            config=config,
            version="2.1.0",
        )
        assert "ModelProvenanceAttestation" in att["type"]
        ok, subject = verify_provenance_attestation(att, kp.public_key_jwk, config=config)
        assert ok is True
        assert subject["vla"]["modelName"] == "OpenVLA-7B"
        assert subject["vla"]["configHash"] == config_hash(config)

    def test_config_mismatch_fails(self, builder):
        kp, s = builder
        att = build_provenance_attestation(
            s,
            robot_did=ROBOT,
            model_name="m",
            weights_hash="uW",
            safety_policy="uP",
            config={"a": 1},
        )
        ok, _ = verify_provenance_attestation(att, kp.public_key_jwk, config={"a": 2})
        assert ok is False

    def test_ota_chain_supersedes(self, builder):
        kp, s = builder
        v1 = build_provenance_attestation(
            s, robot_did=ROBOT, model_name="m", weights_hash="uW1", safety_policy="uP"
        )
        v2 = build_provenance_attestation(
            s,
            robot_did=ROBOT,
            model_name="m",
            weights_hash="uW2",
            safety_policy="uP",
            supersedes=v1["id"] if "id" in v1 else "urn:prev",
        )
        ok, subject = verify_provenance_attestation(v2, kp.public_key_jwk)
        assert ok is True
        assert "supersedes" in subject


class TestPhysicalScope:
    SCOPE = {
        "maxForceN": 100.0,
        "maxSpeedMps": 2.0,
        "maxSpeedNearHumansMps": 0.5,
        "allowedZones": ["zone-A", "zone-B"],
        "shiftWindows": [{"start": "08:00", "end": "18:00"}],
    }

    def test_within_scope(self):
        a = PhysicalAction(force_n=50, speed_mps=1.5, zone="zone-A", time_hm="10:00")
        assert check_physical_action(self.SCOPE, a).ok is True

    def test_force_exceeded(self):
        r = check_physical_action(self.SCOPE, PhysicalAction(force_n=150))
        assert r.ok is False
        assert any("force_exceeded" in x for x in r.reasons)

    def test_near_humans_lower_speed_cap(self):
        # 1.5 m/s is fine normally but not near humans (cap 0.5).
        assert check_physical_action(self.SCOPE, PhysicalAction(speed_mps=1.5)).ok is True
        r = check_physical_action(self.SCOPE, PhysicalAction(speed_mps=1.5, near_humans=True))
        assert r.ok is False
        assert any("near_humans" in x for x in r.reasons)

    def test_zone_and_shift(self):
        assert check_physical_action(self.SCOPE, PhysicalAction(zone="zone-C")).ok is False
        assert check_physical_action(self.SCOPE, PhysicalAction(time_hm="22:00")).ok is False

    def test_credential_round_trip(self, builder):
        kp, s = builder
        cred = build_physical_scope_credential(
            s,
            subject_did=ROBOT,
            max_force_n=100,
            max_speed_mps=2.0,
            max_speed_near_humans_mps=0.5,
            allowed_zones=["zone-A"],
        )
        assert "PhysicalCapabilityScope" in cred["type"]
        scope = cred["credentialSubject"]["physicalScope"]
        assert check_physical_action(scope, PhysicalAction(force_n=50, zone="zone-A")).ok is True

    def test_attenuation(self):
        parent = {"maxForceN": 100, "maxSpeedMps": 2.0, "allowedZones": ["A", "B"]}
        good_child = {"maxForceN": 50, "maxSpeedMps": 1.0, "allowedZones": ["A"]}
        assert attenuates(parent, good_child) is True
        # Broader force is not a valid attenuation.
        assert (
            attenuates(parent, {"maxForceN": 200, "maxSpeedMps": 1.0, "allowedZones": ["A"]})
            is False
        )
        # Adding a zone the parent did not allow is broader.
        assert (
            attenuates(parent, {"maxForceN": 50, "maxSpeedMps": 1.0, "allowedZones": ["A", "C"]})
            is False
        )


class TestVector:
    def _vector(self):
        import json
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "test-vectors", "robotics", "vector.json"
        )
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_identity_credential_verifies(self):
        from vouch.robotics import verify_robot_identity

        v = self._vector()
        ok, subject = verify_robot_identity(
            v["robot_identity_credential"], v["robot_public_key_jwk"]
        )
        assert ok is True
        assert subject["hardwareRoot"]["kind"] == "TPM"

    def test_config_hash_reproduces(self):
        v = self._vector()
        assert config_hash(v["config"]) == v["expected_config_hash"]
