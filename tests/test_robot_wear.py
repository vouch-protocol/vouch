"""Tests for robot wear and degradation attestation."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    attenuate_for_wear,
    attenuates,
    build_wear_attestation,
    verify_wear_attestation,
    verify_wear_chain,
)
from vouch.robotics.identity import RoboticsError

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

SCOPE = {
    "maxForceN": 80.0,
    "maxSpeedMps": 1.5,
    "maxSpeedNearHumansMps": 0.25,
    "allowedZones": ["cell-3"],
    "shiftWindows": [{"start": "08:00", "end": "18:00"}],
}


def _robot():
    kp = generate_identity(domain="robot-a.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestWearAttestation(unittest.TestCase):
    def setUp(self):
        self.kp, self.robot = _robot()
        self.robot_did = self.kp.did

    def _attest(self, level=0.2, prev=None):
        return build_wear_attestation(
            self.robot,
            robot_did=self.robot_did,
            wear_level=level,
            metrics={"actuatorWear": level, "cycleCount": 120000},
            prev_proof=prev,
            attested_at=T0,
        )

    def test_verifies(self):
        ok, subject = verify_wear_attestation(self._attest(0.2), self.kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(subject["wearLevel"], 0.2)
        self.assertEqual(subject["metrics"]["cycleCount"], 120000)

    def test_wrong_key_rejected(self):
        other_kp, _ = _robot()
        ok, _ = verify_wear_attestation(self._attest(), other_kp.public_key_jwk)
        self.assertFalse(ok)

    def test_out_of_range_level_rejected(self):
        with self.assertRaises(RoboticsError):
            self._attest(1.5)

    def test_tampered_level_rejected(self):
        att = self._attest(0.2)
        att["credentialSubject"]["wearLevel"] = 0.9
        ok, _ = verify_wear_attestation(att, self.kp.public_key_jwk)
        self.assertFalse(ok)


class TestWearChain(unittest.TestCase):
    def test_chain_links_by_proof(self):
        kp, robot = _robot()
        did = kp.did
        a = build_wear_attestation(robot, robot_did=did, wear_level=0.1, attested_at=T0)
        b = build_wear_attestation(
            robot,
            robot_did=did,
            wear_level=0.3,
            prev_proof=a["proof"]["proofValue"],
            attested_at=T1,
        )
        ok, latest = verify_wear_chain([a, b], kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(latest["wearLevel"], 0.3)

    def test_broken_link_rejected(self):
        kp, robot = _robot()
        did = kp.did
        a = build_wear_attestation(robot, robot_did=did, wear_level=0.1, attested_at=T0)
        b = build_wear_attestation(
            robot,
            robot_did=did,
            wear_level=0.3,
            prev_proof="uWRONG",
            attested_at=T1,
        )
        ok, _ = verify_wear_chain([a, b], kp.public_key_jwk)
        self.assertFalse(ok)


class TestAutoAttenuation(unittest.TestCase):
    def test_narrows_caps_and_attenuates(self):
        # A wear level of 0.25 scales caps by 0.75, exact in binary floating point.
        narrowed = attenuate_for_wear(SCOPE, 0.25)
        self.assertEqual(narrowed["maxForceN"], 60.0)
        self.assertEqual(narrowed["maxSpeedMps"], 1.125)
        self.assertEqual(narrowed["maxSpeedNearHumansMps"], 0.1875)
        self.assertEqual(narrowed["allowedZones"], ["cell-3"])
        # The derived scope must be a valid attenuation of the original.
        self.assertTrue(attenuates(SCOPE, narrowed))

    def test_zero_wear_is_identity_on_caps(self):
        narrowed = attenuate_for_wear(SCOPE, 0.0)
        self.assertEqual(narrowed["maxForceN"], 80.0)
        self.assertTrue(attenuates(SCOPE, narrowed))

    def test_full_wear_still_attenuates(self):
        narrowed = attenuate_for_wear(SCOPE, 1.0)
        self.assertEqual(narrowed["maxForceN"], 0.0)
        self.assertTrue(attenuates(SCOPE, narrowed))


if __name__ == "__main__":
    unittest.main()
