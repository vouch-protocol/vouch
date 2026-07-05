"""Tests for fused-sensor provenance."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    PerceptionLog,
    build_fused_attestation,
    fusion_inputs_digest,
    hash_frame,
    hash_fused_output,
    verify_fused_attestation,
    verify_fusion_inputs,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _robot():
    kp = generate_identity(domain="robot-a.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestFusedAttestation(unittest.TestCase):
    def setUp(self):
        self.kp, self.robot = _robot()
        self.robot_did = self.kp.did
        self.frames = [b"cam-front-0", b"lidar-top-0", b"radar-0"]
        self.input_hashes = [hash_frame(f) for f in self.frames]
        self.fused_output = b"world-model-0"

    def _attest(self):
        return build_fused_attestation(
            self.robot,
            robot_did=self.robot_did,
            fusion_method="occupancy-grid-v1",
            input_frame_hashes=self.input_hashes,
            fused_output=self.fused_output,
            captured_at=T0,
        )

    def test_verifies_and_carries_inputs(self):
        ok, subject = verify_fused_attestation(self._attest(), self.kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(subject["fusionMethod"], "occupancy-grid-v1")
        self.assertEqual(subject["inputFrameHashes"], self.input_hashes)
        self.assertEqual(subject["fusedOutputHash"], hash_fused_output(self.fused_output))

    def test_verifies_with_raw_output(self):
        ok, _ = verify_fused_attestation(
            self._attest(), self.kp.public_key_jwk, fused_output=self.fused_output
        )
        self.assertTrue(ok)

    def test_wrong_raw_output_rejected(self):
        ok, _ = verify_fused_attestation(
            self._attest(), self.kp.public_key_jwk, fused_output=b"tampered-world-model"
        )
        self.assertFalse(ok)

    def test_wrong_key_rejected(self):
        other_kp, _ = _robot()
        ok, _ = verify_fused_attestation(self._attest(), other_kp.public_key_jwk)
        self.assertFalse(ok)

    def test_tampered_inputs_break_digest(self):
        att = self._attest()
        # Swap an input frame hash without re-signing: the reproduced digest no
        # longer matches the attested inputsDigest.
        att["credentialSubject"]["inputFrameHashes"][0] = hash_frame(b"substituted-frame")
        ok, _ = verify_fused_attestation(att, self.kp.public_key_jwk)
        self.assertFalse(ok)

    def test_inputs_digest_is_order_sensitive(self):
        forward = fusion_inputs_digest(self.input_hashes)
        reversed_ = fusion_inputs_digest(list(reversed(self.input_hashes)))
        self.assertNotEqual(forward, reversed_)


class TestFusionInputs(unittest.TestCase):
    def setUp(self):
        self.kp, self.robot = _robot()
        self.robot_did = self.kp.did
        self.log = PerceptionLog()
        self.frames = [b"cam-front-0", b"lidar-top-0", b"radar-0"]
        for i, f in enumerate(self.frames):
            self.log.record(
                sensor_id=f"sensor-{i}",
                modality=["camera", "lidar", "radar"][i],
                frame=f,
                timestamp="2026-01-01T00:00:00Z",
            )
        self.input_hashes = [hash_frame(f) for f in self.frames]

    def _attest(self, inputs):
        return build_fused_attestation(
            self.robot,
            robot_did=self.robot_did,
            fusion_method="occupancy-grid-v1",
            input_frame_hashes=inputs,
            fused_output=b"world-model-0",
            captured_at=T0,
        )

    def test_all_inputs_recorded(self):
        ok, missing = verify_fusion_inputs(self._attest(self.input_hashes), self.log.entries())
        self.assertTrue(ok)
        self.assertEqual(missing, [])

    def test_unrecorded_input_named(self):
        phantom = hash_frame(b"never-captured")
        ok, missing = verify_fusion_inputs(
            self._attest(self.input_hashes + [phantom]), self.log.entries()
        )
        self.assertFalse(ok)
        self.assertEqual(missing, [phantom])


if __name__ == "__main__":
    unittest.main()
