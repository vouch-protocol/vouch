"""Tests for safe robot-to-human handover."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_handover_ack,
    build_human_handover,
    verify_handover_ack,
    verify_human_handover,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
SCOPE = {"maxForceN": 40.0, "maxSpeedNearHumansMps": 0.25}
ROBOT = "did:web:robot-a.example.com"


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestHumanHandover(unittest.TestCase):
    def setUp(self):
        self.robot_kp, self.robot = _party("robot-a.example.com")

    def test_in_envelope_handover_verifies(self):
        h = build_human_handover(
            self.robot,
            robot_did=self.robot_kp.did,
            recipient="did:web:person-1.example.com",
            object_id="tote-7",
            force_n=18.0,
            speed_mps=0.15,
            scope=SCOPE,
            handover_at=T0,
        )
        ok, subject = verify_human_handover(h, self.robot_kp.public_key_jwk, scope=SCOPE)
        self.assertTrue(ok)
        self.assertTrue(subject["inEnvelope"])

    def test_out_of_envelope_is_honest(self):
        h = build_human_handover(
            self.robot,
            robot_did=self.robot_kp.did,
            recipient="did:web:person-1.example.com",
            object_id="tote-7",
            force_n=90.0,
            speed_mps=0.9,
            scope=SCOPE,
            handover_at=T0,
        )
        ok, subject = verify_human_handover(h, self.robot_kp.public_key_jwk, scope=SCOPE)
        self.assertTrue(ok)
        self.assertFalse(subject["inEnvelope"])

    def test_forged_in_envelope_verdict_rejected(self):
        h = build_human_handover(
            self.robot,
            robot_did=self.robot_kp.did,
            recipient="did:web:person-1.example.com",
            object_id="tote-7",
            force_n=90.0,
            speed_mps=0.9,
            scope=SCOPE,
            handover_at=T0,
        )
        h["credentialSubject"]["inEnvelope"] = True
        ok, _ = verify_human_handover(h, self.robot_kp.public_key_jwk, scope=SCOPE)
        self.assertFalse(ok)


class TestHandoverAck(unittest.TestCase):
    def setUp(self):
        self.robot_kp, self.robot = _party("robot-a.example.com")
        self.person_kp, self.person = _party("person-1.example.com")
        self.handover = build_human_handover(
            self.robot,
            robot_did=self.robot_kp.did,
            recipient=self.person_kp.did,
            object_id="tote-7",
            force_n=18.0,
            speed_mps=0.15,
            scope=SCOPE,
            handover_at=T0,
        )

    def test_ack_binds_to_handover(self):
        ack = build_handover_ack(
            self.person, recipient_did=self.person_kp.did, handover=self.handover
        )
        ok, subject = verify_handover_ack(
            ack, self.person_kp.public_key_jwk, handover=self.handover
        )
        self.assertTrue(ok)
        self.assertEqual(subject["objectId"], "tote-7")

    def test_ack_does_not_verify_against_other_handover(self):
        other = build_human_handover(
            self.robot,
            robot_did=self.robot_kp.did,
            recipient=self.person_kp.did,
            object_id="tote-9",
            force_n=10.0,
            speed_mps=0.1,
            scope=SCOPE,
            handover_at=T0,
        )
        ack = build_handover_ack(
            self.person, recipient_did=self.person_kp.did, handover=self.handover
        )
        ok, _ = verify_handover_ack(ack, self.person_kp.public_key_jwk, handover=other)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
