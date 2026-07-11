"""Tests for accountable teleoperation handoff."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_control_handoff,
    check_control_continuity,
    controller_at,
    verify_control_chain,
    verify_control_handoff,
)
from vouch.robotics.identity import RoboticsError

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 1, 0, 10, 0, tzinfo=timezone.utc)
MID = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
AFTER = datetime(2026, 1, 1, 0, 20, 0, tzinfo=timezone.utc)

ROBOT = "did:web:robot-a.example.com"
AUTONOMY = "did:web:autopilot.example.com"
OPERATOR = "did:web:operator-jane.example.com"


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestControlHandoff(unittest.TestCase):
    def setUp(self):
        self.op_kp, self.operator = _party("operator-jane.example.com")

    def test_handoff_verifies(self):
        h = build_control_handoff(
            self.operator,
            robot_did=ROBOT,
            from_controller=AUTONOMY,
            to_controller=self.op_kp.did,
            mode="teleoperated",
            handoff_at=T0,
        )
        ok, subject = verify_control_handoff(h, self.op_kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(subject["mode"], "teleoperated")

    def test_unknown_mode_rejected_at_build(self):
        with self.assertRaises(RoboticsError):
            build_control_handoff(
                self.operator,
                robot_did=ROBOT,
                from_controller=AUTONOMY,
                to_controller=self.op_kp.did,
                mode="hovering",
                handoff_at=T0,
            )

    def test_issuer_must_be_receiver(self):
        h = build_control_handoff(
            self.operator,
            robot_did=ROBOT,
            from_controller=AUTONOMY,
            to_controller=self.op_kp.did,
            mode="teleoperated",
            handoff_at=T0,
        )
        h["issuer"] = AUTONOMY
        ok, _ = verify_control_handoff(h, self.op_kp.public_key_jwk)
        self.assertFalse(ok)


class TestControlChain(unittest.TestCase):
    def setUp(self):
        self.auto_kp, self.autonomy = _party("autopilot.example.com")
        self.op_kp, self.operator = _party("operator-jane.example.com")
        self.auto_did = self.auto_kp.did
        self.op_did = self.op_kp.did
        # autonomy -> operator (takeover) at T0, operator -> autonomy (return) at T1
        self.h1 = build_control_handoff(
            self.operator,
            robot_did=ROBOT,
            from_controller=self.auto_did,
            to_controller=self.op_did,
            mode="teleoperated",
            handoff_at=T0,
        )
        self.h2 = build_control_handoff(
            self.autonomy,
            robot_did=ROBOT,
            from_controller=self.op_did,
            to_controller=self.auto_did,
            mode="autonomous",
            handoff_at=T1,
        )
        self.keys = {
            self.op_did: self.op_kp.public_key_jwk,
            self.auto_did: self.auto_kp.public_key_jwk,
        }

    def test_chain_verifies_and_returns_current(self):
        ok, current = verify_control_chain(
            [self.h1, self.h2], self.keys, origin_controller=self.auto_did
        )
        self.assertTrue(ok)
        self.assertEqual(current, self.auto_did)

    def test_broken_link_rejected(self):
        stranger = "did:web:someone-else.example.com"
        bad = build_control_handoff(
            self.autonomy,
            robot_did=ROBOT,
            from_controller=stranger,
            to_controller=self.auto_did,
            mode="autonomous",
            handoff_at=T1,
        )
        ok, _ = verify_control_chain([self.h1, bad], self.keys)
        self.assertFalse(ok)

    def test_controller_at_time(self):
        self.assertEqual(controller_at([self.h1, self.h2], "2026-01-01T00:05:00Z"), self.op_did)
        self.assertEqual(controller_at([self.h1, self.h2], "2026-01-01T00:20:00Z"), self.auto_did)
        self.assertIsNone(controller_at([self.h1, self.h2], "2025-12-31T23:59:00Z"))


class TestControlContinuity(unittest.TestCase):
    def test_continuous_chain_ok(self):
        _, autonomy = _party("autopilot.example.com")
        _, operator = _party("operator-jane.example.com")
        h1 = build_control_handoff(
            operator,
            robot_did=ROBOT,
            from_controller=AUTONOMY,
            to_controller=OPERATOR,
            mode="teleoperated",
            handoff_at=T0,
        )
        h2 = build_control_handoff(
            autonomy,
            robot_did=ROBOT,
            from_controller=OPERATOR,
            to_controller=AUTONOMY,
            mode="autonomous",
            handoff_at=T1,
        )
        result = check_control_continuity([h1, h2])
        self.assertTrue(result.ok)
        self.assertEqual(result.gaps, [])
        self.assertEqual(result.overlaps, [])

    def test_discontinuity_flagged(self):
        _, autonomy = _party("autopilot.example.com")
        _, operator = _party("operator-jane.example.com")
        h1 = build_control_handoff(
            operator,
            robot_did=ROBOT,
            from_controller=AUTONOMY,
            to_controller=OPERATOR,
            mode="teleoperated",
            handoff_at=T0,
        )
        # The second link does not begin where the first left off (claims control
        # from autonomy while the operator still held it): a gap and an overlap.
        h2 = build_control_handoff(
            autonomy,
            robot_did=ROBOT,
            from_controller=AUTONOMY,
            to_controller=AUTONOMY,
            mode="autonomous",
            handoff_at=T1,
        )
        result = check_control_continuity([h1, h2])
        self.assertFalse(result.ok)
        self.assertEqual(result.gaps[0]["expected"], OPERATOR)
        self.assertEqual(result.overlaps[0]["found"], AUTONOMY)


if __name__ == "__main__":
    unittest.main()
