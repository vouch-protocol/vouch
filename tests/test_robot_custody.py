"""Tests for the physical custody handoff chain."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_handoff,
    holder_at,
    locate_condition_change,
    verify_handoff,
    verify_handoff_chain,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 1, 0, 10, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 1, 1, 0, 20, 0, tzinfo=timezone.utc)


def _actor(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did), kp.did


class TestHandoff(unittest.TestCase):
    def setUp(self):
        self.picker_kp, self.picker, self.picker_did = _actor("worker-jane.example.com")
        self.robot_a_kp, self.robot_a, self.robot_a_did = _actor("robot-a.example.com")

    def test_handoff_roundtrip(self):
        # The robot receives custody from the human picker; the robot signs.
        hoff = build_handoff(
            self.robot_a,
            task_id="tote-42",
            from_actor=self.picker_did,
            to_actor=self.robot_a_did,
            condition="intact",
            handoff_at=T0,
        )
        ok, subject = verify_handoff(hoff, self.robot_a_kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(subject["fromActor"], self.picker_did)
        self.assertEqual(subject["toActor"], self.robot_a_did)

    def test_issuer_must_be_receiver(self):
        hoff = build_handoff(
            self.robot_a,
            task_id="tote-42",
            from_actor=self.picker_did,
            to_actor=self.robot_a_did,
            handoff_at=T0,
        )
        # The picker's key cannot verify the robot's acceptance.
        ok, _ = verify_handoff(hoff, self.picker_kp.public_key_jwk)
        self.assertFalse(ok)


class TestCustodyChain(unittest.TestCase):
    def setUp(self):
        # human picker -> robot A -> robot B, mixed human and robot actors.
        self.jane_kp, self.jane, self.jane_did = _actor("worker-jane.example.com")
        self.a_kp, self.a, self.a_did = _actor("robot-a.example.com")
        self.b_kp, self.b, self.b_did = _actor("robot-b.example.com")
        self.keys = {
            self.a_did: self.a_kp.public_key_jwk,
            self.b_did: self.b_kp.public_key_jwk,
        }
        self.h1 = build_handoff(
            self.a,
            task_id="tote-42",
            from_actor=self.jane_did,
            to_actor=self.a_did,
            condition="intact",
            handoff_at=T0,
        )
        self.h2 = build_handoff(
            self.b,
            task_id="tote-42",
            from_actor=self.a_did,
            to_actor=self.b_did,
            condition="intact",
            handoff_at=T1,
        )

    def test_valid_chain_returns_current_holder(self):
        ok, holder = verify_handoff_chain([self.h1, self.h2], self.keys, origin_actor=self.jane_did)
        self.assertTrue(ok)
        self.assertEqual(holder, self.b_did)

    def test_broken_link_rejected(self):
        # A handoff whose fromActor is not the previous holder breaks the chain.
        stray_kp, stray, stray_did = _actor("robot-c.example.com")
        bad = build_handoff(
            stray, task_id="tote-42", from_actor="did:web:nobody", to_actor=stray_did, handoff_at=T2
        )
        keys = dict(self.keys)
        keys[stray_did] = stray_kp.public_key_jwk
        ok, _ = verify_handoff_chain([self.h1, bad], keys)
        self.assertFalse(ok)

    def test_missing_receiver_key_rejected(self):
        ok, _ = verify_handoff_chain([self.h1, self.h2], {self.a_did: self.a_kp.public_key_jwk})
        self.assertFalse(ok)

    def test_holder_at_time(self):
        # Before T1 the robot A holds it; at/after T1 robot B holds it.
        self.assertEqual(holder_at([self.h1, self.h2], "2026-01-01T00:05:00Z"), self.a_did)
        self.assertEqual(holder_at([self.h1, self.h2], "2026-01-01T00:15:00Z"), self.b_did)
        self.assertIsNone(holder_at([self.h1, self.h2], "2025-12-31T23:59:00Z"))


class TestConditionLocalization(unittest.TestCase):
    def test_condition_change_localizes_to_holder(self):
        jane_kp, jane, jane_did = _actor("worker-jane.example.com")
        a_kp, a, a_did = _actor("robot-a.example.com")
        b_kp, b, b_did = _actor("robot-b.example.com")
        # Robot A received it intact; robot B received it damaged, so the damage
        # happened while robot A held it.
        h1 = build_handoff(
            a,
            task_id="tote-42",
            from_actor=jane_did,
            to_actor=a_did,
            condition="intact",
            handoff_at=T0,
        )
        h2 = build_handoff(
            b,
            task_id="tote-42",
            from_actor=a_did,
            to_actor=b_did,
            condition="damaged",
            handoff_at=T1,
        )
        change = locate_condition_change([h1, h2])
        self.assertIsNotNone(change)
        self.assertEqual(change["responsibleHolder"], a_did)
        self.assertEqual(change["fromCondition"], "intact")
        self.assertEqual(change["toCondition"], "damaged")

    def test_no_change_returns_none(self):
        _, a, a_did = _actor("robot-a.example.com")
        _, b, b_did = _actor("robot-b.example.com")
        h1 = build_handoff(
            a,
            task_id="t",
            from_actor="did:web:j",
            to_actor=a_did,
            condition="intact",
            handoff_at=T0,
        )
        h2 = build_handoff(
            b, task_id="t", from_actor=a_did, to_actor=b_did, condition="intact", handoff_at=T1
        )
        self.assertIsNone(locate_condition_change([h1, h2]))


if __name__ == "__main__":
    unittest.main()
