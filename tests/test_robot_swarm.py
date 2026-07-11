"""Tests for multi-robot swarm accountability."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_collective_action,
    build_swarm_membership,
    verify_collective_action,
    verify_swarm_membership,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
SWARM = "swarm-42"


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestSwarmMembership(unittest.TestCase):
    def setUp(self):
        self.coord_kp, self.coordinator = _party("coordinator.example.com")
        self.robot_kp, _ = _party("robot-a.example.com")

    def test_membership_verifies(self):
        m = build_swarm_membership(
            self.coordinator,
            swarm_id=SWARM,
            robot_did=self.robot_kp.did,
            role="picker",
            valid_from=T0,
        )
        ok, subject = verify_swarm_membership(m, self.coord_kp.public_key_jwk, swarm_id=SWARM)
        self.assertTrue(ok)
        self.assertEqual(subject["role"], "picker")

    def test_membership_for_other_swarm_rejected(self):
        m = build_swarm_membership(
            self.coordinator, swarm_id=SWARM, robot_did=self.robot_kp.did, valid_from=T0
        )
        ok, _ = verify_swarm_membership(m, self.coord_kp.public_key_jwk, swarm_id="swarm-99")
        self.assertFalse(ok)


class TestCollectiveAction(unittest.TestCase):
    def setUp(self):
        self.coord_kp, self.coordinator = _party("coordinator.example.com")
        self.a_kp, _ = _party("robot-a.example.com")
        self.b_kp, _ = _party("robot-b.example.com")
        self.members = {
            self.a_kp.did: self.a_kp.public_key_jwk,
            self.b_kp.did: self.b_kp.public_key_jwk,
        }
        self.memberships = [
            build_swarm_membership(
                self.coordinator, swarm_id=SWARM, robot_did=self.a_kp.did, valid_from=T0
            ),
            build_swarm_membership(
                self.coordinator, swarm_id=SWARM, robot_did=self.b_kp.did, valid_from=T0
            ),
        ]

    def _action(self, participants):
        return build_collective_action(
            self.coordinator,
            swarm_id=SWARM,
            action="lift-beam",
            participants=participants,
            action_at=T0,
        )

    def test_action_verifies_with_members(self):
        act = self._action([self.a_kp.did, self.b_kp.did])
        ok, unverified = verify_collective_action(
            act,
            self.coord_kp.public_key_jwk,
            memberships=self.memberships,
        )
        self.assertTrue(ok)
        self.assertEqual(unverified, [])

    def test_action_verifies_without_member_check(self):
        act = self._action([self.a_kp.did])
        ok, _ = verify_collective_action(act, self.coord_kp.public_key_jwk)
        self.assertTrue(ok)

    def test_non_member_participant_flagged(self):
        stranger = "did:web:robot-z.example.com"
        act = self._action([self.a_kp.did, stranger])
        ok, unverified = verify_collective_action(
            act,
            self.coord_kp.public_key_jwk,
            memberships=self.memberships,
        )
        self.assertFalse(ok)
        self.assertEqual(unverified, [stranger])


if __name__ == "__main__":
    unittest.main()
