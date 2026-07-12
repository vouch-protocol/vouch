"""Tests for cross-embodiment identity continuity."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_embodiment,
    check_no_fork,
    verify_continuity_chain,
    verify_embodiment,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 1, 1, 2, 0, 0, tzinfo=timezone.utc)


def _agent(domain="agent.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestEmbodiment(unittest.TestCase):
    def setUp(self):
        self.kp, self.agent = _agent()
        self.did = self.kp.did

    def test_embodiment_roundtrip(self):
        cred = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="did:web:body-a.example.com",
            body_hardware_root="uROOTA",
            embodied_at=T0,
        )
        ok, subject = verify_embodiment(cred, self.kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(subject["body"], "did:web:body-a.example.com")
        self.assertEqual(subject["bodyHardwareRoot"], "uROOTA")

    def test_issuer_must_be_the_agent(self):
        cred = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="did:web:body-a.example.com",
            body_hardware_root="uROOTA",
            embodied_at=T0,
        )
        # A different key cannot verify (proof mismatch), and the issuer is the agent.
        _, other = _agent("other.example.com")
        ok, _ = verify_embodiment(cred, generate_identity(domain="x.example.com").public_key_jwk)
        self.assertFalse(ok)

    def test_wrong_key_rejected(self):
        cred = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="did:web:body-a.example.com",
            body_hardware_root="uROOTA",
            embodied_at=T0,
        )
        other_kp, _ = _agent("other.example.com")
        ok, _ = verify_embodiment(cred, other_kp.public_key_jwk)
        self.assertFalse(ok)


class TestContinuityChain(unittest.TestCase):
    def setUp(self):
        self.kp, self.agent = _agent()
        self.did = self.kp.did
        # The mind moves body-a -> body-b -> body-c, every link signed by the agent.
        self.a = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-a",
            body_hardware_root="uA",
            embodied_at=T0,
            valid_seconds=3600,
        )
        self.b = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-b",
            body_hardware_root="uB",
            from_body="body-a",
            embodied_at=T1,
            valid_seconds=3600,
        )
        self.c = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-c",
            body_hardware_root="uC",
            from_body="body-b",
            embodied_at=T2,
        )

    def test_valid_chain_returns_current_body(self):
        ok, current = verify_continuity_chain(
            [self.a, self.b, self.c], self.kp.public_key_jwk, origin_body=None
        )
        self.assertTrue(ok)
        self.assertEqual(current, "body-c")

    def test_broken_link_rejected(self):
        # c claims it came from body-b, but we hand it a chain that skips b.
        ok, _ = verify_continuity_chain([self.a, self.c], self.kp.public_key_jwk)
        self.assertFalse(ok)

    def test_chain_must_be_one_agent_key(self):
        # A link signed by a different agent breaks the "same mind" property.
        other_kp, other = _agent("impostor.example.com")
        forged = build_embodiment(
            other,
            agent_did=other_kp.did,
            body_did="body-b",
            body_hardware_root="uB",
            from_body="body-a",
            embodied_at=T1,
        )
        ok, _ = verify_continuity_chain([self.a, forged], self.kp.public_key_jwk)
        self.assertFalse(ok)


class TestForkDetection(unittest.TestCase):
    def setUp(self):
        self.kp, self.agent = _agent()
        self.did = self.kp.did

    def test_clean_handover_has_no_fork(self):
        # body-a active [T0, T1), body-b active [T1, ...) -> no overlap.
        a = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-a",
            body_hardware_root="uA",
            embodied_at=T0,
            valid_seconds=3600,
        )
        b = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-b",
            body_hardware_root="uB",
            from_body="body-a",
            embodied_at=T1,
        )
        ok, conflict = check_no_fork([a, b])
        self.assertTrue(ok)
        self.assertIsNone(conflict)

    def test_overlapping_bodies_is_a_fork(self):
        # body-a active [T0, T2) still open when body-b starts at T1 -> fork.
        a = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-a",
            body_hardware_root="uA",
            embodied_at=T0,
            valid_seconds=2 * 3600,
        )
        b = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-b",
            body_hardware_root="uB",
            embodied_at=T1,
            valid_seconds=3600,
        )
        ok, conflict = check_no_fork([a, b])
        self.assertFalse(ok)
        self.assertIsNotNone(conflict)
        self.assertEqual({conflict["bodyA"], conflict["bodyB"]}, {"body-a", "body-b"})

    def test_open_ended_windows_on_two_bodies_is_a_fork(self):
        # Two bodies each with no validUntil, both open-ended -> overlap -> fork.
        a = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-a",
            body_hardware_root="uA",
            embodied_at=T0,
        )
        b = build_embodiment(
            self.agent,
            agent_did=self.did,
            body_did="body-b",
            body_hardware_root="uB",
            embodied_at=T1,
        )
        ok, _ = check_no_fork([a, b])
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
