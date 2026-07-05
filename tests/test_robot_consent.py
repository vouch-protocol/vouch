"""Tests for bystander-consent evidence."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_consent_evidence,
    build_consent_token,
    hash_capture,
    verify_consent_evidence,
    verify_consent_token,
)
from vouch.robotics.identity import RoboticsError

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
IN_WINDOW = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
AFTER = datetime(2026, 1, 1, 2, 0, 0, tzinfo=timezone.utc)


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestConsentToken(unittest.TestCase):
    def setUp(self):
        self.by_kp, self.bystander = _party("person-1.example.com")
        self.robot_kp, self.robot = _party("robot-a.example.com")
        self.capture_hash = hash_capture(b"frame-0")

    def _token(self):
        return build_consent_token(
            self.bystander,
            bystander_did=self.by_kp.did,
            capture_hash=self.capture_hash,
            robot_did=self.robot_kp.did,
            valid_seconds=3600,
            granted_at=T0,
        )

    def test_token_verifies_for_its_capture(self):
        ok, subject = verify_consent_token(
            self._token(),
            self.by_kp.public_key_jwk,
            capture_hash=self.capture_hash,
            robot_did=self.robot_kp.did,
            now=IN_WINDOW,
        )
        self.assertTrue(ok)
        self.assertEqual(subject["robotDid"], self.robot_kp.did)

    def test_token_rejected_for_other_capture(self):
        ok, _ = verify_consent_token(
            self._token(),
            self.by_kp.public_key_jwk,
            capture_hash=hash_capture(b"different-frame"),
            robot_did=self.robot_kp.did,
            now=IN_WINDOW,
        )
        self.assertFalse(ok)

    def test_token_rejected_for_other_robot(self):
        ok, _ = verify_consent_token(
            self._token(),
            self.by_kp.public_key_jwk,
            capture_hash=self.capture_hash,
            robot_did="did:web:robot-z.example.com",
            now=IN_WINDOW,
        )
        self.assertFalse(ok)

    def test_token_out_of_window_rejected(self):
        ok, _ = verify_consent_token(
            self._token(),
            self.by_kp.public_key_jwk,
            capture_hash=self.capture_hash,
            robot_did=self.robot_kp.did,
            now=AFTER,
        )
        self.assertFalse(ok)


class TestConsentEvidence(unittest.TestCase):
    def setUp(self):
        self.by_kp, self.bystander = _party("person-1.example.com")
        self.robot_kp, self.robot = _party("robot-a.example.com")
        self.robot_did = self.robot_kp.did
        self.capture = b"frame-0"
        self.capture_hash = hash_capture(self.capture)
        self.token = build_consent_token(
            self.bystander,
            bystander_did=self.by_kp.did,
            capture_hash=self.capture_hash,
            robot_did=self.robot_did,
            valid_seconds=3600,
            granted_at=T0,
        )

    def test_explicit_consent_evidence_verifies(self):
        ev = build_consent_evidence(
            self.robot,
            robot_did=self.robot_did,
            capture_hash=self.capture_hash,
            basis="explicit-consent",
            consent_tokens=[self.token],
            valid_from=T0,
        )
        ok, subject = verify_consent_evidence(
            ev,
            self.robot_kp.public_key_jwk,
            capture=self.capture,
            consent_tokens=[self.token],
            bystander_keys={self.by_kp.did: self.by_kp.public_key_jwk},
            now=IN_WINDOW,
        )
        self.assertTrue(ok)
        self.assertEqual(subject["basis"], "explicit-consent")

    def test_explicit_consent_requires_a_token(self):
        with self.assertRaises(RoboticsError):
            build_consent_evidence(
                self.robot,
                robot_did=self.robot_did,
                capture_hash=self.capture_hash,
                basis="explicit-consent",
                valid_from=T0,
            )

    def test_redacted_basis_needs_no_token(self):
        ev = build_consent_evidence(
            self.robot,
            robot_did=self.robot_did,
            capture_hash=self.capture_hash,
            basis="redacted",
            redaction_hash=hash_capture(b"blurred-frame"),
            valid_from=T0,
        )
        ok, subject = verify_consent_evidence(
            ev, self.robot_kp.public_key_jwk, capture=self.capture
        )
        self.assertTrue(ok)
        self.assertEqual(subject["basis"], "redacted")

    def test_wrong_capture_rejected(self):
        ev = build_consent_evidence(
            self.robot,
            robot_did=self.robot_did,
            capture_hash=self.capture_hash,
            basis="posted-notice",
            valid_from=T0,
        )
        ok, _ = verify_consent_evidence(
            ev, self.robot_kp.public_key_jwk, capture=b"a-different-capture"
        )
        self.assertFalse(ok)

    def test_unknown_basis_rejected_at_build(self):
        with self.assertRaises(RoboticsError):
            build_consent_evidence(
                self.robot,
                robot_did=self.robot_did,
                capture_hash=self.capture_hash,
                basis="whatever",
                valid_from=T0,
            )

    def test_token_for_another_capture_does_not_satisfy_evidence(self):
        other_hash = hash_capture(b"other-capture")
        stray = build_consent_token(
            self.bystander,
            bystander_did=self.by_kp.did,
            capture_hash=other_hash,
            robot_did=self.robot_did,
            valid_seconds=3600,
            granted_at=T0,
        )
        ev = build_consent_evidence(
            self.robot,
            robot_did=self.robot_did,
            capture_hash=self.capture_hash,
            basis="explicit-consent",
            consent_tokens=[stray],
            valid_from=T0,
        )
        # The stray token is committed, but it is bound to a different capture, so
        # verifying it against this evidence's capture fails.
        ok, _ = verify_consent_evidence(
            ev,
            self.robot_kp.public_key_jwk,
            capture=self.capture,
            consent_tokens=[stray],
            bystander_keys={self.by_kp.did: self.by_kp.public_key_jwk},
            now=IN_WINDOW,
        )
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
