"""Adversarial tests for the Halos safety-evidence recorder."""

import unittest

from vouch import Signer
from vouch.root_of_trust import generate_did_key_identity
from vouch.robotics import (
    HALOS_SAFETY_EVIDENCE_TYPE,
    HalosError,
    SafetyEventRecorder,
    build_safety_evidence,
    verify_safety_evidence,
)

KEY = bytes([9] * 32)
HALOS_STACK = {
    "igxSom": "IGX-Thor-SoM",
    "halosCore": "Halos Core Linux 1.0",
    "blueprint": ["SAIM", "SEI", "SDM"],
}
WINDOW = {"from": "2026-07-12T00:00:00Z", "to": "2026-07-12T01:00:00Z"}


def _robot():
    return Signer.from_keypair(generate_did_key_identity())


def _scenario():
    robot_kp = generate_did_key_identity()
    robot = Signer.from_keypair(robot_kp)
    rec = SafetyEventRecorder(KEY)
    rec.record("SAIM", "camera_blockage_cleared", {"cam": 2})
    rec.record("SEI", "multi_camera_fused", {"objects": 3})
    rec.record("SDM", "slow_stop", {"reason": "out_of_distribution"})
    rec.record("estop", "emergency_stop", {"by": "operator-7"})
    evidence = build_safety_evidence(
        robot,
        halos_stack=HALOS_STACK,
        window=WINDOW,
        recorder=rec,
        robot_identity="urn:uuid:robot-id",
    )
    return {
        "robot": robot,
        "robot_pub": robot_kp.public_key_jwk,
        "rec": rec,
        "evidence": evidence,
    }


class TestHalosSafetyEvidence(unittest.TestCase):
    def test_happy_path_seals_and_verifies(self):
        s = _scenario()
        ok, subject = verify_safety_evidence(
            s["evidence"], s["robot_pub"], entries=s["rec"].entries()
        )
        self.assertTrue(ok, subject)
        self.assertEqual(subject["id"], s["robot"].get_did())
        self.assertEqual(subject["entryCount"], 4)
        self.assertEqual(subject["blackboxHead"], s["rec"].head())
        self.assertEqual(subject["halosStack"]["blueprint"], ["SAIM", "SEI", "SDM"])
        self.assertEqual(subject["robotIdentity"], "urn:uuid:robot-id")
        self.assertIn(HALOS_SAFETY_EVIDENCE_TYPE, s["evidence"]["type"])

    def test_signature_only_path_without_entries(self):
        s = _scenario()
        ok, subject = verify_safety_evidence(s["evidence"], s["robot_pub"])
        self.assertTrue(ok, subject)
        self.assertEqual(subject["entryCount"], 4)

    def test_unknown_event_source_rejected(self):
        rec = SafetyEventRecorder(KEY)
        with self.assertRaises(HalosError):
            rec.record("bogus", "whatever", {})

    def test_tampered_entry_rejected(self):
        s = _scenario()
        entries = s["rec"].entries()
        entries[1]["event"] = "forged_event"
        ok, _ = verify_safety_evidence(s["evidence"], s["robot_pub"], entries=entries)
        self.assertFalse(ok)

    def test_truncated_record_rejected(self):
        s = _scenario()
        entries = s["rec"].entries()[:-1]
        ok, _ = verify_safety_evidence(s["evidence"], s["robot_pub"], entries=entries)
        self.assertFalse(ok)

    def test_appended_after_seal_rejected(self):
        s = _scenario()
        # Seal, then keep recording: the presented log no longer matches the seal.
        s["rec"].record("operator", "resume", {"by": "operator-7"})
        ok, _ = verify_safety_evidence(s["evidence"], s["robot_pub"], entries=s["rec"].entries())
        self.assertFalse(ok)

    def test_reordered_entries_rejected(self):
        s = _scenario()
        entries = s["rec"].entries()
        entries[0], entries[2] = entries[2], entries[0]
        ok, _ = verify_safety_evidence(s["evidence"], s["robot_pub"], entries=entries)
        self.assertFalse(ok)

    def test_wrong_robot_key_rejected(self):
        s = _scenario()
        other = generate_did_key_identity()
        ok, _ = verify_safety_evidence(
            s["evidence"], other.public_key_jwk, entries=s["rec"].entries()
        )
        self.assertFalse(ok)

    def test_forged_evidence_not_attributable_to_robot(self):
        # An attacker seals the robot's real head under its own key. Verifying with
        # the robot's key fails, so the evidence cannot be attributed to the robot.
        s = _scenario()
        attacker = _robot()
        forged = build_safety_evidence(
            attacker,
            halos_stack=HALOS_STACK,
            window=WINDOW,
            blackbox_head=s["rec"].head(),
            entry_count=s["rec"].count(),
        )
        ok, _ = verify_safety_evidence(forged, s["robot_pub"], entries=s["rec"].entries())
        self.assertFalse(ok)

    def test_head_mismatch_rejected(self):
        s = _scenario()
        bad = build_safety_evidence(
            s["robot"],
            halos_stack=HALOS_STACK,
            window=WINDOW,
            blackbox_head="uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            entry_count=s["rec"].count(),
        )
        ok, _ = verify_safety_evidence(bad, s["robot_pub"], entries=s["rec"].entries())
        self.assertFalse(ok)

    def test_missing_stack_or_window_rejected(self):
        robot = _robot()
        with self.assertRaises(HalosError):
            build_safety_evidence(
                robot, halos_stack={}, window=WINDOW, blackbox_head="u", entry_count=0
            )
        with self.assertRaises(HalosError):
            build_safety_evidence(
                robot, halos_stack=HALOS_STACK, window={}, blackbox_head="u", entry_count=0
            )

    def test_payloads_confidential_but_chain_public(self):
        # The chain verifies from the encrypted entries without the key, while the
        # payloads open only with the black-box key.
        s = _scenario()
        entries = s["rec"].entries()
        self.assertNotIn("operator-7", str(entries))  # payload is encrypted
        opened = s["rec"].open_entry(entries[3])
        self.assertEqual(opened["source"], "estop")
        self.assertEqual(opened["detail"]["by"], "operator-7")


if __name__ == "__main__":
    unittest.main()
