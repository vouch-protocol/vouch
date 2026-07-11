"""Adversarial tests for the root-of-trust robot-identity binding."""

import unittest

from vouch import Signer
from vouch.root_of_trust import (
    ACTION_ISSUE_AGENT_IDENTITY,
    build_agent_identity,
    build_recognized_issuer,
    generate_did_key_identity,
)
from vouch.robotics import (
    ACTION_ISSUE_ROBOT_IDENTITY,
    SoftwareRootOfTrust,
    build_robot_identity,
    mint_robot_identity,
    verify_robot_identity_chain,
)

HW_SEED = bytes([7] * 32)
ATTRS = {
    "make": "Acme Robotics",
    "model": "AR-7",
    "serial": "SN-000123",
    "owner": "did:web:acme.example.com",
}


def _signer():
    return Signer.from_keypair(generate_did_key_identity())


def _scenario(recognized_actions=None):
    """Build a full valid scenario and return the pieces so tests can perturb one."""
    root = _signer()
    manufacturer = _signer()
    robot_kp = generate_did_key_identity()
    robot = Signer.from_keypair(robot_kp)

    recognized = build_recognized_issuer(
        root,
        issuer_did=manufacturer.did,
        recognized_actions=recognized_actions or [ACTION_ISSUE_ROBOT_IDENTITY],
    )
    hw_root = SoftwareRootOfTrust(seed=HW_SEED, kind="TPM")
    robot_hw_cred = mint_robot_identity(
        robot, hw_root, make="Acme Robotics", model="AR-7", serial="SN-000123"
    )
    robot_key_mb = robot.get_public_key_multikey()
    authority = build_robot_identity(
        manufacturer, robot_did=robot.did, hardware_key_multibase=robot_key_mb, attributes=ATTRS
    )
    return {
        "root": root,
        "manufacturer": manufacturer,
        "robot": robot,
        "robot_pub": robot_kp.public_key_jwk,
        "robot_key_mb": robot_key_mb,
        "recognized": recognized,
        "robot_hw_cred": robot_hw_cred,
        "authority": authority,
    }


class TestRobotIdentityChain(unittest.TestCase):
    def _verify(self, s, **over):
        return verify_robot_identity_chain(
            over.get("authority", s["authority"]),
            over.get("recognized", s["recognized"]),
            over.get("robot_hw_cred", s["robot_hw_cred"]),
            trusted_root=over.get("trusted_root", s["root"].did),
            robot_public_key=over.get("robot_public_key", s["robot_pub"]),
            is_revoked=over.get("is_revoked"),
        )

    def test_happy_path_confirms_provenance_and_hardware(self):
        s = _scenario()
        r = self._verify(s)
        self.assertTrue(r.ok, r.reason)
        self.assertTrue(r.hardware_rooted)
        self.assertEqual(r.robot_did, s["robot"].did)
        self.assertEqual(r.issuer_did, s["manufacturer"].did)
        self.assertEqual(r.root_did, s["root"].did)
        self.assertEqual(r.attributes["make"], "Acme Robotics")

    def test_issuer_not_recognized_for_robot_action(self):
        # The manufacturer is recognized only to issue agent identities.
        s = _scenario(recognized_actions=[ACTION_ISSUE_AGENT_IDENTITY])
        r = self._verify(s)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "issuer_not_recognized_for_action")

    def test_wrong_pinned_root_rejected(self):
        s = _scenario()
        other_root = _signer()
        r = self._verify(s, trusted_root=other_root.did)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "recognized_issuer_not_from_root")

    def test_manufacturer_vouched_a_different_key(self):
        # The authority identity binds a key that is not the robot's real key.
        s = _scenario()
        stray = _signer()
        forged_authority = build_robot_identity(
            s["manufacturer"],
            robot_did=s["robot"].did,
            hardware_key_multibase=stray.get_public_key_multikey(),
            attributes=ATTRS,
        )
        r = self._verify(s, authority=forged_authority)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "hardware_key_mismatch")

    def test_hardware_attestation_forged(self):
        # A software key claims to be hardware-rooted: swap the key and re-sign the
        # credential, so the hardware attestation no longer matches the binding.
        s = _scenario()
        impostor_kp = generate_did_key_identity()
        # Present the robot's own hardware credential but claim it under an impostor key:
        # the credential proof no longer verifies, so the hardware root is invalid.
        r = verify_robot_identity_chain(
            s["authority"],
            s["recognized"],
            s["robot_hw_cred"],
            trusted_root=s["root"].did,
            robot_public_key=impostor_kp.public_key_jwk,
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "hardware_root_invalid")

    def test_hardware_credential_for_a_different_robot(self):
        s = _scenario()
        other = _scenario()
        # Present robot B's hardware credential (verified with B's key) against robot A's
        # authority identity: the subjects do not match.
        r = verify_robot_identity_chain(
            s["authority"],
            s["recognized"],
            other["robot_hw_cred"],
            trusted_root=s["root"].did,
            robot_public_key=other["robot_pub"],
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "hardware_subject_mismatch")

    def test_plain_agent_identity_has_no_hardware_key(self):
        # A recognized robot-issuer issues a plain agent identity with no hardware key.
        s = _scenario()
        plain = build_agent_identity(
            s["manufacturer"], subject_did=s["robot"].did, attributes={"make": "Acme"}
        )
        r = self._verify(s, authority=plain)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "identity_no_hardware_key")

    def test_self_signed_manufacturer_not_from_root(self):
        # A manufacturer that recognized itself, not signed by the pinned root.
        s = _scenario()
        rogue = _signer()
        self_reco = build_recognized_issuer(
            rogue,
            issuer_did=s["manufacturer"].did,
            recognized_actions=[ACTION_ISSUE_ROBOT_IDENTITY],
        )
        r = self._verify(s, recognized=self_reco)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "recognized_issuer_not_from_root")

    def test_revoked_issuer_rejected(self):
        s = _scenario()
        r = self._verify(s, is_revoked=lambda c: c is s["recognized"])
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "recognized_issuer_revoked")


if __name__ == "__main__":
    unittest.main()
