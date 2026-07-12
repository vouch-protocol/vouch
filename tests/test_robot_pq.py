"""Tests for post-quantum signing of robot credentials."""

import unittest

from vouch import Signer, generate_identity
from vouch.robotics import (
    HYBRID_CRYPTOSUITE,
    SoftwareRootOfTrust,
    is_pq,
    migrate_to_pq,
    mint_robot_identity,
    sign_pq,
    verify_pq,
    verify_robot_credential,
)
from vouch.robotics.identity import ROBOT_IDENTITY_TYPE


def _robot(domain="robot.example.com"):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestPQSigning(unittest.TestCase):
    def setUp(self):
        self.kp, self.robot = _robot()
        self.root = SoftwareRootOfTrust(kind="TPM")

    def _identity_pq(self):
        classical = mint_robot_identity(
            self.robot, self.root, make="Acme", model="AR-7", serial="SN-1"
        )
        return sign_pq(classical, self.robot)

    def test_sign_pq_uses_hybrid_cryptosuite(self):
        cred = self._identity_pq()
        self.assertTrue(is_pq(cred))
        self.assertEqual(cred["proof"]["cryptosuite"], HYBRID_CRYPTOSUITE)
        self.assertIn(ROBOT_IDENTITY_TYPE, cred["type"])

    def test_pq_credential_verifies(self):
        cred = self._identity_pq()
        ml_pub = self.robot.public_key_mldsa44()
        self.assertTrue(verify_pq(cred, self.kp.public_key_jwk, ml_pub))

    def test_pq_accepts_mldsa_multikey_string(self):
        cred = self._identity_pq()
        ml_multikey = self.robot.public_key_mldsa44_multikey()
        self.assertTrue(verify_pq(cred, self.kp.public_key_jwk, ml_multikey))

    def test_tampered_pq_credential_fails(self):
        cred = self._identity_pq()
        cred["credentialSubject"]["make"] = "Tampered"
        ml_pub = self.robot.public_key_mldsa44()
        self.assertFalse(verify_pq(cred, self.kp.public_key_jwk, ml_pub))

    def test_wrong_pq_key_fails(self):
        cred = self._identity_pq()
        _, other = _robot("other.example.com")
        self.assertFalse(verify_pq(cred, self.kp.public_key_jwk, other.public_key_mldsa44()))


class TestDualVerify(unittest.TestCase):
    def setUp(self):
        self.kp, self.robot = _robot()
        self.root = SoftwareRootOfTrust(kind="TPM")

    def test_dual_verify_handles_classical(self):
        classical = mint_robot_identity(
            self.robot, self.root, make="Acme", model="AR-7", serial="S"
        )
        self.assertFalse(is_pq(classical))
        self.assertTrue(verify_robot_credential(classical, self.kp.public_key_jwk))

    def test_dual_verify_handles_hybrid(self):
        classical = mint_robot_identity(
            self.robot, self.root, make="Acme", model="AR-7", serial="S"
        )
        pq = sign_pq(classical, self.robot)
        ml_pub = self.robot.public_key_mldsa44()
        self.assertTrue(
            verify_robot_credential(pq, self.kp.public_key_jwk, mldsa44_public_key=ml_pub)
        )

    def test_hybrid_without_pq_key_is_refused(self):
        classical = mint_robot_identity(
            self.robot, self.root, make="Acme", model="AR-7", serial="S"
        )
        pq = sign_pq(classical, self.robot)
        self.assertFalse(verify_robot_credential(pq, self.kp.public_key_jwk))


class TestMigration(unittest.TestCase):
    def test_migrate_preserves_body_and_upgrades_proof(self):
        kp, robot = _robot()
        root = SoftwareRootOfTrust(kind="TPM")
        classical = mint_robot_identity(robot, root, make="Acme", model="AR-7", serial="SN-9")
        self.assertFalse(is_pq(classical))

        migrated = migrate_to_pq(classical, robot)
        self.assertTrue(is_pq(migrated))
        # The credential body is preserved, only the proof changed.
        self.assertEqual(migrated["credentialSubject"], classical["credentialSubject"])
        self.assertEqual(migrated["type"], classical["type"])
        ml_pub = robot.public_key_mldsa44()
        self.assertTrue(
            verify_robot_credential(migrated, kp.public_key_jwk, mldsa44_public_key=ml_pub)
        )


if __name__ == "__main__":
    unittest.main()
