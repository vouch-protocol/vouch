"""Tests for post-quantum signing of robot credentials."""

import unittest

from vouch import Signer, generate_identity
from vouch.robotics import (
    CLASSICAL_CRYPTOSUITE,
    HYBRID_CRYPTOSUITE,
    POST_QUANTUM_CRYPTOSUITE,
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

    def test_sign_pq_emits_a_proof_set(self):
        cred = self._identity_pq()
        self.assertTrue(is_pq(cred))
        proofs = cred["proof"]
        self.assertIsInstance(proofs, list)
        self.assertEqual(
            [p["cryptosuite"] for p in proofs],
            [CLASSICAL_CRYPTOSUITE, POST_QUANTUM_CRYPTOSUITE],
        )
        self.assertTrue(proofs[0]["proofValue"].startswith("z"))
        self.assertTrue(proofs[1]["proofValue"].startswith("u"))
        self.assertIn(ROBOT_IDENTITY_TYPE, cred["type"])

    def test_sign_pq_never_emits_the_composite(self):
        cred = self._identity_pq()
        self.assertNotIn(HYBRID_CRYPTOSUITE, [p["cryptosuite"] for p in cred["proof"]])

    def test_pre_alignment_composite_credential_is_still_recognized_and_verified(self):
        """A robot credential fielded under the composite keeps verifying."""
        from vouch import data_integrity_hybrid

        classical = mint_robot_identity(
            self.robot, self.root, make="Acme", model="AR-7", serial="SN-1"
        )
        ml_pub = self.robot.public_key_mldsa44()  # also generates the keypair
        body = {k: v for k, v in classical.items() if k != "proof"}
        body["proof"] = data_integrity_hybrid.build_hybrid_proof(
            body,
            ed25519_private_key=self.robot._raw_priv,
            mldsa44_secret_key=self.robot._mldsa44_secret,
            verification_method=self.robot.verification_method_id(),
        )
        self.assertEqual(body["proof"]["cryptosuite"], HYBRID_CRYPTOSUITE)
        self.assertTrue(is_pq(body))
        self.assertTrue(verify_pq(body, self.kp.public_key_jwk, ml_pub))
        self.assertTrue(
            verify_robot_credential(body, self.kp.public_key_jwk, mldsa44_public_key=ml_pub)
        )

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

    def test_stripped_pq_proof_set_is_not_downgraded_to_classical(self):
        """A post-quantum proof set stripped to its lone Ed25519 proof must not
        be accepted when the caller supplied an ML-DSA-44 key. Supplying the key
        means the caller requires the post-quantum proof, so a downgraded
        credential is rejected even though the extracted Ed25519 proof is
        genuine. The same credential still verifies when no ML-DSA-44 key is
        supplied, because then the caller is accepting classical proofs."""
        classical = mint_robot_identity(
            self.robot, self.root, make="Acme", model="AR-7", serial="S"
        )
        pq = sign_pq(classical, self.robot)
        ml_pub = self.robot.public_key_mldsa44()

        # The attacker strips the proof set down to just the standalone
        # eddsa-jcs-2022 proof object, dropping the ML-DSA-44 proof.
        proofs = pq["proof"]
        self.assertEqual(proofs[0]["cryptosuite"], CLASSICAL_CRYPTOSUITE)
        stripped = {k: v for k, v in pq.items() if k != "proof"}
        stripped["proof"] = proofs[0]

        # The extracted Ed25519 proof is itself genuine, so it is not detected
        # as a post-quantum credential any more.
        self.assertFalse(is_pq(stripped))

        # A caller that requires post-quantum (passes the ML-DSA-44 key) must
        # reject the downgraded credential.
        self.assertFalse(
            verify_robot_credential(stripped, self.kp.public_key_jwk, mldsa44_public_key=ml_pub)
        )

        # A caller that accepts classical credentials (no ML-DSA-44 key) still
        # verifies the genuine extracted Ed25519 proof.
        self.assertTrue(verify_robot_credential(stripped, self.kp.public_key_jwk))


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
