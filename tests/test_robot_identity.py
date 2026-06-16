"""
Tests for hardware-rooted robot identity (Phase 5.1).
"""

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    SoftwareRootOfTrust,
    lifecycle_event,
    mint_robot_identity,
    verify_robot_identity,
)


@pytest.fixture
def robot():
    kp = generate_identity(domain="robot-fleet.example.com")
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _mint(robot, root=None):
    kp, signer = robot
    root = root or SoftwareRootOfTrust(seed=bytes(range(32)), kind="TPM")
    return mint_robot_identity(
        signer,
        root,
        make="Acme Robotics",
        model="AR-7",
        serial="SN-000123",
        owner="did:web:owner.example.com",
        lifecycle=[lifecycle_event("manufactured"), lifecycle_event("commissioned")],
    )


class TestRobotIdentity:
    def test_mint_and_verify(self, robot):
        kp, _ = robot
        cred = _mint(robot)
        assert "RobotIdentityCredential" in cred["type"]
        ok, subject = verify_robot_identity(cred, kp.public_key_jwk)
        assert ok is True
        assert subject["make"] == "Acme Robotics"
        assert subject["serial"] == "SN-000123"
        assert subject["hardwareRoot"]["kind"] == "TPM"
        assert len(subject["lifecycle"]) == 2

    def test_tampered_serial_fails_credential_proof(self, robot):
        kp, _ = robot
        cred = _mint(robot)
        cred["credentialSubject"]["serial"] = "SN-999999"
        ok, _ = verify_robot_identity(cred, kp.public_key_jwk)
        assert ok is False  # the credential proof no longer matches

    def test_forged_hardware_root_fails(self, robot):
        kp, _ = robot
        cred = _mint(robot)
        # Swap in a different hardware root key (attacker cannot re-sign the binding).
        attacker_root = SoftwareRootOfTrust(seed=bytes([7] * 32))
        cred["credentialSubject"]["hardwareRoot"]["publicKeyMultibase"] = (
            attacker_root.public_key_multibase()
        )
        # Re-sign the credential proof so only the hardware attestation is wrong.
        from vouch import Signer
        from vouch.robotics._signing import attach_proof

        signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
        cred.pop("proof", None)
        cred = attach_proof(cred, signer)
        ok, _ = verify_robot_identity(cred, kp.public_key_jwk)
        assert ok is False  # hardware attestation does not verify against the swapped key

    def test_binding_ties_key_to_hardware(self, robot):
        # A credential minted for one robot key does not verify under another key.
        cred = _mint(robot)
        other = generate_identity(domain="other.example.com")
        ok, _ = verify_robot_identity(cred, other.public_key_jwk)
        assert ok is False
