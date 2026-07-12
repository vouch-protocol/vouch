"""
Tests for the robot lifecycle: ownership transfer (chain of custody), key
rotation (key history), and decommissioning.
"""

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_decommission,
    build_key_rotation,
    build_ownership_transfer,
    verify_custody_chain,
    verify_decommission,
    verify_key_history,
    verify_key_rotation,
    verify_ownership_transfer,
)
from vouch.robotics.identity import RoboticsError

ROBOT = "did:web:robot.example.com"


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


# ---------------------------------------------------------------------------
# Ownership transfer
# ---------------------------------------------------------------------------


class TestOwnershipTransfer:
    def test_build_and_verify(self):
        kp, owner = _party("owner-a.example.com")
        t = build_ownership_transfer(owner, robot_did=ROBOT, to_owner="did:web:owner-b.example.com")
        assert "RobotOwnershipTransferCredential" in t["type"]
        ok, subject = verify_ownership_transfer(t, kp.public_key_jwk)
        assert ok is True
        assert subject["fromOwner"] == owner.get_did()
        assert subject["toOwner"] == "did:web:owner-b.example.com"

    def test_issuer_must_be_from_owner(self):
        kp, owner = _party("owner-a.example.com")
        t = build_ownership_transfer(
            owner, robot_did=ROBOT, to_owner="did:web:b", from_owner="did:web:someone-else"
        )
        # signed by owner-a but claims fromOwner someone-else: rejected
        ok, _ = verify_ownership_transfer(t, kp.public_key_jwk)
        assert ok is False

    def test_wrong_key_fails(self):
        _, owner = _party("owner-a.example.com")
        other = generate_identity(domain="x.example.com")
        t = build_ownership_transfer(owner, robot_did=ROBOT, to_owner="did:web:b")
        ok, _ = verify_ownership_transfer(t, other.public_key_jwk)
        assert ok is False

    def test_custody_chain(self):
        kpa, a = _party("owner-a.example.com")
        kpb, b = _party("owner-b.example.com")
        t1 = build_ownership_transfer(a, robot_did=ROBOT, to_owner=b.get_did())
        t2 = build_ownership_transfer(
            b, robot_did=ROBOT, to_owner="did:web:owner-c.example.com", prev_transfer_id="t1"
        )
        keys = {a.get_did(): kpa.public_key_jwk, b.get_did(): kpb.public_key_jwk}
        ok, current = verify_custody_chain([t1, t2], keys, origin_owner=a.get_did())
        assert ok is True
        assert current == "did:web:owner-c.example.com"

    def test_custody_chain_broken_link(self):
        kpa, a = _party("owner-a.example.com")
        kpx, x = _party("owner-x.example.com")  # not the recipient of t1
        t1 = build_ownership_transfer(a, robot_did=ROBOT, to_owner="did:web:owner-b.example.com")
        # x was never given the robot, so its transfer does not chain
        t2 = build_ownership_transfer(x, robot_did=ROBOT, to_owner="did:web:owner-c.example.com")
        keys = {a.get_did(): kpa.public_key_jwk, x.get_did(): kpx.public_key_jwk}
        ok, _ = verify_custody_chain([t1, t2], keys, origin_owner=a.get_did())
        assert ok is False


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_build_and_verify(self):
        kp_old, old = _party("robot.example.com")
        new = generate_identity(domain="robot.example.com")
        new_mb = Signer(private_key=new.private_key_jwk, did=ROBOT).get_public_key_multikey()
        rot = build_key_rotation(old, robot_did=ROBOT, new_key_multibase=new_mb, reason="scheduled")
        assert "RobotKeyRotationCredential" in rot["type"]
        ok, subject = verify_key_rotation(rot, kp_old.public_key_jwk)
        assert ok is True
        assert subject["newKey"] == new_mb
        assert subject["previousKey"] == old.get_public_key_multikey()

    def test_new_key_not_yet_trusted_by_old_verifier(self):
        kp_old, old = _party("robot.example.com")
        other = generate_identity(domain="x.example.com")
        new_mb = Signer(private_key=other.private_key_jwk, did=ROBOT).get_public_key_multikey()
        rot = build_key_rotation(old, robot_did=ROBOT, new_key_multibase=new_mb)
        # rotation must be signed by the OLD key; verifying with a stranger key fails
        ok, _ = verify_key_rotation(rot, other.public_key_jwk)
        assert ok is False

    def test_key_history_chain(self):
        kp1, k1 = _party("robot.example.com")
        n2 = generate_identity(domain="robot.example.com")
        s2 = Signer(private_key=n2.private_key_jwk, did=ROBOT)
        n3 = generate_identity(domain="robot.example.com")
        mb1 = k1.get_public_key_multikey()
        mb2 = s2.get_public_key_multikey()
        mb3 = Signer(private_key=n3.private_key_jwk, did=ROBOT).get_public_key_multikey()
        r1 = build_key_rotation(k1, robot_did=ROBOT, new_key_multibase=mb2)
        r2 = build_key_rotation(s2, robot_did=ROBOT, new_key_multibase=mb3)
        keys = {mb1: kp1.public_key_jwk, mb2: n2.public_key_jwk}
        ok, current = verify_key_history([r1, r2], mb1, keys)
        assert ok is True
        assert current == mb3


# ---------------------------------------------------------------------------
# Decommission
# ---------------------------------------------------------------------------


class TestDecommission:
    def test_build_and_verify(self):
        kp, authority = _party("authority.example.com")
        d = build_decommission(
            authority, robot_did=ROBOT, reason="end of service life", final_disposition="recycled"
        )
        assert "RobotDecommissionCredential" in d["type"]
        ok, subject = verify_decommission(d, kp.public_key_jwk)
        assert ok is True
        assert subject["reason"] == "end of service life"
        assert subject["finalDisposition"] == "recycled"

    def test_trusted_authority_enforced(self):
        kp, authority = _party("authority.example.com")
        d = build_decommission(authority, robot_did=ROBOT, reason="scrapped")
        ok, _ = verify_decommission(d, kp.public_key_jwk, trusted_authorities={authority.get_did()})
        assert ok is True
        ok, _ = verify_decommission(d, kp.public_key_jwk, trusted_authorities={"did:web:other"})
        assert ok is False

    def test_reason_required(self):
        _, authority = _party("authority.example.com")
        with pytest.raises(RoboticsError):
            build_decommission(authority, robot_did=ROBOT, reason="")

    def test_wrong_key_fails(self):
        _, authority = _party("authority.example.com")
        other = generate_identity(domain="x.example.com")
        d = build_decommission(authority, robot_did=ROBOT, reason="scrapped")
        ok, _ = verify_decommission(d, other.public_key_jwk)
        assert ok is False
