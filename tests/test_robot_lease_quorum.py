"""
Tests for the delegation lease (offline-verifiable, nesting) and the physical
quorum (M-of-N approvals for high-consequence physical actions).
"""

from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.robotics import (
    PhysicalAction,
    build_action_approval,
    build_delegation_lease,
    lease_permits,
    verify_action_authorization,
    verify_delegation_lease,
)
from vouch.robotics.identity import RoboticsError

ROBOT = "did:web:robot.example.com"


def _signer(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


@pytest.fixture
def authority():
    return _signer("fleet-authority.example.com")


def _scope(force=80.0, speed=1.5, zones=("cell-3",)):
    return {
        "maxForceN": force,
        "maxSpeedMps": speed,
        "maxSpeedNearHumansMps": 0.25,
        "allowedZones": list(zones),
    }


# ---------------------------------------------------------------------------
# Delegation lease
# ---------------------------------------------------------------------------


class TestDelegationLease:
    def test_build_and_verify_offline(self, authority):
        kp, s = authority
        lease = build_delegation_lease(
            s, robot_did=ROBOT, lease_id="lease-1", scope=_scope(), valid_seconds=600
        )
        assert "DelegationLeaseCredential" in lease["type"]
        ok, subject = verify_delegation_lease(lease, kp.public_key_jwk)
        assert ok is True
        assert subject["leaseId"] == "lease-1"

    def test_expired_lease_fails(self, authority):
        kp, s = authority
        past = datetime(2026, 1, 1, tzinfo=timezone.utc)
        lease = build_delegation_lease(
            s, robot_did=ROBOT, lease_id="l", scope=_scope(), valid_seconds=60, valid_from=past
        )
        ok, _ = verify_delegation_lease(lease, kp.public_key_jwk, now=past + timedelta(seconds=120))
        assert ok is False

    def test_not_yet_valid_fails(self, authority):
        kp, s = authority
        future = datetime(2030, 1, 1, tzinfo=timezone.utc)
        lease = build_delegation_lease(
            s, robot_did=ROBOT, lease_id="l", scope=_scope(), valid_seconds=60, valid_from=future
        )
        ok, _ = verify_delegation_lease(
            lease, kp.public_key_jwk, now=future - timedelta(seconds=60)
        )
        assert ok is False

    def test_wrong_key_fails(self, authority):
        _, s = authority
        other = generate_identity(domain="other.example.com")
        lease = build_delegation_lease(
            s, robot_did=ROBOT, lease_id="l", scope=_scope(), valid_seconds=600
        )
        ok, _ = verify_delegation_lease(lease, other.public_key_jwk)
        assert ok is False

    def test_sub_lease_must_attenuate(self, authority):
        kp, s = authority
        parent = _scope(force=80.0, zones=("cell-3", "cell-4"))
        # a narrower child is accepted
        child_ok = build_delegation_lease(
            s,
            robot_did=ROBOT,
            lease_id="c1",
            scope=_scope(force=40.0, zones=("cell-3",)),
            valid_seconds=600,
            parent_lease_id="p",
        )
        ok, _ = verify_delegation_lease(child_ok, kp.public_key_jwk, parent_scope=parent)
        assert ok is True
        # a wider child (more force, new zone) is rejected
        child_bad = build_delegation_lease(
            s,
            robot_did=ROBOT,
            lease_id="c2",
            scope=_scope(force=120.0, zones=("cell-9",)),
            valid_seconds=600,
            parent_lease_id="p",
        )
        ok, _ = verify_delegation_lease(child_bad, kp.public_key_jwk, parent_scope=parent)
        assert ok is False

    def test_lease_permits_action_within_scope_and_window(self, authority):
        _, s = authority
        lease = build_delegation_lease(
            s, robot_did=ROBOT, lease_id="l", scope=_scope(), valid_seconds=600
        )
        subject = lease["credentialSubject"]
        assert lease_permits(subject, PhysicalAction(force_n=10.0, zone="cell-3"), lease) is True
        assert lease_permits(subject, PhysicalAction(force_n=200.0, zone="cell-3"), lease) is False
        assert lease_permits(subject, PhysicalAction(zone="cell-9"), lease) is False

    def test_build_rejects_bad_inputs(self, authority):
        _, s = authority
        with pytest.raises(RoboticsError):
            build_delegation_lease(
                s, robot_did=ROBOT, lease_id="l", scope=_scope(), valid_seconds=0
            )
        with pytest.raises(RoboticsError):
            build_delegation_lease(
                s, robot_did=ROBOT, lease_id="", scope=_scope(), valid_seconds=60
            )


# ---------------------------------------------------------------------------
# Physical quorum
# ---------------------------------------------------------------------------


class TestPhysicalQuorum:
    def _approvers(self, n):
        out = []
        for i in range(n):
            kp, s = _signer(f"approver-{i}.example.com")
            out.append((kp, s))
        return out

    def test_threshold_met(self):
        approvers = self._approvers(3)
        keys = {s.get_did(): kp.public_key_jwk for kp, s in approvers}
        approvals = [
            build_action_approval(s, action_id="act-1", robot_did=ROBOT) for _, s in approvers[:2]
        ]
        ok, who = verify_action_authorization(
            approvals, action_id="act-1", robot_did=ROBOT, approver_keys=keys, threshold=2
        )
        assert ok is True
        assert len(who) == 2

    def test_threshold_not_met(self):
        approvers = self._approvers(3)
        keys = {s.get_did(): kp.public_key_jwk for kp, s in approvers}
        approvals = [build_action_approval(approvers[0][1], action_id="act-1", robot_did=ROBOT)]
        ok, who = verify_action_authorization(
            approvals, action_id="act-1", robot_did=ROBOT, approver_keys=keys, threshold=2
        )
        assert ok is False
        assert len(who) == 1

    def test_duplicate_approver_counts_once(self):
        approvers = self._approvers(2)
        keys = {s.get_did(): kp.public_key_jwk for kp, s in approvers}
        s0 = approvers[0][1]
        approvals = [
            build_action_approval(s0, action_id="act-1", robot_did=ROBOT),
            build_action_approval(s0, action_id="act-1", robot_did=ROBOT),
        ]
        ok, who = verify_action_authorization(
            approvals, action_id="act-1", robot_did=ROBOT, approver_keys=keys, threshold=2
        )
        assert ok is False
        assert who == sorted({s0.get_did()})

    def test_approver_outside_set_ignored(self):
        approvers = self._approvers(3)
        keys = {s.get_did(): kp.public_key_jwk for kp, s in approvers}
        allowed = {approvers[0][1].get_did(), approvers[1][1].get_did()}
        approvals = [
            build_action_approval(approvers[0][1], action_id="act-1", robot_did=ROBOT),
            build_action_approval(
                approvers[2][1], action_id="act-1", robot_did=ROBOT
            ),  # not allowed
        ]
        ok, who = verify_action_authorization(
            approvals,
            action_id="act-1",
            robot_did=ROBOT,
            approver_keys=keys,
            threshold=2,
            approver_set=allowed,
        )
        assert ok is False
        assert who == [approvers[0][1].get_did()]

    def test_wrong_action_or_robot_ignored(self):
        approvers = self._approvers(2)
        keys = {s.get_did(): kp.public_key_jwk for kp, s in approvers}
        approvals = [
            build_action_approval(approvers[0][1], action_id="act-OTHER", robot_did=ROBOT),
            build_action_approval(approvers[1][1], action_id="act-1", robot_did="did:web:other"),
        ]
        ok, _ = verify_action_authorization(
            approvals, action_id="act-1", robot_did=ROBOT, approver_keys=keys, threshold=1
        )
        assert ok is False

    def test_reject_decision_does_not_count(self):
        approvers = self._approvers(2)
        keys = {s.get_did(): kp.public_key_jwk for kp, s in approvers}
        approvals = [
            build_action_approval(
                approvers[0][1], action_id="act-1", robot_did=ROBOT, decision="reject"
            ),
            build_action_approval(approvers[1][1], action_id="act-1", robot_did=ROBOT),
        ]
        ok, who = verify_action_authorization(
            approvals, action_id="act-1", robot_did=ROBOT, approver_keys=keys, threshold=2
        )
        assert ok is False
        assert len(who) == 1
