"""Tests for robot-to-infrastructure bounded access."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    attenuates_grant,
    authorize_access,
    build_access_grant,
    build_access_request,
    verify_access_grant,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
IN_WINDOW = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
AFTER = datetime(2026, 1, 1, 2, 0, 0, tzinfo=timezone.utc)


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestAccessGrant(unittest.TestCase):
    def setUp(self):
        self.op_kp, self.operator = _party("facility-ops.example.com")
        self.robot_kp, self.robot = _party("robot-a.example.com")
        self.robot_did = self.robot_kp.did

    def _grant(self):
        return build_access_grant(
            self.operator,
            robot_did=self.robot_did,
            resource="door-3",
            operations=["open", "close"],
            zone="cell-3",
            valid_seconds=3600,
            granted_at=T0,
        )

    def test_grant_verifies_in_window(self):
        ok, subject = verify_access_grant(self._grant(), self.op_kp.public_key_jwk, now=IN_WINDOW)
        self.assertTrue(ok)
        self.assertEqual(subject["resource"], "door-3")

    def test_grant_out_of_window_rejected(self):
        ok, _ = verify_access_grant(self._grant(), self.op_kp.public_key_jwk, now=AFTER)
        self.assertFalse(ok)

    def test_grant_wrong_operator_key_rejected(self):
        other_kp, _ = _party("stranger.example.com")
        ok, _ = verify_access_grant(self._grant(), other_kp.public_key_jwk, now=IN_WINDOW)
        self.assertFalse(ok)


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.op_kp, self.operator = _party("facility-ops.example.com")
        self.robot_kp, self.robot = _party("robot-a.example.com")
        self.robot_did = self.robot_kp.did
        self.grant = build_access_grant(
            self.operator,
            robot_did=self.robot_did,
            resource="door-3",
            operations=["open", "close"],
            zone="cell-3",
            valid_seconds=3600,
            granted_at=T0,
        )

    def _request(self, operation="open", resource="door-3"):
        return build_access_request(
            self.robot,
            robot_did=self.robot_did,
            resource=resource,
            operation=operation,
            requested_at=IN_WINDOW,
        )

    def test_permitted_operation_authorized(self):
        res = authorize_access(
            self.grant,
            self._request("open"),
            self.op_kp.public_key_jwk,
            self.robot_kp.public_key_jwk,
            now=IN_WINDOW,
        )
        self.assertTrue(res.ok)
        self.assertEqual(res.reasons, [])

    def test_operation_not_in_grant_refused(self):
        res = authorize_access(
            self.grant,
            self._request("unlock_admin"),
            self.op_kp.public_key_jwk,
            self.robot_kp.public_key_jwk,
            now=IN_WINDOW,
        )
        self.assertFalse(res.ok)
        self.assertIn("operation not permitted by the grant", res.reasons)

    def test_wrong_resource_refused(self):
        res = authorize_access(
            self.grant,
            self._request("open", resource="door-9"),
            self.op_kp.public_key_jwk,
            self.robot_kp.public_key_jwk,
            now=IN_WINDOW,
        )
        self.assertFalse(res.ok)
        self.assertIn("grant and request name different resources", res.reasons)

    def test_out_of_window_refused(self):
        res = authorize_access(
            self.grant,
            self._request("open"),
            self.op_kp.public_key_jwk,
            self.robot_kp.public_key_jwk,
            now=AFTER,
        )
        self.assertFalse(res.ok)

    def test_request_from_a_different_robot_refused(self):
        other_kp, other = _party("robot-b.example.com")
        forged = build_access_request(
            other,
            robot_did=other_kp.did,
            resource="door-3",
            operation="open",
            requested_at=IN_WINDOW,
        )
        res = authorize_access(
            self.grant, forged, self.op_kp.public_key_jwk, other_kp.public_key_jwk, now=IN_WINDOW
        )
        self.assertFalse(res.ok)
        self.assertIn("grant and request name different robots", res.reasons)


class TestAttenuation(unittest.TestCase):
    def test_sub_grant_may_only_narrow(self):
        op_kp, operator = _party("facility-ops.example.com")
        _, robot = _party("robot-a.example.com")
        robot_did = robot.get_did()
        parent = build_access_grant(
            operator,
            robot_did=robot_did,
            resource="door-3",
            operations=["open", "close"],
            zone="cell-3",
            valid_seconds=3600,
        )
        narrower = build_access_grant(
            operator,
            robot_did=robot_did,
            resource="door-3",
            operations=["open"],
            zone="cell-3",
            valid_seconds=1800,
        )
        wider = build_access_grant(
            operator,
            robot_did=robot_did,
            resource="door-3",
            operations=["open", "close", "unlock_admin"],
            valid_seconds=1800,
        )
        other_resource = build_access_grant(
            operator,
            robot_did=robot_did,
            resource="door-9",
            operations=["open"],
            valid_seconds=1800,
        )
        self.assertTrue(attenuates_grant(parent, narrower))
        self.assertFalse(attenuates_grant(parent, wider))
        self.assertFalse(attenuates_grant(parent, other_resource))


if __name__ == "__main__":
    unittest.main()
