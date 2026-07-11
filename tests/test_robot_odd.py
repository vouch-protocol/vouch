"""Tests for operating-domain (ODD) conformance."""

import unittest
from datetime import datetime, timezone

from vouch import Signer, generate_identity
from vouch.robotics import (
    build_odd_conformance,
    build_odd_credential,
    check_in_domain,
    verify_odd_conformance,
    verify_odd_credential,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

DOMAIN = {
    "allowedZones": ["yard-north", "yard-south"],
    "maxSpeedMps": 3.0,
    "conditions": {"maxWindMps": 12.0, "minVisibilityM": 50.0},
    "timeWindows": [{"start": "06:00", "end": "20:00"}],
}


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestODDCredential(unittest.TestCase):
    def test_credential_round_trips(self):
        op_kp, operator = _party("facility-ops.example.com")
        robot_kp, _ = _party("robot-a.example.com")
        cred = build_odd_credential(
            operator,
            robot_did=robot_kp.did,
            allowed_zones=DOMAIN["allowedZones"],
            max_speed_mps=DOMAIN["maxSpeedMps"],
            conditions=DOMAIN["conditions"],
            time_windows=DOMAIN["timeWindows"],
            valid_from=T0,
        )
        ok, domain = verify_odd_credential(cred, op_kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertEqual(domain["maxSpeedMps"], 3.0)


class TestInDomainCheck(unittest.TestCase):
    def test_in_domain(self):
        observed = {
            "maxSpeedMps": 2.4,
            "zones": ["yard-north"],
            "conditions": {"maxWindMps": 8.0, "minVisibilityM": 120.0},
            "timeHm": "10:30",
        }
        self.assertTrue(check_in_domain(DOMAIN, observed).ok)

    def test_speed_out_of_domain(self):
        res = check_in_domain(DOMAIN, {"maxSpeedMps": 4.5})
        self.assertFalse(res.ok)
        self.assertTrue(any("speed_out_of_domain" in r for r in res.reasons))

    def test_zone_out_of_domain(self):
        res = check_in_domain(DOMAIN, {"zones": ["yard-north", "street"]})
        self.assertFalse(res.ok)
        self.assertTrue(any("zone_out_of_domain" in r for r in res.reasons))

    def test_condition_out_of_domain(self):
        res = check_in_domain(DOMAIN, {"conditions": {"maxWindMps": 20.0, "minVisibilityM": 10.0}})
        self.assertFalse(res.ok)
        self.assertEqual(len(res.reasons), 2)

    def test_time_out_of_domain(self):
        res = check_in_domain(DOMAIN, {"timeHm": "23:00"})
        self.assertFalse(res.ok)
        self.assertTrue(any("time_out_of_domain" in r for r in res.reasons))


class TestConformanceAttestation(unittest.TestCase):
    def setUp(self):
        self.robot_kp, self.robot = _party("robot-a.example.com")

    def test_in_domain_attestation_verifies(self):
        observed = {"maxSpeedMps": 2.0, "zones": ["yard-south"], "timeHm": "09:00"}
        att = build_odd_conformance(
            self.robot,
            robot_did=self.robot_kp.did,
            domain=DOMAIN,
            observed=observed,
            interval_index=0,
            attested_at=T0,
        )
        ok, subject = verify_odd_conformance(att, self.robot_kp.public_key_jwk, domain=DOMAIN)
        self.assertTrue(ok)
        self.assertTrue(subject["inDomain"])

    def test_out_of_domain_attestation_is_honest(self):
        observed = {"maxSpeedMps": 5.0, "zones": ["street"], "timeHm": "23:30"}
        att = build_odd_conformance(
            self.robot,
            robot_did=self.robot_kp.did,
            domain=DOMAIN,
            observed=observed,
            interval_index=1,
            attested_at=T0,
        )
        ok, subject = verify_odd_conformance(att, self.robot_kp.public_key_jwk, domain=DOMAIN)
        self.assertTrue(ok)
        self.assertFalse(subject["inDomain"])

    def test_forged_in_domain_verdict_rejected(self):
        observed = {"maxSpeedMps": 5.0, "zones": ["street"]}
        att = build_odd_conformance(
            self.robot,
            robot_did=self.robot_kp.did,
            domain=DOMAIN,
            observed=observed,
            interval_index=2,
            attested_at=T0,
        )
        # Tamper the verdict to claim in-domain despite out-of-domain observations.
        att["credentialSubject"]["inDomain"] = True
        ok, _ = verify_odd_conformance(att, self.robot_kp.public_key_jwk, domain=DOMAIN)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
