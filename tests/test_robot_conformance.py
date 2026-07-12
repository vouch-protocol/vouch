"""Tests for the robotics regulatory conformance profiles, checker, and attestation."""

import unittest

from vouch import Signer, generate_identity
from vouch.robotics import (
    PROFILES,
    build_conformance_attestation,
    build_physical_scope_credential,
    build_provenance_attestation,
    build_safety_record,
    check_conformance,
    mint_robot_identity,
    profile,
    report_digest,
    verify_conformance_attestation,
)
from vouch.robotics.conformance import _path_value
from vouch.robotics.identity import RoboticsError, SoftwareRootOfTrust
from vouch.robotics.safety_record import SafetyEventLog


def _party(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _full_credential_set(robot, robot_did, authority):
    root = SoftwareRootOfTrust(kind="TPM")
    identity = mint_robot_identity(
        robot, root, make="Acme", model="AR-7", serial="SN-1", owner="did:web:owner.example.com"
    )
    config = {"temperature": 0.0}
    prov = build_provenance_attestation(
        robot,
        robot_did=robot_did,
        model_name="OpenVLA-7B",
        weights_hash="uW",
        safety_policy="uP",
        config=config,
        version="1.0",
    )
    scope = build_physical_scope_credential(
        robot,
        subject_did=robot_did,
        max_force_n=80.0,
        max_speed_mps=1.5,
        max_speed_near_humans_mps=0.25,
        allowed_zones=["cell-3"],
    )
    log = SafetyEventLog()
    log.append("near_miss", severity="low")
    record = build_safety_record(authority, robot_did=robot_did, summary=log.summarize())
    return [identity, prov, scope, record]


class TestProfiles(unittest.TestCase):
    def test_all_profiles_are_well_formed(self):
        for prof in PROFILES.values():
            self.assertIn("regime", prof)
            self.assertTrue(prof["requirements"])
            for req in prof["requirements"]:
                for key in ("id", "clause", "title", "credential", "fields"):
                    self.assertIn(key, req)

    def test_profile_lookup_and_unknown(self):
        self.assertEqual(profile("iso-10218")["version"], "2011")
        with self.assertRaises(RoboticsError):
            profile("does-not-exist")


class TestChecker(unittest.TestCase):
    def setUp(self):
        self.robot_kp, self.robot = _party("ar7.example.com")
        _, self.authority = _party("authority.example.com")
        self.creds = _full_credential_set(self.robot, self.robot_kp.did, self.authority)

    def test_full_set_conforms_to_eu_ai_act(self):
        report = check_conformance(self.creds, "eu-ai-act-high-risk")
        self.assertTrue(report["conforms"])
        self.assertEqual(report["satisfiedCount"], report["totalCount"])
        self.assertTrue(all(r["satisfied"] for r in report["requirements"]))

    def test_full_set_conforms_to_iso_10218(self):
        self.assertTrue(check_conformance(self.creds, "iso-10218")["conforms"])

    def test_missing_credential_fails_its_requirement(self):
        # Drop the safety record: the record-keeping requirement should fail.
        without_record = self.creds[:-1]
        report = check_conformance(without_record, "eu-ai-act-high-risk")
        self.assertFalse(report["conforms"])
        failed = [r for r in report["requirements"] if not r["satisfied"]]
        self.assertEqual([r["id"] for r in failed], ["eu-aia-record-keeping"])

    def test_missing_field_fails_even_when_credential_present(self):
        # A scope without the near-human cap fails the AI Act human-oversight clause.
        scope_no_human = build_physical_scope_credential(
            self.robot,
            subject_did=self.robot_kp.did,
            max_force_n=80.0,
            max_speed_mps=1.5,
            allowed_zones=["cell-3"],
        )
        creds = [c for c in self.creds if "PhysicalCapabilityScope" not in c["type"]]
        creds.append(scope_no_human)
        report = check_conformance(creds, "eu-ai-act-high-risk")
        oversight = next(r for r in report["requirements"] if r["id"] == "eu-aia-human-oversight")
        self.assertFalse(oversight["satisfied"])

    def test_empty_set_conforms_to_nothing(self):
        report = check_conformance([], "ul-3300")
        self.assertEqual(report["satisfiedCount"], 0)
        self.assertFalse(report["conforms"])

    def test_report_is_deterministic(self):
        a = check_conformance(self.creds, "iso-ts-15066")
        b = check_conformance(self.creds, "iso-ts-15066")
        self.assertEqual(report_digest(a), report_digest(b))

    def test_path_value_helper(self):
        subject = {"physicalScope": {"maxForceN": 80.0, "allowedZones": []}}
        self.assertEqual(_path_value(subject, "physicalScope.maxForceN"), 80.0)
        self.assertIsNone(_path_value(subject, "physicalScope.missing"))
        self.assertIsNone(_path_value(subject, "nope.deep"))


class TestAttestation(unittest.TestCase):
    def setUp(self):
        self.robot_kp, self.robot = _party("ar7.example.com")
        self.auth_kp, self.authority = _party("assessor.example.com")
        self.creds = _full_credential_set(self.robot, self.robot_kp.did, self.authority)

    def test_attestation_roundtrip(self):
        report = check_conformance(self.creds, "iso-10218")
        att = build_conformance_attestation(
            self.authority, robot_did=self.robot_kp.did, report=report
        )
        ok, subject = verify_conformance_attestation(att, self.auth_kp.public_key_jwk)
        self.assertTrue(ok)
        self.assertTrue(subject["conforms"])
        self.assertEqual(subject["profileId"], "iso-10218")
        self.assertEqual(subject["reportDigest"], report_digest(report))

    def test_wrong_key_rejected(self):
        report = check_conformance(self.creds, "iso-10218")
        att = build_conformance_attestation(
            self.authority, robot_did=self.robot_kp.did, report=report
        )
        ok, _ = verify_conformance_attestation(att, self.robot_kp.public_key_jwk)
        self.assertFalse(ok)

    def test_tampered_report_breaks_digest(self):
        report = check_conformance(self.creds, "iso-10218")
        att = build_conformance_attestation(
            self.authority, robot_did=self.robot_kp.did, report=report
        )
        att["credentialSubject"]["report"]["conforms"] = False
        ok, _ = verify_conformance_attestation(att, self.auth_kp.public_key_jwk)
        self.assertFalse(ok)

    def test_report_must_come_from_checker(self):
        with self.assertRaises(RoboticsError):
            build_conformance_attestation(
                self.authority, robot_did=self.robot_kp.did, report={"x": 1}
            )


if __name__ == "__main__":
    unittest.main()
