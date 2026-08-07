"""Tests for the robotics examples (examples/robotics_ai_act_evidence_pack.py
and examples/robotics_vla_accountability_loop.py).

Mirrors the example-loading convention used by test_fastapi_credential_gate.py:
the example modules are loaded from the examples/ directory and their helper
functions are exercised directly, so the examples stay runnable scripts while
their logic remains testable.
"""

import importlib.util
import os
import unittest
from pathlib import Path

from vouch.robotics import verify_blackbox_chain, verify_conformance_attestation
from vouch.robotics.blackbox import BlackBoxLog

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _load_example(name):
    spec = importlib.util.spec_from_file_location(name, EXAMPLES_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence_pack = _load_example("robotics_ai_act_evidence_pack")
vla_loop = _load_example("robotics_vla_accountability_loop")


class TestEvidencePack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.robot_kp, cls.robot = evidence_pack.make_party("ar7.example.com")
        cls.assessor_kp, cls.assessor = evidence_pack.make_party("assessor.example.com")
        cls.credentials = evidence_pack.build_evidence_pack(
            cls.robot, cls.robot_kp.did, cls.assessor
        )
        cls.reports = evidence_pack.check_all_profiles(cls.credentials)

    def test_covers_all_five_profiles(self):
        self.assertEqual(sorted(self.reports), sorted(evidence_pack.ALL_PROFILE_IDS))
        self.assertEqual(len(self.reports), 5)

    def test_every_profile_conforms(self):
        for pid, report in self.reports.items():
            self.assertTrue(report["conforms"], f"{pid} does not conform: {report}")
            self.assertEqual(report["satisfiedCount"], report["totalCount"])

    def test_base_set_leaves_the_expected_gaps(self):
        base = evidence_pack.build_base_credentials(self.robot, self.robot_kp.did, self.assessor)
        reports = evidence_pack.check_all_profiles(base)
        self.assertFalse(reports["iso-ts-15066"]["conforms"])
        self.assertFalse(reports["ul-3300"]["conforms"])
        self.assertTrue(reports["eu-ai-act-high-risk"]["conforms"])

    def test_every_signed_attestation_verifies(self):
        attestations = evidence_pack.sign_attestations(
            self.assessor, self.robot_kp.did, self.reports
        )
        for pid, attestation in attestations.items():
            ok, subject = verify_conformance_attestation(
                attestation, self.assessor_kp.public_key_jwk
            )
            self.assertTrue(ok, f"{pid} attestation does not verify")
            self.assertTrue(subject["conforms"])
            self.assertEqual(subject["profileId"], pid)

    def test_attestation_rejects_wrong_key(self):
        attestations = evidence_pack.sign_attestations(
            self.assessor, self.robot_kp.did, self.reports
        )
        attestation = attestations["eu-ai-act-high-risk"]
        ok, _ = verify_conformance_attestation(attestation, self.robot_kp.public_key_jwk)
        self.assertFalse(ok)


class TestVlaAccountabilityLoop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.robot_kp, cls.robot = vla_loop.make_party("ar7.example.com")

    def test_provenance_verifies_on_load(self):
        ok, attestation, subject = vla_loop.load_model_with_provenance(
            self.robot, self.robot_kp.did, self.robot_kp.public_key_jwk
        )
        self.assertTrue(ok)
        self.assertEqual(subject["vla"]["modelName"], vla_loop.VLA_MODEL_NAME)
        self.assertIn("proof", attestation)

    def _run_loop(self):
        from vouch.robotics import build_physical_scope_credential

        scope_cred = build_physical_scope_credential(
            self.robot,
            subject_did=self.robot_kp.did,
            max_force_n=80.0,
            max_speed_mps=1.5,
            max_speed_near_humans_mps=0.5,
            allowed_zones=["cell-3"],
        )
        scope = scope_cred["credentialSubject"]["physicalScope"]
        blackbox = BlackBoxLog(key=os.urandom(32))
        decisions = vla_loop.run_accountability_loop(scope, blackbox)
        return decisions, blackbox

    def test_gate_allows_safe_and_denies_unsafe_actions(self):
        decisions, _ = self._run_loop()
        by_task = {task: result for task, result in decisions}
        self.assertTrue(by_task["pick up the cup"].ok)
        self.assertTrue(by_task["hand cup to operator"].ok)
        self.assertFalse(by_task["sprint to the dock"].ok)
        self.assertTrue(any("speed_exceeded" in r for r in by_task["sprint to the dock"].reasons))
        self.assertFalse(by_task["fetch from loading bay"].ok)
        self.assertTrue(
            any(r.startswith("zone_not_allowed") for r in by_task["fetch from loading bay"].reasons)
        )

    def test_blackbox_chain_verifies_and_detects_tampering(self):
        decisions, blackbox = self._run_loop()
        entries = blackbox.entries()
        self.assertEqual(len(entries), len(decisions))

        ok, error = verify_blackbox_chain(entries)
        self.assertTrue(ok, error)

        tampered = [dict(e) for e in entries]
        tampered[2]["event"] = "actuation_allowed"
        ok, error = verify_blackbox_chain(tampered)
        self.assertFalse(ok)
        self.assertIn("tampered", error)


if __name__ == "__main__":
    unittest.main()
