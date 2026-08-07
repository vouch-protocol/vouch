"""Tests for the robotics examples (examples/robotics_ai_act_evidence_pack.py,
examples/robotics_vla_accountability_loop.py, and
examples/robotics_openvla_gated_loop.py).

Mirrors the example-loading convention used by test_fastapi_credential_gate.py:
the example modules are loaded from the examples/ directory and their helper
functions are exercised directly, so the examples stay runnable scripts while
their logic remains testable.
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

from vouch.robotics import (
    verify_blackbox_chain,
    verify_conformance_attestation,
    verify_provenance_attestation,
)
from vouch.robotics.blackbox import BlackBoxLog

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _load_example(name):
    spec = importlib.util.spec_from_file_location(name, EXAMPLES_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence_pack = _load_example("robotics_ai_act_evidence_pack")
vla_loop = _load_example("robotics_vla_accountability_loop")
# Imports without torch/transformers installed: every heavy import in that
# example is deferred into the function that needs it, so the pure helpers
# (the action mapping, the weights hash, the gate loop) stay testable in CI.
openvla_loop = _load_example("robotics_openvla_gated_loop")


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


class TestOpenVlaGatedLoop(unittest.TestCase):
    """
    The OpenVLA example without OpenVLA: these cover the parts that do not need
    weights -- the action-vector mapping, the weights hash, provenance, and the
    gate loop. What a real checkpoint does is not asserted here.
    """

    @classmethod
    def setUpClass(cls):
        cls.robot_kp, cls.robot = openvla_loop.make_party("ar7.example.com")

    def _mapped(self, vector, **kwargs):
        return openvla_loop.action_vector_to_physical_action(vector, **kwargs)

    def test_skips_cleanly_when_dependencies_are_absent(self):
        # In an environment without the `openvla` extra the example must report
        # why and exit 0 rather than trying to fetch 16 GB of weights.
        missing = openvla_loop.missing_dependencies()
        reason = openvla_loop.unavailable_reason()
        if missing:
            self.assertIsNotNone(reason)
            for distribution in missing:
                self.assertIn(distribution, reason)
            self.assertEqual(openvla_loop.main(), 0)

    def test_speed_is_translation_magnitude_over_the_control_period(self):
        # 3-4-5: |(0.3, 0.4, 0)| = 0.5 m over a 0.2 s period -> 2.5 m/s.
        action = self._mapped([0.3, 0.4, 0.0, 0.0, 0.0, 0.0, 1.0], zone="cell-3")
        self.assertAlmostEqual(action.speed_mps, 2.5)
        # Rotation deltas are deliberately excluded from the speed figure.
        rotating = self._mapped([0.3, 0.4, 0.0, 1.0, -2.0, 0.5, 1.0], zone="cell-3")
        self.assertAlmostEqual(rotating.speed_mps, 2.5)

    def test_force_comes_from_the_gripper_axis_and_is_clamped(self):
        # Pin the convention (0 = closed) so this asserts the ramp itself. The
        # default is deliberately NOT this ramp: see TestOpenVlaGripperConvention.
        max_n = openvla_loop.MAX_GRIP_FORCE_N
        closed_at_zero = {"gripper_closed_at": 0.0}
        self.assertAlmostEqual(self._mapped([0, 0, 0, 0, 0, 0, 1.0], **closed_at_zero).force_n, 0.0)
        self.assertAlmostEqual(
            self._mapped([0, 0, 0, 0, 0, 0, 0.0], **closed_at_zero).force_n, max_n
        )
        self.assertAlmostEqual(
            self._mapped([0, 0, 0, 0, 0, 0, 0.5], **closed_at_zero).force_n, max_n / 2
        )
        # Out-of-range de-normalisation must not produce a negative force that
        # slips past the force check, nor one above the calibration constant.
        self.assertAlmostEqual(self._mapped([0, 0, 0, 0, 0, 0, 1.7], **closed_at_zero).force_n, 0.0)
        self.assertAlmostEqual(
            self._mapped([0, 0, 0, 0, 0, 0, -0.5], **closed_at_zero).force_n, max_n
        )

    def test_zone_and_near_humans_come_from_the_caller_not_the_vector(self):
        vector = [0.0] * 6 + [1.0]
        self.assertIsNone(self._mapped(vector).zone)
        self.assertFalse(self._mapped(vector).near_humans)
        action = self._mapped(vector, zone="cell-3", near_humans=True)
        self.assertEqual(action.zone, "cell-3")
        self.assertTrue(action.near_humans)

    def test_malformed_vectors_are_rejected(self):
        with self.assertRaises(ValueError):
            self._mapped([0.0, 0.0, 0.0])
        with self.assertRaises(ValueError):
            self._mapped([0.0] * 8)
        with self.assertRaises(ValueError):
            self._mapped([0.0] * 6 + [1.0], control_period_s=0)

    def test_weights_hash_covers_real_file_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sub").mkdir()
            (root / "model-00001.safetensors").write_bytes(b"A" * 1000)
            (root / "sub" / "model-00002.bin").write_bytes(b"B" * 10)
            (root / "config.json").write_text("{}")  # not a weight file

            files = openvla_loop.weight_files(root)
            self.assertEqual(
                [p.name for p in files], ["model-00001.safetensors", "model-00002.bin"]
            )

            hashed = openvla_loop.hash_weight_files(files, root)
            self.assertTrue(hashed.startswith("u"))
            self.assertEqual(len(hashed), 44)  # multibase base64url SHA-256, unpadded
            # Chunking is an implementation detail, not part of the hash.
            self.assertEqual(openvla_loop.hash_weight_files(files, root, chunk_size=7), hashed)

            (root / "model-00001.safetensors").write_bytes(b"A" * 999 + b"C")
            changed = openvla_loop.hash_weight_files(openvla_loop.weight_files(root), root)
            self.assertNotEqual(changed, hashed)

    def test_weight_files_handles_the_symlinked_hugging_face_cache(self):
        # The real HF cache does not store shards inside the snapshot directory:
        # it symlinks snapshots/<rev>/<file> out to ../../blobs/<sha>. Resolving
        # those symlinks escapes the snapshot root, so hashing must use the
        # in-snapshot path. This is a regression guard for that layout.
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            blobs = cache / "blobs"
            snapshot = cache / "snapshots" / "abc123"
            blobs.mkdir(parents=True)
            snapshot.mkdir(parents=True)
            (blobs / "deadbeef").write_bytes(b"WEIGHTS-A")
            os.symlink("../../blobs/deadbeef", snapshot / "model.safetensors")

            files = openvla_loop.weight_files(snapshot)
            self.assertEqual([p.name for p in files], ["model.safetensors"])
            hashed = openvla_loop.hash_weight_files(files, snapshot)
            self.assertTrue(hashed.startswith("u"))

    def test_provenance_carries_the_real_weights_hash(self):
        weights_hash = openvla_loop.digest(b"stand-in-for-real-weight-bytes")
        ok, attestation, subject = openvla_loop.load_model_with_provenance(
            self.robot, self.robot_kp.did, self.robot_kp.public_key_jwk, weights_hash=weights_hash
        )
        self.assertTrue(ok)
        self.assertEqual(subject["vla"]["modelName"], openvla_loop.VLA_MODEL_NAME)
        self.assertEqual(subject["vla"]["weightsHash"], weights_hash)
        self.assertIn("proof", attestation)

        # The attested config pins the values the action mapping depends on, so
        # changing the control period invalidates the attestation.
        drifted = dict(openvla_loop.vla_config())
        drifted["controlPeriodS"] = openvla_loop.CONTROL_PERIOD_S * 2
        ok, _ = verify_provenance_attestation(
            attestation, self.robot_kp.public_key_jwk, config=drifted
        )
        self.assertFalse(ok)

    def _run_loop(self, proposals):
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
        decisions = openvla_loop.run_accountability_loop(scope, blackbox, proposals)
        return decisions, blackbox

    def _proposals(self):
        # Stand-ins for what the model would emit: a slow careful grasp, a lunge
        # that breaks the near-humans speed cap, and a step whose zone is out of
        # scope whatever the vector says.
        gentle = [0.02, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2]
        lunge = [0.3, 0.4, 0.0, 0.0, 0.0, 0.0, 1.0]
        return [
            openvla_loop.Proposal(
                "pick up the cup", gentle, self._mapped(gentle, zone="cell-3", near_humans=True)
            ),
            openvla_loop.Proposal(
                "move to the dock", lunge, self._mapped(lunge, zone="cell-3", near_humans=True)
            ),
            openvla_loop.Proposal(
                "fetch from the loading bay", gentle, self._mapped(gentle, zone="loading-bay")
            ),
        ]

    def test_gate_allows_safe_and_denies_unsafe_proposals(self):
        decisions, _ = self._run_loop(self._proposals())
        by_task = {task: result for task, result in decisions}
        self.assertTrue(by_task["pick up the cup"].ok)
        self.assertFalse(by_task["move to the dock"].ok)
        self.assertTrue(any("speed_exceeded" in r for r in by_task["move to the dock"].reasons))
        self.assertFalse(by_task["fetch from the loading bay"].ok)
        self.assertTrue(
            any(
                r.startswith("zone_not_allowed")
                for r in by_task["fetch from the loading bay"].reasons
            )
        )

    def test_blackbox_records_the_raw_action_vector(self):
        proposals = self._proposals()
        _, blackbox = self._run_loop(proposals)
        entries = blackbox.entries()
        self.assertEqual(len(entries), len(proposals))

        # Only a key holder can read it; the recorded vector is what the model
        # emitted, so an investigator can replay the mapping after the fact.
        payload = blackbox.open_entry(entries[1])
        self.assertEqual(payload["actionVector"], proposals[1].vector)
        self.assertEqual(payload["model"], openvla_loop.MODEL_ID)
        self.assertEqual(payload["task"], "move to the dock")

        ok, error = verify_blackbox_chain(entries)
        self.assertTrue(ok, error)

        tampered = [dict(e) for e in entries]
        tampered[1]["event"] = "actuation_allowed"
        ok, error = verify_blackbox_chain(tampered)
        self.assertFalse(ok)
        self.assertIn("tampered", error)


if __name__ == "__main__":
    unittest.main()


class TestOpenVlaGripperConvention(unittest.TestCase):
    """
    Which end of OpenVLA's gripper axis means "closed" is not confirmed against
    the checkpoint, and getting it backwards would make the force estimate
    backwards -- a fully closed gripper would score as exerting no force and the
    gate would allow it. The default must therefore be fail-safe: never below
    either convention.
    """

    def _force(self, gripper, **kw):
        action = openvla_loop.action_vector_to_physical_action(
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, gripper], **kw
        )
        return action.force_n

    def test_unverified_default_never_underestimates_either_convention(self):
        for g in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
            unverified = self._force(g)
            closed_at_zero = self._force(g, gripper_closed_at=0.0)
            closed_at_one = self._force(g, gripper_closed_at=1.0)
            self.assertGreaterEqual(
                unverified + 1e-9,
                max(closed_at_zero, closed_at_one),
                f"gripper={g}: default under-estimates force",
            )

    def test_each_pinned_convention_is_the_expected_ramp(self):
        self.assertAlmostEqual(
            self._force(0.0, gripper_closed_at=0.0), openvla_loop.MAX_GRIP_FORCE_N
        )
        self.assertAlmostEqual(self._force(1.0, gripper_closed_at=0.0), 0.0)
        self.assertAlmostEqual(
            self._force(1.0, gripper_closed_at=1.0), openvla_loop.MAX_GRIP_FORCE_N
        )
        self.assertAlmostEqual(self._force(0.0, gripper_closed_at=1.0), 0.0)

    def test_out_of_range_gripper_is_clamped_not_negative(self):
        self.assertGreaterEqual(self._force(-0.5), 0.0)
        self.assertLessEqual(self._force(1.7), openvla_loop.MAX_GRIP_FORCE_N)

    def test_an_unknown_convention_is_rejected(self):
        with self.assertRaises(ValueError):
            self._force(0.5, gripper_closed_at=0.5)

    def test_the_assumed_convention_is_recorded_in_the_attested_config(self):
        self.assertIn("gripperClosedAt", openvla_loop.vla_config())
        self.assertEqual(
            openvla_loop.vla_config()["gripperClosedAt"], openvla_loop.GRIPPER_CLOSED_AT
        )
