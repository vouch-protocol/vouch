"""
Tests for the ROS 2 action-gate package (integrations/ros2).

These run with pytest alone: no ROS 2 install, no DDS, no physical robot. The
package deliberately keeps every decision in `vouch_ros2.core` /
`vouch_ros2.params`, both plain Python, so the gating, provenance and
black-box logic is testable off-robot; `vouch_ros2.node` is a thin rclpy shell
over it and imports rclpy guarded, which is asserted here too.

Mirrors the path-loading convention used by test_examples_robotics.py: the
package lives outside the importable `vouch` tree, so its directory is placed
on sys.path for the duration of the test module.
"""

import ast
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree

ROS2_PKG_DIR = Path(__file__).resolve().parent.parent / "integrations" / "ros2"
if str(ROS2_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(ROS2_PKG_DIR))

import vouch_ros2  # noqa: E402
from vouch_ros2 import node as gate_node  # noqa: E402
from vouch_ros2.core import (  # noqa: E402
    ActionGateCore,
    ActionGateError,
    build_scope,
    build_scope_credential,
    load_blackbox_key,
    load_signer,
    multibase_sha256,
    parse_action,
    scope_from_credential,
)
from vouch_ros2.params import core_from_params, defaults, scope_from_params  # noqa: E402
from vouch.robotics import (
    open_entry,
    verify_blackbox_chain,
    verify_provenance_attestation,
)  # noqa: E402

SCOPE = {
    "maxForceN": 80.0,
    "maxSpeedMps": 1.5,
    "maxSpeedNearHumansMps": 0.5,
    "allowedZones": ["cell-3"],
}

# The same episode the VLA accountability-loop example plans: two actions
# inside the envelope, an over-speed sprint, and an out-of-zone fetch.
EPISODE = [
    {
        "task": "pick up the cup",
        "force_n": 20.0,
        "speed_mps": 0.3,
        "near_humans": True,
        "zone": "cell-3",
    },
    {
        "task": "hand cup to operator",
        "force_n": 10.0,
        "speed_mps": 0.2,
        "near_humans": True,
        "zone": "cell-3",
    },
    {"task": "sprint to the dock", "speed_mps": 2.5, "near_humans": True, "zone": "cell-3"},
    {"task": "fetch from loading bay", "force_n": 15.0, "speed_mps": 0.5, "zone": "loading-bay"},
]

ROS_MODULES = {"rclpy", "std_msgs", "rosidl_runtime_py", "launch", "launch_ros", "rclcpp"}


def _imported_names(path):
    """Every module name a source file imports, from its AST."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
    return names


def make_core(**overrides):
    """An ActionGateCore with a fresh ephemeral identity and black-box key."""
    signer, did, public_key = load_signer()
    kwargs = dict(
        signer=signer,
        robot_did=did,
        scope=dict(SCOPE),
        model_name="Gemini Robotics ER 2",
        weights_hash=multibase_sha256(b"gemini-robotics-er-2-weights"),
        safety_policy=multibase_sha256(b"factory-floor-safety-policy-v3"),
        model_config={"planner": "er-2", "temperature": 0.0},
        model_version="2.0",
        public_key_jwk=public_key,
        blackbox_key=b"\x11" * 32,
    )
    kwargs.update(overrides)
    return ActionGateCore(**kwargs)


class TestPackageImportsWithoutRos(unittest.TestCase):
    """The point of the split: the core imports and runs with no ROS present."""

    def test_core_never_imports_a_ros_module(self):
        # Static check over the import graph, so this holds on a machine that
        # does have ROS installed too.
        for module in (vouch_ros2, vouch_ros2.core, vouch_ros2.params):
            for name in _imported_names(Path(module.__file__)):
                self.assertNotIn(
                    name.split(".")[0],
                    ROS_MODULES,
                    f"{module.__name__} imports {name}; the core must stay ROS-free",
                )
        self.assertTrue(hasattr(vouch_ros2, "ActionGateCore"))

    def test_node_module_imports_whether_or_not_ros_is_present(self):
        # The node module must import even without ROS, so tooling (and this
        # test) can introspect it; without rclpy it simply refuses to run.
        self.assertTrue(hasattr(gate_node, "VouchActionGate"))
        if gate_node.ROS_AVAILABLE:
            self.assertIsNone(gate_node.require_ros())
        else:
            with self.assertRaises(ImportError):
                gate_node.require_ros()

    def test_node_advertises_its_entry_point_name(self):
        self.assertEqual(gate_node.NODE_NAME, "vouch_action_gate")


class TestActionParsing(unittest.TestCase):
    def test_parses_json_string_from_a_string_message(self):
        action = parse_action('{"task": "pick", "speed_mps": 0.3, "zone": "cell-3"}')
        self.assertEqual(action.task, "pick")
        self.assertEqual(action.speed_mps, 0.3)
        self.assertEqual(action.zone, "cell-3")

    def test_accepts_camel_case_from_a_javascript_planner(self):
        action = parse_action({"speedMps": 2.0, "nearHumans": True, "forceN": 5, "task": "x"})
        self.assertEqual(action.speed_mps, 2.0)
        self.assertEqual(action.force_n, 5.0)
        self.assertTrue(action.near_humans)

    def test_rejects_unparsable_payloads(self):
        with self.assertRaises(ActionGateError):
            parse_action("not json")
        with self.assertRaises(ActionGateError):
            parse_action("[1, 2, 3]")
        with self.assertRaises(ActionGateError):
            parse_action('{"speed_mps": "fast"}')


class TestGating(unittest.TestCase):
    def setUp(self):
        self.core = make_core()

    def test_in_envelope_action_is_allowed(self):
        decision = self.core.evaluate(EPISODE[0])
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, [])

    def test_over_speed_near_humans_is_denied(self):
        decision = self.core.evaluate(EPISODE[2])
        self.assertFalse(decision.allowed)
        self.assertTrue(any("speed_exceeded" in r for r in decision.reasons))

    def test_out_of_zone_action_is_denied(self):
        decision = self.core.evaluate(EPISODE[3])
        self.assertFalse(decision.allowed)
        self.assertIn("zone_not_allowed: loading-bay", decision.reasons)

    def test_over_force_action_is_denied(self):
        decision = self.core.evaluate({"task": "crush", "force_n": 500.0, "zone": "cell-3"})
        self.assertFalse(decision.allowed)
        self.assertTrue(any("force_exceeded" in r for r in decision.reasons))

    def test_only_allowed_actions_reach_the_actuators(self):
        decisions = [self.core.evaluate(a) for a in EPISODE]
        allowed = [d for d in decisions if d.allowed]
        denied = [d for d in decisions if not d.allowed]
        self.assertEqual(len(allowed), 2)
        self.assertEqual(len(denied), 2)
        for decision in allowed:
            payload = decision.actuator_payload()
            self.assertEqual(payload["task"], decision.action.task)
            self.assertIn("vouchEntryHash", payload)
        for decision in denied:
            with self.assertRaises(ActionGateError):
                decision.actuator_payload()
            self.assertTrue(decision.denial_payload()["reasons"])
        self.assertEqual(self.core.counts(), {"allowed": 2, "denied": 2})

    def test_denial_payload_carries_reasons_and_black_box_link(self):
        decision = self.core.evaluate(EPISODE[3])
        payload = decision.denial_payload()
        self.assertEqual(payload["zone"], "loading-bay")
        self.assertEqual(payload["reasons"], decision.reasons)
        self.assertEqual(payload["vouchEntryHash"], decision.entry["entryHash"])

    def test_shift_window_denies_an_out_of_hours_action(self):
        core = make_core(
            scope=dict(SCOPE, shiftWindows=[{"start": "06:00", "end": "18:00"}]),
            clock=lambda: "23:30",
        )
        decision = core.evaluate(EPISODE[0])
        self.assertFalse(decision.allowed)
        self.assertIn("outside_shift_window: 23:30", decision.reasons)

    def test_refuses_an_empty_scope(self):
        signer, did, _ = load_signer()
        with self.assertRaises(ActionGateError):
            ActionGateCore(
                signer=signer,
                robot_did=did,
                scope={},
                model_name="m",
                weights_hash="u0",
                safety_policy="p",
            )
        with self.assertRaises(ActionGateError):
            build_scope(max_force_n=-1.0, max_speed_mps=-1.0)


class TestProvenance(unittest.TestCase):
    def test_startup_attestation_is_signed_and_verifies(self):
        signer, did, public_key = load_signer()
        config = {"planner": "er-2", "temperature": 0.0}
        core = ActionGateCore(
            signer=signer,
            robot_did=did,
            scope=dict(SCOPE),
            model_name="Gemini Robotics ER 2",
            weights_hash=multibase_sha256(b"weights"),
            safety_policy=multibase_sha256(b"policy"),
            model_config=config,
            model_version="2.0",
            public_key_jwk=public_key,
        )
        self.assertTrue(core.provenance_verified)
        ok, subject = verify_provenance_attestation(core.provenance, public_key, config=config)
        self.assertTrue(ok)
        self.assertEqual(subject["vla"]["modelName"], "Gemini Robotics ER 2")
        self.assertEqual(subject["id"], did)
        self.assertIn("ModelProvenanceAttestation", core.provenance["type"])

    def test_attestation_does_not_verify_under_a_different_config(self):
        core = make_core()
        ok, _ = verify_provenance_attestation(
            core.provenance, load_signer()[2], config={"planner": "someone-else"}
        )
        self.assertFalse(ok)

    def test_scope_credential_round_trips(self):
        signer, did, _ = load_signer()
        credential = build_scope_credential(signer, subject_did=did, scope=dict(SCOPE))
        self.assertEqual(scope_from_credential(credential), SCOPE)
        with self.assertRaises(ActionGateError):
            scope_from_credential({"credentialSubject": {}})


class TestBlackBox(unittest.TestCase):
    def test_every_decision_is_recorded_and_the_chain_verifies(self):
        core = make_core()
        for action in EPISODE:
            core.evaluate(action)
        entries = core.entries()
        # one provenance entry plus one entry per decision
        self.assertEqual(len(entries), len(EPISODE) + 1)
        self.assertEqual(entries[0]["event"], "provenance_recorded")
        self.assertEqual(
            [e["event"] for e in entries[1:]],
            [
                "actuation_allowed",
                "actuation_allowed",
                "actuation_denied",
                "actuation_denied",
            ],
        )
        chain_ok, error = core.verify_chain()
        self.assertTrue(chain_ok, error)
        self.assertEqual(core.head(), entries[-1]["entryHash"])

    def test_rewriting_a_denial_breaks_the_chain(self):
        core = make_core()
        for action in EPISODE:
            core.evaluate(action)
        tampered = core.entries()
        tampered[3]["event"] = "actuation_allowed"
        chain_ok, error = verify_blackbox_chain(tampered)
        self.assertFalse(chain_ok)
        self.assertIsNotNone(error)

    def test_payloads_are_readable_only_with_the_key(self):
        key = b"\x22" * 32
        core = make_core(blackbox_key=key)
        core.evaluate(EPISODE[2])
        entry = core.entries()[-1]
        payload = open_entry(entry, key)
        self.assertEqual(payload["task"], "sprint to the dock")
        self.assertTrue(payload["reasons"])
        self.assertNotIn("sprint", entry["ciphertext"])

    def test_entries_are_appended_to_the_log_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "blackbox.jsonl")
            core = make_core(blackbox_path=path)
            core.evaluate(EPISODE[0])
            core.evaluate(EPISODE[3])
            with open(path, encoding="utf-8") as handle:
                lines = [json.loads(line) for line in handle if line.strip()]
        self.assertEqual(len(lines), 3)
        chain_ok, error = verify_blackbox_chain(lines)
        self.assertTrue(chain_ok, error)

    def test_key_material_is_validated(self):
        self.assertEqual(len(load_blackbox_key()), 32)
        self.assertEqual(load_blackbox_key("aa" * 32), b"\xaa" * 32)
        with self.assertRaises(ActionGateError):
            load_blackbox_key("aa" * 16)
        with self.assertRaises(ActionGateError):
            load_blackbox_key("zz" * 32)
        with self.assertRaises(ActionGateError):
            load_blackbox_key("aa" * 32, "/nonexistent/key")


class TestParameters(unittest.TestCase):
    def test_defaults_declare_every_topic_the_node_uses(self):
        params = defaults()
        for name in (
            "proposed_action_topic",
            "allowed_action_topic",
            "denial_topic",
            "provenance_topic",
            "blackbox_head_topic",
        ):
            self.assertTrue(params[name], f"{name} has no default")
        self.assertEqual(len(params), len(vouch_ros2.PARAMETERS))

    def test_scope_is_built_from_parameters(self):
        params = defaults()
        params["scope.shift_windows_json"] = '[{"start": "06:00", "end": "18:00"}]'
        scope = scope_from_params(params)
        self.assertEqual(scope["maxSpeedNearHumansMps"], 0.5)
        self.assertEqual(scope["allowedZones"], ["cell-3"])
        self.assertEqual(scope["shiftWindows"], [{"start": "06:00", "end": "18:00"}])

    def test_negative_parameter_means_unbounded(self):
        params = defaults()
        params["scope.max_force_n"] = -1.0
        self.assertNotIn("maxForceN", scope_from_params(params))

    def test_malformed_json_parameters_are_rejected(self):
        params = defaults()
        params["scope.shift_windows_json"] = "{not json"
        with self.assertRaises(ActionGateError):
            scope_from_params(params)
        params = defaults()
        params["model.config_json"] = "[1, 2]"
        with self.assertRaises(ActionGateError):
            core_from_params(params)

    def test_core_from_params_gates_end_to_end(self):
        params = defaults()
        params["model.name"] = "Gemini Robotics ER 2"
        params["model.safety_policy"] = "factory-floor-safety-policy-v3"
        core, info = core_from_params(params)
        self.assertTrue(info["did"].startswith("did:"))
        self.assertTrue(info["warnings"], "an unconfigured gate must warn loudly")
        self.assertTrue(core.provenance_verified)
        self.assertTrue(core.evaluate(json.dumps(EPISODE[0])).allowed)
        self.assertFalse(core.evaluate(json.dumps(EPISODE[3])).allowed)
        chain_ok, error = core.verify_chain()
        self.assertTrue(chain_ok, error)

    def test_partial_identity_is_a_configuration_error(self):
        with self.assertRaises(ActionGateError):
            load_signer("", "did:web:robot.example.com")

    def test_supplied_identity_signs_the_attestation(self):
        from vouch import generate_identity

        keypair = generate_identity(domain="ar7.example.com")
        params = defaults()
        params["identity.did"] = keypair.did
        params["identity.private_key_jwk"] = keypair.private_key_jwk
        core, info = core_from_params(params)
        self.assertEqual(info["did"], keypair.did)
        ok, subject = verify_provenance_attestation(
            core.provenance, keypair.public_key_jwk, config=core.model_config
        )
        self.assertTrue(ok)
        self.assertEqual(subject["id"], keypair.did)


class TestAmentPackageMetadata(unittest.TestCase):
    """
    Static checks on the parts that need colcon to exercise for real.

    A colcon build cannot run here, so these assert what can be asserted
    offline: the manifest parses and declares an ament_python build, the
    resource marker exists, the console entry point names something that
    actually exists, and the launch file is valid Python that declares an
    argument for every override it passes.
    """

    def test_manifest_declares_an_ament_python_build(self):
        manifest = ElementTree.parse(ROS2_PKG_DIR / "package.xml").getroot()
        self.assertEqual(manifest.get("format"), "3")
        self.assertEqual(manifest.findtext("name"), "vouch_ros2")
        self.assertEqual(manifest.findtext("buildtool_depend"), "ament_python")
        self.assertEqual(manifest.findtext("export/build_type"), "ament_python")
        exec_depends = {el.text for el in manifest.findall("exec_depend")}
        self.assertIn("rclpy", exec_depends)
        self.assertIn("std_msgs", exec_depends)

    def test_ament_resource_marker_exists(self):
        self.assertTrue((ROS2_PKG_DIR / "resource" / "vouch_ros2").is_file())
        self.assertTrue((ROS2_PKG_DIR / "setup.cfg").is_file())
        self.assertTrue((ROS2_PKG_DIR / "README.md").is_file())

    def test_console_entry_point_resolves(self):
        setup_py = (ROS2_PKG_DIR / "setup.py").read_text(encoding="utf-8")
        self.assertIn("vouch_action_gate = vouch_ros2.node:main", setup_py)
        self.assertTrue(callable(gate_node.main))

    def test_launch_file_parses_and_declares_every_argument_it_uses(self):
        launch_file = ROS2_PKG_DIR / "launch" / "vouch_action_gate.launch.py"
        tree = ast.parse(launch_file.read_text(encoding="utf-8"))
        self.assertTrue(
            any(
                isinstance(n, ast.FunctionDef) and n.name == "generate_launch_description"
                for n in tree.body
            )
        )
        source = launch_file.read_text(encoding="utf-8")
        declared = dict(vouch_ros2.PARAMETERS)
        for _, param, _, _ in _launch_arguments(tree):
            self.assertIn(param, declared, f"launch sets undeclared parameter {param}")
        self.assertIn("params_file", source)


def _launch_arguments(tree):
    """The ARGUMENTS table from the launch module, read statically."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "ARGUMENTS":
            return [
                (
                    element.elts[0].value,
                    element.elts[1].value,
                    element.elts[2].value,
                    None,
                )
                for element in node.value.elts
            ]
    raise AssertionError("launch file has no ARGUMENTS table")


if __name__ == "__main__":
    unittest.main()
