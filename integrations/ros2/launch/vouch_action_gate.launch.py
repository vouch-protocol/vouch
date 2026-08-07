"""
Launch the Vouch action gate between a planner and a robot's actuators.

    ros2 launch vouch_ros2 vouch_action_gate.launch.py \
        proposed_action_topic:=/planner/proposed_action \
        allowed_action_topic:=/actuator/action \
        blackbox_log_path:=/var/log/robot/blackbox.jsonl

Every launch argument maps to the identically named node parameter, with the
dotted scope/identity/blackbox/model prefixes flattened to underscores (launch
argument names cannot contain dots). Each override is wrapped in a
``ParameterValue`` with an explicit type, because launch substitutions are
strings and the node declares typed parameters.

For anything richer -- shift windows, a full model config -- pass a YAML file:

    ros2 launch vouch_ros2 vouch_action_gate.launch.py params_file:=my_gate.yaml

See config/gate_params.yaml for the shape.
"""

import os
from typing import List

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node
from launch_ros.parameter_descriptions import ParameterValue

PACKAGE = "vouch_ros2"

# (launch argument, node parameter, default, type)
ARGUMENTS = [
    ("proposed_action_topic", "proposed_action_topic", "planner/proposed_action", str),
    ("allowed_action_topic", "allowed_action_topic", "actuator/action", str),
    ("denial_topic", "denial_topic", "vouch/denials", str),
    ("provenance_topic", "provenance_topic", "vouch/provenance", str),
    ("blackbox_head_topic", "blackbox_head_topic", "vouch/blackbox_head", str),
    ("max_force_n", "scope.max_force_n", "80.0", float),
    ("max_speed_mps", "scope.max_speed_mps", "1.5", float),
    ("max_speed_near_humans_mps", "scope.max_speed_near_humans_mps", "0.5", float),
    ("allowed_zones", "scope.allowed_zones", "['cell-3']", List[str]),
    ("shift_windows_json", "scope.shift_windows_json", "", str),
    ("robot_did", "identity.did", "", str),
    ("robot_private_key_jwk", "identity.private_key_jwk", "", str),
    ("blackbox_key_hex", "blackbox.key_hex", "", str),
    ("blackbox_key_file", "blackbox.key_file", "", str),
    ("blackbox_log_path", "blackbox.log_path", "", str),
    ("model_name", "model.name", "unnamed-planner", str),
    ("model_version", "model.version", "", str),
    ("model_weights_hash", "model.weights_hash", "", str),
    ("model_weights_file", "model.weights_file", "", str),
    ("model_safety_policy", "model.safety_policy", "", str),
    ("model_config_json", "model.config_json", "{}", str),
]

DESCRIPTIONS = {
    "proposed_action_topic": "Topic the planner publishes proposed actions on (JSON String).",
    "allowed_action_topic": "Topic allowed actions are republished on, for the actuators.",
    "denial_topic": "Topic deny reasons are published on.",
    "allowed_zones": "YAML list of zone ids the robot may operate in.",
    "blackbox_log_path": "Append each black-box entry to this JSONL file.",
    "model_weights_file": "Weights artifact to hash into the provenance attestation.",
}


def generate_launch_description():
    """Build the launch description for a single gate node."""
    default_params = os.path.join(
        get_package_share_directory(PACKAGE), "config", "gate_params.yaml"
    )

    declarations = [
        DeclareLaunchArgument(arg, default_value=default, description=DESCRIPTIONS.get(arg, ""))
        for arg, _, default, _ in ARGUMENTS
    ]
    declarations.append(
        DeclareLaunchArgument(
            "params_file",
            default_value=default_params,
            description="YAML parameter file applied before the launch-argument overrides.",
        )
    )

    overrides = {
        param: ParameterValue(LaunchConfiguration(arg), value_type=value_type)
        for arg, param, _, value_type in ARGUMENTS
    }

    gate = Node(
        package=PACKAGE,
        executable="vouch_action_gate",
        name="vouch_action_gate",
        output="screen",
        emulate_tty=True,
        parameters=[LaunchConfiguration("params_file"), overrides],
    )

    return LaunchDescription(declarations + [gate])
