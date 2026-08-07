"""
Vouch accountability gate for ROS 2.

``vouch_ros2.node`` puts the Vouch loop between a planner and a robot's
actuators: a signed model-provenance attestation on startup, a pre-actuation
PhysicalCapabilityScope gate on every proposed action, and a tamper-evident
black box over every allow/deny decision.

Importing this package pulls in **no** ROS dependency: everything here is plain
Python, so the gating logic can be exercised with pytest on a machine without
ROS. ``vouch_ros2.node`` is the only module that imports rclpy, and it does so
lazily.
"""

from .core import (
    ALLOWED_EVENT,
    DENIED_EVENT,
    PROVENANCE_EVENT,
    ActionGateCore,
    ActionGateError,
    Decision,
    ProposedAction,
    build_scope,
    build_scope_credential,
    load_blackbox_key,
    load_signer,
    multibase_sha256,
    parse_action,
    scope_from_credential,
)
from .params import PARAMETERS, core_from_params, defaults, scope_from_params, warnings_for

__version__ = "2.1.0"

__all__ = [
    "ALLOWED_EVENT",
    "DENIED_EVENT",
    "PARAMETERS",
    "PROVENANCE_EVENT",
    "ActionGateCore",
    "ActionGateError",
    "Decision",
    "ProposedAction",
    "__version__",
    "build_scope",
    "build_scope_credential",
    "core_from_params",
    "defaults",
    "load_blackbox_key",
    "load_signer",
    "multibase_sha256",
    "parse_action",
    "scope_from_credential",
    "scope_from_params",
]
