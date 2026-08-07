"""
``vouch_action_gate``: the ROS 2 node that sits between planner and actuators.

Every message this node handles is a ``std_msgs/String`` carrying JSON, so the
package stays a pure ``ament_python`` build with no ``rosidl`` message
generation and no ``ament_cmake`` dependency. Point it at whatever your planner
already publishes by remapping topics; the payload shape is documented in the
package README.

The node owns no policy. It reads parameters, hands them to
:func:`vouch_ros2.params.core_from_params`, and for each incoming message asks
:class:`vouch_ros2.core.ActionGateCore` for a decision:

  * allowed -> republished on ``allowed_action_topic`` (the actuator side)
  * denied  -> the reasons go out on ``denial_topic``; nothing reaches actuators

rclpy is imported guarded so ``import vouch_ros2`` works on a machine with no
ROS installed and the core stays unit testable.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from .core import Decision
from .params import PARAMETERS, core_from_params

try:  # pragma: no cover - exercised only where ROS 2 is installed
    import rclpy
    from rclpy.node import Node as _RclpyNode
    from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
    from std_msgs.msg import String

    ROS_AVAILABLE = True
    ROS_IMPORT_ERROR: Optional[BaseException] = None
except ImportError as exc:  # pragma: no cover - the no-ROS path taken by tests
    rclpy = None  # type: ignore[assignment]
    String = None  # type: ignore[assignment]
    DurabilityPolicy = HistoryPolicy = QoSProfile = ReliabilityPolicy = None  # type: ignore
    _RclpyNode = object  # type: ignore[assignment,misc]
    ROS_AVAILABLE = False
    ROS_IMPORT_ERROR = exc

NODE_NAME = "vouch_action_gate"

_NO_ROS_HELP = (
    "rclpy is not importable, so the Vouch action gate cannot run as a ROS 2 node. "
    "Source a ROS 2 Jazzy install first (`source /opt/ros/jazzy/setup.bash`). "
    "The gating, provenance and black-box logic in vouch_ros2.core needs no ROS "
    "and can be used directly from plain Python."
)


def require_ros() -> None:
    """Raise a helpful error when rclpy is missing."""
    if not ROS_AVAILABLE:
        raise ImportError(_NO_ROS_HELP) from ROS_IMPORT_ERROR


def _latched_qos(depth: int = 1) -> Any:
    """Transient-local QoS so a late subscriber still receives the attestation."""
    return QoSProfile(
        depth=depth,
        history=HistoryPolicy.KEEP_LAST,
        reliability=ReliabilityPolicy.RELIABLE,
        durability=DurabilityPolicy.TRANSIENT_LOCAL,
    )


class VouchActionGate(_RclpyNode):
    """Gates planner-proposed actions against a signed PhysicalCapabilityScope."""

    def __init__(self) -> None:
        require_ros()
        super().__init__(NODE_NAME)

        for name, default in PARAMETERS:
            self.declare_parameter(name, default)
        params = {name: self.get_parameter(name).value for name, _ in PARAMETERS}

        self.core, info = core_from_params(params, clock=self._clock_hm)
        for warning in info["warnings"]:
            self.get_logger().warn(warning)
        self.get_logger().info(
            f"vouch action gate armed: did={info['did']} scope={json.dumps(info['scope'])} "
            f"provenance_verified={self.core.provenance_verified}"
        )

        depth = int(params["queue_depth"])
        self._allowed_pub = self.create_publisher(String, params["allowed_action_topic"], depth)
        self._denial_pub = self.create_publisher(String, params["denial_topic"], depth)
        self._provenance_pub = self.create_publisher(
            String, params["provenance_topic"], _latched_qos()
        )
        self._head_pub = self.create_publisher(
            String, params["blackbox_head_topic"], _latched_qos()
        )
        self._subscription = self.create_subscription(
            String, params["proposed_action_topic"], self.on_proposed_action, depth
        )

        # Publish the startup attestation once, latched, so anything that joins
        # the graph later can still see what model this robot is running.
        self._provenance_pub.publish(String(data=json.dumps(self.core.provenance)))
        self._publish_head()

        self.get_logger().info(
            f"gating {params['proposed_action_topic']} -> {params['allowed_action_topic']} "
            f"(denials on {params['denial_topic']})"
        )

    # -- callbacks ---------------------------------------------------------

    def on_proposed_action(self, msg: Any) -> None:
        """Gate one proposed action. Only allowed actions reach the actuators."""
        try:
            decision = self.core.evaluate(msg.data)
        except Exception as exc:  # noqa: BLE001 - a bad payload must never actuate
            self.get_logger().error(f"rejecting unparsable proposed action: {exc}")
            self._denial_pub.publish(
                String(data=json.dumps({"reasons": [f"unparsable_action: {exc}"]}))
            )
            return
        self._publish_decision(decision)

    def _publish_decision(self, decision: Decision) -> None:
        if decision.allowed:
            self._allowed_pub.publish(String(data=json.dumps(decision.actuator_payload())))
            self.get_logger().info(f"ALLOW {decision.action.task or decision.action.action_id}")
        else:
            self._denial_pub.publish(String(data=json.dumps(decision.denial_payload())))
            self.get_logger().warn(
                f"DENY {decision.action.task or decision.action.action_id}: "
                f"{'; '.join(decision.reasons)}"
            )
        self._publish_head()

    def _publish_head(self) -> None:
        counts = self.core.counts()
        self._head_pub.publish(
            String(
                data=json.dumps(
                    {
                        "head": self.core.head(),
                        "entries": len(self.core.entries()),
                        "allowed": counts["allowed"],
                        "denied": counts["denied"],
                    }
                )
            )
        )

    def _clock_hm(self) -> str:
        """ "HH:MM" UTC from the ROS clock, for shift-window checks."""
        import datetime

        seconds = self.get_clock().now().nanoseconds / 1e9
        return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc).strftime("%H:%M")

    def report_on_shutdown(self) -> None:
        """Log the final black-box state so an operator sees the chain verdict."""
        chain_ok, error = self.core.verify_chain()
        counts = self.core.counts()
        self.get_logger().info(
            f"black box: entries={len(self.core.entries())} allowed={counts['allowed']} "
            f"denied={counts['denied']} chain_verifies={chain_ok}"
            + (f" ({error})" if error else "")
        )


def main(args: Optional[list] = None) -> None:
    """Console entry point (``ros2 run vouch_ros2 vouch_action_gate``)."""
    require_ros()
    rclpy.init(args=args)
    node = VouchActionGate()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.report_on_shutdown()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


__all__ = ["NODE_NAME", "ROS_AVAILABLE", "VouchActionGate", "main", "require_ros"]


if __name__ == "__main__":
    main()
