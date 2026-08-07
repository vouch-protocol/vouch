# vouch_ros2 — the Vouch accountability loop as a ROS 2 node

> **Status: unbuilt — not yet verified against a ROS runtime.** The package is
> complete and its decision logic is covered by tests that need neither ROS nor
> a robot, but `colcon build`, `ros2 launch` and `ros2 run` have not been
> executed against it. A first real build should confirm: dotted parameter
> names (`scope.max_force_n`) declaring and reading back under rclpy, the
> `ParameterValue(..., value_type=...)` coercion in the launch file, the
> nested-YAML to dotted-parameter mapping, and transient-local QoS delivering
> the startup attestation to late joiners. Treat it as reviewed source, not as
> a running node, until that has happened.

`vouch_ros2` puts the Vouch accountability loop between a planner and a robot's
actuators. It is the ROS 2 packaging of
[`examples/robotics_vla_accountability_loop.py`](../../examples/robotics_vla_accountability_loop.py):

1. **Provenance on load.** On startup the node signs a
   `ModelProvenanceAttestation` recording the planner/model, weights hash,
   safety policy and config in use, and publishes it latched on
   `vouch/provenance`.
2. **Pre-actuation scope gate.** Every action the planner proposes is checked
   with `check_physical_action` against a signed `PhysicalCapabilityScope`
   *before* it can reach the actuators. Only allowed actions are republished on
   the actuator topic; deny reasons go out on a separate topic and nothing
   actuates.
3. **Tamper-evident black box.** Every decision, allowed or denied, is appended
   to an encrypted, hash-linked `BlackBoxLog`. Anyone can verify the chain;
   only a key holder can read the payloads.

```
  planner ──▶ /planner/proposed_action ──▶ ┌──────────────────┐ ──▶ /actuator/action ──▶ actuators
                                           │ vouch_action_gate│ ──▶ /vouch/denials
                                           │  scope gate      │ ──▶ /vouch/provenance   (latched)
                                           └──────────────────┘ ──▶ /vouch/blackbox_head (latched)
                                                    │
                                                    ▼
                                            black box (JSONL)
```

## Why ROS 2 Jazzy

This package targets **ROS 2 Jazzy Jalisco**. Jazzy's Tier 1 platform is Ubuntu
24.04 Noble, which is what this repository's container runs. Humble Hawksbill —
the previous LTS — targets Ubuntu 22.04 Jammy and is not installable on Noble
without building from source, so Jazzy is the right target here. The package is
pure `ament_python` with no C++ or `rosidl` code generation and depends only on
`rclpy` and `std_msgs`, so it should also build unchanged on Humble (22.04) and
Kilted if you need those.

## Message format

Every topic carries `std_msgs/msg/String` whose `data` is a JSON object. This
keeps the package a pure `ament_python` build with no interface generation, and
lets you bridge to whatever action type your stack already uses with a small
adapter node rather than adopting a new `.msg`.

A proposed action (`proposed_action_topic`) — every field optional; `snake_case`
or `camelCase` both accepted:

```json
{
  "action_id": "a-17",
  "task": "pick up the cup",
  "force_n": 20.0,
  "speed_mps": 0.3,
  "near_humans": true,
  "zone": "cell-3",
  "time_hm": "09:30"
}
```

An **allowed** action is republished verbatim on `allowed_action_topic` with one
field added, linking it to its black-box entry:

```json
{ "...": "the planner's own payload", "vouchEntryHash": "u3Qy..." }
```

A **denied** action publishes on `denial_topic` and reaches no actuator:

```json
{
  "actionId": "a-19",
  "task": "sprint to the dock",
  "zone": "cell-3",
  "speedMps": 2.5,
  "nearHumans": true,
  "reasons": ["near_humans speed_exceeded: 2.5 m/s > 0.5 m/s"],
  "vouchEntryHash": "uJk2..."
}
```

An unparsable payload is denied too: the node never actuates a message it could
not understand.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `proposed_action_topic` | `planner/proposed_action` | Planner output the gate subscribes to. |
| `allowed_action_topic` | `actuator/action` | Where allowed actions are republished. |
| `denial_topic` | `vouch/denials` | Where deny reasons are published. |
| `provenance_topic` | `vouch/provenance` | Latched startup attestation. |
| `blackbox_head_topic` | `vouch/blackbox_head` | Latched chain head + allow/deny counts. |
| `queue_depth` | `10` | Pub/sub queue depth. |
| `scope.max_force_n` | `80.0` | Force cap, newtons. Negative = unbounded. |
| `scope.max_speed_mps` | `1.5` | Speed cap, m/s. Negative = unbounded. |
| `scope.max_speed_near_humans_mps` | `0.5` | Slower cap applied when `near_humans`. |
| `scope.allowed_zones` | `['cell-3']` | Zone ids the robot may act in. Empty = unrestricted. |
| `scope.shift_windows_json` | `""` | JSON `[{"start":"HH:MM","end":"HH:MM"}]`. |
| `identity.did` | `""` | Robot DID. |
| `identity.private_key_jwk` | `""` | Ed25519 private key JWK that signs the attestation. |
| `blackbox.key_hex` | `""` | 32-byte AES-256 key, 64 hex chars. |
| `blackbox.key_file` | `""` | File holding that hex key instead. |
| `blackbox.log_path` | `""` | Append each entry as JSONL here. |
| `model.name` | `unnamed-planner` | The planner/model being gated. |
| `model.version` | `""` | Model version. |
| `model.weights_hash` | `""` | Multibase SHA-256 of the weights. |
| `model.weights_file` | `""` | Hash this artifact instead of supplying the digest. |
| `model.safety_policy` | `""` | Active safety-policy id or hash. |
| `model.config_json` | `{}` | Runtime config; its JCS SHA-256 goes in the attestation. |
| `stamp_time_from_clock` | `false` | Stamp untimed actions from the ROS clock, so shift windows bite. |

The scope must bound **at least one** dimension. A gate with an entirely empty
scope would allow everything, so the node refuses to start rather than pretend
to enforce.

Leaving `identity.*`, `blackbox.*` or `model.weights_*` empty is allowed for a
bench run — the node generates ephemeral key material and logs a warning for
each — but nothing signed with an ephemeral key is verifiable once the process
exits. Configure them for anything real.

## Build

`vouch_ros2` needs the `vouch-protocol` Python distribution in the same
interpreter ROS uses. It is on PyPI, not in the ROS index:

```bash
# ROS 2 Jazzy on Ubuntu 24.04 Noble
source /opt/ros/jazzy/setup.bash
python3 -m pip install --break-system-packages vouch-protocol
```

Then build it like any ament_python package. The package root is this
directory, so symlink or copy it into a colcon workspace's `src/`:

```bash
mkdir -p ~/robot_ws/src
ln -s "$(pwd)/integrations/ros2" ~/robot_ws/src/vouch_ros2

cd ~/robot_ws
colcon build --packages-select vouch_ros2 --symlink-install
source install/setup.bash
```

## Run

```bash
ros2 launch vouch_ros2 vouch_action_gate.launch.py \
    proposed_action_topic:=/planner/proposed_action \
    allowed_action_topic:=/actuator/action \
    max_speed_near_humans_mps:=0.5 \
    allowed_zones:="['cell-3']" \
    model_name:="Gemini Robotics ER 2" \
    blackbox_log_path:=/var/log/robot/blackbox.jsonl
```

or without launch:

```bash
ros2 run vouch_ros2 vouch_action_gate --ros-args \
    --params-file src/vouch_ros2/config/gate_params.yaml
```

Poke it by hand:

```bash
# allowed: inside the envelope
ros2 topic pub --once /planner/proposed_action std_msgs/msg/String \
  '{data: "{\"task\": \"pick up the cup\", \"force_n\": 20.0, \"speed_mps\": 0.3, \"near_humans\": true, \"zone\": \"cell-3\"}"}'

# denied: over the near-human speed cap
ros2 topic pub --once /planner/proposed_action std_msgs/msg/String \
  '{data: "{\"task\": \"sprint to the dock\", \"speed_mps\": 2.5, \"near_humans\": true, \"zone\": \"cell-3\"}"}'

ros2 topic echo /actuator/action      # only the allowed one appears
ros2 topic echo /vouch/denials        # the deny reason appears here
ros2 topic echo /vouch/provenance     # the signed startup attestation
```

## Verifying a black box afterwards

`blackbox.log_path` is JSONL, one entry per line, and the chain is verifiable
without the encryption key:

```python
import json
from vouch.robotics import open_entry, verify_blackbox_chain

entries = [json.loads(line) for line in open("blackbox.jsonl")]
print(verify_blackbox_chain(entries))          # (True, None) unless tampered

key = bytes.fromhex(open("blackbox.key").read().strip())
for entry in entries:
    print(entry["event"], open_entry(entry, key))
```

## Tests

The gating, provenance, black-box and parameter logic lives in
`vouch_ros2/core.py` and `vouch_ros2/params.py`, both plain Python with no ROS
imports — `vouch_ros2/node.py` is a thin rclpy shell over them and imports
rclpy guarded. So the loop is testable with pytest alone, with no ROS install
and no physical robot:

```bash
# from the repository root
python -m pytest tests/test_ros2_action_gate.py -v
```

The tests live in the repository's top-level `tests/` directory, matching the
rest of this repo (`pyproject.toml` sets `testpaths = ["tests"]`). They cover
the allow/deny decisions, the signed attestation, the hash chain and its
tamper-detection, the parameter surface, and — statically — the manifest,
entry point and launch file that only a real `colcon build` could exercise.

## Using the core without ROS

Nothing in `vouch_ros2.core` needs ROS, so the same gate can front any control
stack:

```python
from vouch_ros2 import core_from_params, defaults

params = defaults()
params["model.name"] = "Gemini Robotics ER 2"
gate, info = core_from_params(params)

decision = gate.evaluate({"task": "sprint", "speed_mps": 2.5, "near_humans": True})
if decision.allowed:
    actuate(decision.actuator_payload())
else:
    print(decision.denial_payload()["reasons"])
```

## License

Apache-2.0, same as the rest of the Vouch Protocol repository.
