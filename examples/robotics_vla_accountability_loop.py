"""
VLA accountability loop: provenance on load, a pre-actuation scope gate, and a
tamper-evident black box.

A robot driven by a vision-language-action model (here Gemini Robotics ER 2)
composes three Vouch robotics primitives into one accountable control loop:

  1. Provenance on load: before autonomy is enabled, the robot verifies the
     signed ModelProvenanceAttestation for the exact weights and config it is
     about to run.
  2. Pre-actuation scope gate: every action the planner proposes is checked
     against the robot's signed PhysicalCapabilityScope before actuating; an
     over-speed or out-of-zone action is denied, not attempted.
  3. Tamper-evident black box: every decision, allowed or denied, is appended
     to an encrypted, hash-linked black-box log. Anyone can verify the chain;
     only a holder of the key can read the payloads.

Run it:  python examples/robotics_vla_accountability_loop.py
"""

import base64
import hashlib
import os

from vouch import Signer, generate_identity
from vouch.robotics import (
    BlackBoxLog,
    PhysicalAction,
    build_physical_scope_credential,
    build_provenance_attestation,
    check_physical_action,
    verify_blackbox_chain,
    verify_provenance_attestation,
)

VLA_MODEL_NAME = "Gemini Robotics ER 2"
VLA_CONFIG = {"planner": "er-2", "temperature": 0.0, "max_plan_steps": 8}

# What the planner proposes during one task episode. The first two stay inside
# the envelope; the sprint exceeds the near-human speed cap and the loading-bay
# fetch leaves the allowed zone, so the gate must deny both.
PLANNED_ACTIONS = [
    (
        "pick up the cup",
        PhysicalAction(force_n=20.0, speed_mps=0.3, near_humans=True, zone="cell-3"),
    ),
    (
        "hand cup to operator",
        PhysicalAction(force_n=10.0, speed_mps=0.2, near_humans=True, zone="cell-3"),
    ),
    ("sprint to the dock", PhysicalAction(speed_mps=2.5, near_humans=True, zone="cell-3")),
    ("fetch from loading bay", PhysicalAction(force_n=15.0, speed_mps=0.5, zone="loading-bay")),
]


def make_party(domain: str):
    """Generate an identity for one party and wrap it in a Signer."""
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def digest(data: bytes) -> str:
    """Multibase (base64url) SHA-256, the hash form Vouch credentials carry."""
    return "u" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(
        "ascii"
    )


def load_model_with_provenance(robot, robot_did, public_key):
    """Sign the model's provenance and verify it before enabling autonomy."""
    attestation = build_provenance_attestation(
        robot,
        robot_did=robot_did,
        model_name=VLA_MODEL_NAME,
        weights_hash=digest(b"gemini-robotics-er-2-weights"),
        safety_policy=digest(b"factory-floor-safety-policy-v3"),
        config=VLA_CONFIG,
        version="2.0",
    )
    ok, subject = verify_provenance_attestation(attestation, public_key, config=VLA_CONFIG)
    return ok, attestation, subject


def run_accountability_loop(scope, blackbox, actions=PLANNED_ACTIONS):
    """
    Gate each proposed action against the physical scope, record every decision
    in the black box, and return the per-action decisions.
    """
    decisions = []
    for task, action in actions:
        result = check_physical_action(scope, action)
        blackbox.append(
            "actuation_allowed" if result.ok else "actuation_denied",
            {
                "task": task,
                "zone": action.zone,
                "speedMps": action.speed_mps,
                "nearHumans": action.near_humans,
                "reasons": result.reasons,
            },
        )
        decisions.append((task, result))
    return decisions


def main() -> None:
    robot_kp, robot = make_party("ar7.example.com")

    # 1. provenance on load: no verified provenance, no autonomy.
    ok, _attestation, subject = load_model_with_provenance(
        robot, robot_kp.did, robot_kp.public_key_jwk
    )
    print(f"provenance verifies: {ok}  model={subject['vla']['modelName']}")
    if not ok:
        raise SystemExit("refusing to enable autonomy without verified provenance")

    # 2. pre-actuation scope gate, with every decision black-boxed.
    scope_cred = build_physical_scope_credential(
        robot,
        subject_did=robot_kp.did,
        max_force_n=80.0,
        max_speed_mps=1.5,
        max_speed_near_humans_mps=0.5,
        allowed_zones=["cell-3"],
    )
    scope = scope_cred["credentialSubject"]["physicalScope"]
    blackbox = BlackBoxLog(key=os.urandom(32))
    for task, result in run_accountability_loop(scope, blackbox):
        verdict = "ALLOW" if result.ok else "DENY "
        why = f"  ({'; '.join(result.reasons)})" if result.reasons else ""
        print(f"  [{verdict}] {task}{why}")

    # 3. the black box is tamper-evident without the key.
    entries = blackbox.entries()
    chain_ok, error = verify_blackbox_chain(entries)
    print(f"black-box chain verifies: {chain_ok}  entries={len(entries)}")

    # Rewriting history (the denied sprint becomes "allowed") breaks the chain.
    tampered = [dict(e) for e in entries]
    tampered[2]["event"] = "actuation_allowed"
    chain_ok, error = verify_blackbox_chain(tampered)
    print(f"tampered chain detected: {not chain_ok}  ({error})")


if __name__ == "__main__":
    main()
