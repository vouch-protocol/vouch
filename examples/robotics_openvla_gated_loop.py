"""
OpenVLA behind the accountability loop: provenance on load, a pre-actuation
scope gate, and a tamper-evident black box -- driven by a real VLA model.

This is the model-in-the-loop variant of
`examples/robotics_vla_accountability_loop.py`. That example ships a hardcoded
list of proposed actions so it runs anywhere with no extra dependencies. This
one replaces the hardcoded list with actual inference from OpenVLA
(`openvla/openvla-7b`, open weights, MIT licence), and runs whatever the model
proposes through the same three primitives:

  1. Provenance on load: a ModelProvenanceAttestation is signed over the
     SHA-256 of the *actual downloaded weight files* and verified before
     autonomy is enabled. No verified provenance, no autonomy.
  2. Pre-actuation scope gate: every action the model proposes is mapped into
     a PhysicalAction and checked against the robot's signed
     PhysicalCapabilityScope *before* actuating. The model does not get to
     decide whether it is inside the envelope.
  3. Tamper-evident black box: every decision, allowed or denied, is appended
     to an encrypted, hash-linked log along with the raw action vector the
     model emitted, so an investigator can later reconstruct exactly what the
     model asked for and what the gate did about it.

Honesty notes, because this example is only useful if its seams are visible:

  - The action-vector -> PhysicalAction mapping is an interpretation, not a
    measurement. Its assumptions are spelled out on
    `action_vector_to_physical_action`; read them before trusting a number it
    produces.
  - `zone` and `near_humans` are NOT model outputs. They come from the robot's
    own state estimator and are passed in by the caller. Letting the model
    supply them would let it talk its way past its own envelope.
  - `trust_remote_code=True` is required by OpenVLA: loading it executes Python
    shipped in the model repo. That is a supply-chain decision. Pin a
    `revision`, review the code, and note that the weights hash recorded here
    covers the weight shards, not those .py files.
  - The demo observation frame is a synthetic placeholder unless you point
    VOUCH_OPENVLA_IMAGE at a real camera frame. Actions predicted from a blank
    image are meaningless as robot behaviour; what the example demonstrates is
    that *whatever* the model emits still has to clear the gate.

Requires the optional `openvla` extra and a locally cached checkpoint (~16 GB);
it never downloads weights on its own. With either missing it prints how to
get them and exits 0, so CI can run it unattended:

    pip install 'vouch-protocol[openvla]'
    huggingface-cli download openvla/openvla-7b

Status: the OpenVLA code path is UNVERIFIED. It has never been executed
against a real checkpoint. Before relying on it, confirm against real weights,
in this order: `predict_action`'s return shape (a batched (1,7) array rather
than 7 floats trips the arity guard), the processor `.to(device, dtype=...)`
convention, the gripper convention for `bridge_orig` (see
`action_vector_to_physical_action` -- the default is fail-safe until pinned),
and CONTROL_PERIOD_S as the dataset's real control rate. Everything that does
not need weights is covered by tests.

Run it:  python examples/robotics_openvla_gated_loop.py
"""

import base64
import hashlib
import importlib.util
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

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

MODEL_ID = "openvla/openvla-7b"
VLA_MODEL_NAME = "OpenVLA 7B"

# OpenVLA's documented prompt form. The model was trained on exactly this
# template; deviating from it degrades the predicted actions.
PROMPT_TEMPLATE = "In: What action should the robot take to {instruction}?\nOut:"

# `predict_action` de-normalises its output with the statistics of one training
# dataset, named by `unnorm_key`. The key selects the action space, so it also
# selects the units the mapping below assumes. `bridge_orig` (BridgeData V2) is
# metres / radians / normalised gripper at roughly 5 Hz.
UNNORM_KEY = "bridge_orig"
CONTROL_PERIOD_S = 0.2

# Calibration constant for the gripper, NOT a model output. See
# `action_vector_to_physical_action`.
MAX_GRIP_FORCE_N = 40.0

# Which end of OpenVLA's gripper axis means "fully closed": 0.0, 1.0, or None
# when it has not been confirmed against the checkpoint in use. None selects the
# fail-safe both-ways reading in action_vector_to_physical_action, which can only
# over-estimate grip force. Pin this once verified.
GRIPPER_CLOSED_AT = None

WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".pth")

# (module to import, distribution to install) for the optional `openvla` extra.
REQUIRED_MODULES = (
    ("torch", "torch"),
    ("transformers", "transformers"),
    ("timm", "timm"),
    ("huggingface_hub", "huggingface-hub"),
    ("PIL", "Pillow"),
)

SKIP_NOTICE = """\
skipping: {reason}

This example drives a real OpenVLA checkpoint. It needs the optional extra and
a locally cached copy of the weights (~16 GB); it never downloads them itself:

    pip install 'vouch-protocol[openvla]'
    huggingface-cli download {model_id}

The same accountability loop, with a scripted planner and no heavy
dependencies, runs anywhere:

    python examples/robotics_vla_accountability_loop.py
"""

# One task episode. The instruction is what the model is asked to do; the zone
# and the near-humans flag are what the ROBOT knows about its own situation and
# are never taken from the model. The loading-bay step is outside the signed
# scope whatever the model emits, so the gate denies it on zone alone.
EPISODE = [
    ("pick up the cup", "cell-3", True),
    ("hand the cup to the operator", "cell-3", True),
    ("move as fast as you can to the dock", "cell-3", True),
    ("fetch the box from the loading bay", "loading-bay", False),
]


@dataclass
class LoadedModel:
    """A loaded OpenVLA checkpoint plus the placement chosen for it."""

    processor: Any
    model: Any
    device: str
    dtype: Any


@dataclass
class Proposal:
    """One episode step: what was asked, what the model emitted, what the gate sees."""

    instruction: str
    vector: List[float]  # the raw 7-DoF OpenVLA output
    action: PhysicalAction  # the same step expressed in Vouch's physical-action schema


def make_party(domain: str):
    """Generate an identity for one party and wrap it in a Signer."""
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


def _multibase(raw: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def digest(data: bytes) -> str:
    """Multibase (base64url) SHA-256, the hash form Vouch credentials carry."""
    return _multibase(hashlib.sha256(data).digest())


def vla_config(revision: Optional[str] = None) -> Dict[str, Any]:
    """
    The runtime config attested alongside the weights. Its JCS hash goes into
    the provenance attestation, so changing the unnorm key, the control period,
    or the gripper calibration invalidates the attestation -- these are exactly
    the values the action mapping depends on.
    """
    config: Dict[str, Any] = {
        "modelId": MODEL_ID,
        "unnormKey": UNNORM_KEY,
        "controlPeriodS": CONTROL_PERIOD_S,
        "maxGripForceN": MAX_GRIP_FORCE_N,
        # Which end of the gripper axis means "closed". null records that the
        # convention was not verified against the checkpoint and the fail-safe
        # both-ways reading was used, so a verifier can tell an assumed run from
        # a pinned one.
        "gripperClosedAt": GRIPPER_CLOSED_AT,
        "doSample": False,
    }
    if revision is not None:
        config["revision"] = revision
    return config


# ---------------------------------------------------------------------------
# Availability: this example must skip cleanly, never download
# ---------------------------------------------------------------------------


def missing_dependencies() -> List[str]:
    """Distributions from the `openvla` extra that are not importable here."""
    missing = []
    for module, distribution in REQUIRED_MODULES:
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):  # a broken/partial install
            found = False
        if not found:
            missing.append(distribution)
    return missing


def unavailable_reason(model_id: str = MODEL_ID) -> Optional[str]:
    """
    Why this example cannot run here, or None if it can. Checks the optional
    dependencies first, then whether the checkpoint is already in the local
    Hugging Face cache -- deliberately without touching the network.
    """
    missing = missing_dependencies()
    if missing:
        return f"missing dependencies: {', '.join(missing)}"
    try:
        resolve_snapshot(model_id)
    except Exception as exc:  # noqa: BLE001 - any resolution failure means "not cached"
        return f"{model_id} is not in the local Hugging Face cache ({type(exc).__name__})"
    return None


# ---------------------------------------------------------------------------
# Real weights, real hash
# ---------------------------------------------------------------------------


def resolve_snapshot(
    model_id: str = MODEL_ID,
    *,
    revision: Optional[str] = None,
    local_files_only: bool = True,
) -> Path:
    """
    Local directory holding the checkpoint. `local_files_only=True` by default,
    so this resolves an already-cached snapshot and raises rather than pulling
    16 GB down on someone who only wanted to run an example.
    """
    from huggingface_hub import snapshot_download

    return Path(
        snapshot_download(model_id, revision=revision, local_files_only=local_files_only)
    ).resolve()


def weight_files(snapshot_dir: Path) -> List[Path]:
    """Every weight shard in the snapshot, ordered by relative path."""
    root = Path(snapshot_dir).resolve()
    files = [p for p in root.rglob("*") if p.is_file() and p.suffix in WEIGHT_SUFFIXES]
    # Order by the path *within* the snapshot. Deliberately not p.resolve():
    # the Hugging Face cache symlinks each snapshot file out to
    # ../../blobs/<sha>, so resolving would escape `root` and relative_to would
    # raise. rglob already yields paths rooted at `root`.
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def hash_weight_files(files: Sequence[Path], root: Path, *, chunk_size: int = 1 << 20) -> str:
    """
    SHA-256 over the real weight bytes, as multibase base64url.

    A tree hash, not a per-file hash: for each shard in relative-path order it
    absorbs the path, the byte length, and the contents, each null-separated, so
    renaming, resharding, or truncating a file all change the result. Streamed
    in chunks because the shards do not fit in memory.

    This covers the weight shards only. Config JSON and the .py files that
    `trust_remote_code` executes are NOT included; pin a revision if you need to
    bind those too (the resolved revision goes into the attested config).
    """
    root = Path(root).resolve()
    hasher = hashlib.sha256()
    for path in files:
        # The in-snapshot path, not the resolved one: the HF cache symlinks
        # shards to blobs outside the snapshot directory (see weight_files).
        name = Path(path).relative_to(root).as_posix()
        hasher.update(name.encode("utf-8") + b"\0")
        hasher.update(str(Path(path).stat().st_size).encode("ascii") + b"\0")
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        hasher.update(b"\0")
    return _multibase(hasher.digest())


def compute_weights_hash(model_id: str = MODEL_ID, **kwargs) -> Tuple[str, Path, List[Path]]:
    """Resolve the cached snapshot and hash its weight shards."""
    snapshot = resolve_snapshot(model_id, **kwargs)
    files = weight_files(snapshot)
    if not files:
        raise FileNotFoundError(f"no weight files ({', '.join(WEIGHT_SUFFIXES)}) under {snapshot}")
    return hash_weight_files(files, snapshot), snapshot, files


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------


def load_openvla(
    model_id: str = MODEL_ID,
    *,
    device: Optional[str] = None,
    revision: Optional[str] = None,
    local_files_only: bool = True,
) -> LoadedModel:
    """
    Load OpenVLA the way its model card documents: AutoProcessor plus
    AutoModelForVision2Seq, both with `trust_remote_code=True` (the checkpoint
    ships its own modelling code, including `predict_action`).

    bfloat16 on CUDA, float32 on CPU. flash-attention-2 is deliberately not
    requested: it is an optional speedup that needs a separate build, and its
    absence must not stop the example. On CPU a 7B model is workable but slow.
    """
    import torch
    from transformers import AutoModelForVision2Seq, AutoProcessor

    if device is None:
        device = "cuda:0" if torch.cuda.is_available() else "cpu"
    dtype = torch.bfloat16 if device.startswith("cuda") else torch.float32

    processor = AutoProcessor.from_pretrained(
        model_id, revision=revision, trust_remote_code=True, local_files_only=local_files_only
    )
    model = AutoModelForVision2Seq.from_pretrained(
        model_id,
        revision=revision,
        torch_dtype=dtype,
        low_cpu_mem_usage=True,
        trust_remote_code=True,
        local_files_only=local_files_only,
    ).to(device)
    model.eval()
    return LoadedModel(processor=processor, model=model, device=device, dtype=dtype)


def observation_image(path: Optional[str] = None, size: Tuple[int, int] = (224, 224)):
    """
    The camera frame handed to the model.

    A real deployment passes the live frame here -- and should attest it with
    `build_perception_attestation` so the black box can be tied to what the
    robot actually saw. Absent VOUCH_OPENVLA_IMAGE this returns a flat grey
    placeholder purely so the example is runnable; predictions from it carry no
    meaning as robot behaviour.
    """
    from PIL import Image

    path = path or os.environ.get("VOUCH_OPENVLA_IMAGE")
    if path:
        return Image.open(path).convert("RGB")
    return Image.new("RGB", size, (127, 127, 127))


def propose_action(loaded: LoadedModel, image, instruction: str, *, unnorm_key=UNNORM_KEY):
    """
    Run one forward pass and return OpenVLA's 7-DoF action as a list of floats.

    `do_sample=False` keeps it greedy, so the same frame and instruction give
    the same action -- an accountability requirement, not a quality one: a
    non-reproducible planner cannot be audited after the fact.
    """
    prompt = PROMPT_TEMPLATE.format(instruction=instruction)
    inputs = loaded.processor(prompt, image).to(loaded.device, dtype=loaded.dtype)
    action = loaded.model.predict_action(**inputs, unnorm_key=unnorm_key, do_sample=False)
    return [float(v) for v in action]


# ---------------------------------------------------------------------------
# The mapping the gate depends on
# ---------------------------------------------------------------------------


def action_vector_to_physical_action(
    vector: Sequence[float],
    *,
    zone: Optional[str] = None,
    near_humans: bool = False,
    control_period_s: float = CONTROL_PERIOD_S,
    max_grip_force_n: float = MAX_GRIP_FORCE_N,
    gripper_closed_at: Optional[float] = GRIPPER_CLOSED_AT,
) -> PhysicalAction:
    """
    Map one OpenVLA action vector into a Vouch PhysicalAction.

    OpenVLA emits, per control step, a 7-vector in the action space of the
    dataset named by `unnorm_key` (here `bridge_orig`, BridgeData V2):

        a = [dx, dy, dz, droll, dpitch, dyaw, gripper]

        dx, dy, dz          end-effector translation delta, METRES, to be
                            applied over one control period
        droll, dpitch, dyaw end-effector rotation delta, RADIANS, same period
        gripper             normalised aperture command in [0, 1],
                            0 = fully closed, 1 = fully open

    The mapping, and every assumption it makes:

      speed_mps = ||(dx, dy, dz)|| / control_period_s
          Assumes the controller executes the commanded delta over exactly one
          control period at constant velocity. Real controllers interpolate, so
          instantaneous peak speed can exceed this average -- treat the number
          as a lower bound on commanded end-effector speed, and set the scope's
          cap with that headroom in mind. It is the speed of the END EFFECTOR,
          not of a mobile base: gating a base-speed cap with this number would
          be comparing two different things.

      force_n = closure(gripper) * max_grip_force_n
          OpenVLA's gripper axis is an aperture/position command, not a force
          command. Converting it to newtons needs a per-gripper calibration
          constant, which is what `max_grip_force_n` is: the force the gripper
          exerts when fully closed on a rigid object, taken from its datasheet.
          The linear interpolation between open and closed is a deliberate
          simplification -- real grippers are non-linear, and the force actually
          delivered depends on the compliance of what is grasped. The result is
          a conservative estimate for gating, never a measurement; a robot with
          a load cell should gate on the measured value instead.

          WHICH END OF THE AXIS MEANS "CLOSED" IS NOT SAFE TO GUESS. OpenVLA's
          documentation describes the gripper axis as normalised to [0, 1], and
          the widely used reading is 0 = closed, 1 = open -- but a fine-tune, a
          different `unnorm_key`, or a binarised gripper can inverate that, and
          getting it backwards means the force estimate is backwards: the gate
          would read a fully closed gripper as exerting no force and allow it.

          So `gripper_closed_at` selects the convention explicitly, and its
          DEFAULT IS FAIL-SAFE rather than a guess:

            None (default)  convention unverified -> closure = max(g, 1 - g),
                            the larger of the two readings. This can only ever
                            OVER-estimate force, so the gate may deny an action
                            it need not, and can never allow one it should deny.
            0.0             0 means closed -> closure = 1 - g
            1.0             1 means closed -> closure = g

          Pin `gripper_closed_at` once the convention is confirmed against the
          actual checkpoint; until then the default trades false denials for the
          guarantee that a closed gripper is never scored as harmless. The value
          in use is recorded in the attested config, so a verifier can see which
          convention the run assumed.

      near_humans, zone
          Not derivable from the vector, and not model outputs. OpenVLA has no
          notion of either. They come from the robot's own state estimator
          (localisation, safety scanners, light curtains) and are passed in by
          the caller. Feeding the model's own belief about its zone into the
          gate would let the model argue its way past the envelope.

    Rotation deltas are deliberately NOT folded into the speed figure. Turning
    an angular delta into a linear speed needs the end effector's radius from
    the axis of rotation, which is a kinematic property of the arm and is simply
    not present in the action vector. A scope that must bound rotational motion
    needs its own cap and a forward-kinematics step; this example does not fake
    one, and a reviewer should read the absence as a known gap rather than a
    claim of coverage.

    Values outside the documented ranges are clamped, not rejected: the gripper
    axis is clamped into [0, 1] so a de-normalisation artefact cannot produce a
    negative force that silently passes the force check. An out-of-range
    translation delta is passed through, because a large one MUST reach the gate
    and be denied.
    """
    if len(vector) != 7:
        raise ValueError(f"expected a 7-DoF OpenVLA action vector, got {len(vector)} values")
    if control_period_s <= 0:
        raise ValueError("control_period_s must be positive")

    dx, dy, dz = (float(v) for v in vector[:3])
    gripper = float(vector[6])

    translation_m = math.sqrt(dx * dx + dy * dy + dz * dz)
    speed_mps = translation_m / control_period_s

    clamped = min(1.0, max(0.0, gripper))
    if gripper_closed_at is None:
        # Convention unverified: take the larger of both readings, which can
        # only over-estimate force. Over-denying is recoverable; scoring a
        # closed gripper as harmless is not.
        closure = max(clamped, 1.0 - clamped)
    elif gripper_closed_at == 0.0:
        closure = 1.0 - clamped
    elif gripper_closed_at == 1.0:
        closure = clamped
    else:
        raise ValueError("gripper_closed_at must be 0.0, 1.0, or None (unverified)")
    force_n = closure * max_grip_force_n

    return PhysicalAction(
        force_n=force_n,
        speed_mps=speed_mps,
        near_humans=near_humans,
        zone=zone,
    )


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def load_model_with_provenance(robot, robot_did, public_key, *, weights_hash, config=None):
    """
    Sign the model's provenance over the real weights hash and verify it before
    enabling autonomy. Returns (ok, attestation, subject).
    """
    config = vla_config() if config is None else config
    attestation = build_provenance_attestation(
        robot,
        robot_did=robot_did,
        model_name=VLA_MODEL_NAME,
        weights_hash=weights_hash,
        safety_policy=digest(b"factory-floor-safety-policy-v3"),
        config=config,
        version="7b",
    )
    ok, subject = verify_provenance_attestation(attestation, public_key, config=config)
    return ok, attestation, subject


def plan_episode(loaded: LoadedModel, image, episode=EPISODE, **mapping_kwargs) -> List[Proposal]:
    """Ask the model for one action per episode step and map each into a PhysicalAction."""
    proposals = []
    for instruction, zone, near_humans in episode:
        vector = propose_action(loaded, image, instruction)
        action = action_vector_to_physical_action(
            vector, zone=zone, near_humans=near_humans, **mapping_kwargs
        )
        proposals.append(Proposal(instruction=instruction, vector=vector, action=action))
    return proposals


def run_accountability_loop(scope, blackbox, proposals: Sequence[Proposal]):
    """
    Gate each proposed action against the physical scope, record every decision
    in the black box -- together with the raw action vector the model emitted --
    and return the per-step decisions.
    """
    decisions = []
    for proposal in proposals:
        action = proposal.action
        result = check_physical_action(scope, action)
        blackbox.append(
            "actuation_allowed" if result.ok else "actuation_denied",
            {
                "task": proposal.instruction,
                "model": MODEL_ID,
                "actionVector": [round(v, 6) for v in proposal.vector],
                "zone": action.zone,
                "speedMps": action.speed_mps,
                "forceN": action.force_n,
                "nearHumans": action.near_humans,
                "reasons": result.reasons,
            },
        )
        decisions.append((proposal.instruction, result))
    return decisions


def main() -> int:
    reason = unavailable_reason()
    if reason:
        print(SKIP_NOTICE.format(reason=reason, model_id=MODEL_ID))
        return 0

    robot_kp, robot = make_party("ar7.example.com")

    # 1. provenance on load, over the bytes actually on disk.
    weights_hash, snapshot, files = compute_weights_hash()
    total_bytes = sum(p.stat().st_size for p in files)
    print(f"weights: {len(files)} shard(s), {total_bytes / 1e9:.2f} GB under {snapshot}")
    print(f"weightsHash: {weights_hash}")

    ok, _attestation, subject = load_model_with_provenance(
        robot, robot_kp.did, robot_kp.public_key_jwk, weights_hash=weights_hash
    )
    print(f"provenance verifies: {ok}  model={subject['vla']['modelName']}")
    if not ok:
        raise SystemExit("refusing to enable autonomy without verified provenance")

    # 2. real inference, then the same pre-actuation gate, every decision logged.
    loaded = load_openvla()
    print(f"loaded {MODEL_ID} on {loaded.device} ({loaded.dtype})")
    proposals = plan_episode(loaded, observation_image())

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
    decisions = run_accountability_loop(scope, blackbox, proposals)

    for proposal, (task, result) in zip(proposals, decisions):
        verdict = "ALLOW" if result.ok else "DENY "
        why = f"  ({'; '.join(result.reasons)})" if result.reasons else ""
        vector = " ".join(f"{v:+.3f}" for v in proposal.vector)
        print(f"  [{verdict}] {task}{why}")
        print(
            f"          a=[{vector}]  ->  {proposal.action.speed_mps:.3f} m/s, "
            f"{proposal.action.force_n:.1f} N, zone={proposal.action.zone}"
        )

    # 3. the black box is tamper-evident without the key.
    entries = blackbox.entries()
    chain_ok, error = verify_blackbox_chain(entries)
    print(f"black-box chain verifies: {chain_ok}  entries={len(entries)}")

    # Rewriting history (a denied step becomes "allowed") breaks the chain.
    tampered = [dict(e) for e in entries]
    tampered[-1]["event"] = "actuation_allowed"
    chain_ok, error = verify_blackbox_chain(tampered)
    print(f"tampered chain detected: {not chain_ok}  ({error})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
