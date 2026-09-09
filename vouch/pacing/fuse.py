"""
Capability-Proportional Sequential Delay (PAD-130).

Every rate limit that can be bought out of gets cheaper as the party subject to
it grows richer. A sequential delay function cannot be bought out of, because
its evaluation is serial and additional parallel resources do not shorten it.

Here the required delay is a monotone non-decreasing function of the measured
capability increment over a committed reference point, so a larger leap buys the
surrounding world a proportionally longer interval. The evaluation is seeded
from the current root of a shared append-only log combined with the step's own
registration digest, so the seed does not exist before the registration is
published, which forecloses precomputation and gives mutually distrustful
participants one clock that none of them sets.

The reference sequential function is a checkpointed hash chain: evaluation is
strictly serial, while verification splits into independent segments that a
verifier can check in any order or in parallel. The ``SequentialFunction``
protocol is the substitution point for a succinct verifiable delay function.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from ._common import PacingError, base_credential, mb64, subject_of, unmb64, verify_credential

ADVANCEMENT_TYPE = "VouchAdvancementCredential"

REASON_INVALID_PROOF = "invalid_proof"
REASON_SEED_MISMATCH = "seed_mismatch"
REASON_STEPS_INSUFFICIENT = "sequential_steps_insufficient"
REASON_DELAY_PROOF_INVALID = "delay_proof_invalid"
REASON_PARAMS_MISMATCH = "delay_parameters_mismatch"
REASON_INCREMENT_MISMATCH = "increment_mismatch"

DEFAULT_PARAMETERS: Dict[str, Any] = {
    "baseSteps": 1000,
    "stepsPerUnit": 500.0,
    "exponent": 1.5,
    "maxSteps": 100_000_000,
}


def required_steps(increment: float, parameters: Optional[Dict[str, Any]] = None) -> int:
    """
    Sequential steps required for a capability increment.

    Monotone non-decreasing in the increment: a larger step always requires at
    least as long an interval as a smaller one. A non-positive increment still
    requires the base interval, so an advancement is never instantaneous.
    """
    params = dict(DEFAULT_PARAMETERS)
    params.update(parameters or {})
    base = int(params["baseSteps"])
    per_unit = float(params["stepsPerUnit"])
    exponent = float(params["exponent"])
    ceiling = int(params["maxSteps"])
    if base < 0 or per_unit < 0 or exponent < 0 or ceiling < base:
        raise PacingError("delay parameters must be non-negative with maxSteps >= baseSteps")
    delta = max(0.0, float(increment))
    steps = base + int(per_unit * (delta**exponent))
    return min(steps, ceiling)


def derive_seed(log_root: str, registration_digest: str) -> bytes:
    """
    The sequential evaluation's seed.

    Binding the shared log root to the step's own registration digest means the
    seed is unavailable until the registration is in the log, so the evaluation
    cannot have been started earlier.
    """
    if not log_root or not isinstance(log_root, str):
        raise PacingError("log_root is required")
    if not registration_digest or not isinstance(registration_digest, str):
        raise PacingError("registration_digest is required")
    payload = (
        b"vouch-pacing-fuse-seed\x00"
        + log_root.encode("utf-8")
        + b"\x00"
        + registration_digest.encode("utf-8")
    )
    return hashlib.sha256(payload).digest()


class SequentialFunction:
    """
    The substitution point for a verifiable delay function.

    An implementation must be inherently serial to evaluate. Verification may be
    cheaper, and may be parallel, but evaluation must not be.
    """

    name = "abstract"

    def evaluate(self, seed: bytes, steps: int) -> Dict[str, Any]:
        """Evaluate for the given number of steps and return a proof object."""
        raise NotImplementedError

    def verify(self, seed: bytes, steps: int, proof: Dict[str, Any]) -> bool:
        """Check a proof against the seed and step count. Default-deny."""
        raise NotImplementedError


@dataclass
class CheckpointedHashChain(SequentialFunction):
    """
    Iterated SHA-256 with periodic checkpoints.

    Evaluation is strictly serial because each state depends on the one before
    it. Verification recomputes the segments between checkpoints, and those
    segments are independent of one another, so a verifier may check them in any
    order or spread them across cores while an evaluator cannot.
    """

    checkpoint_interval: int = 1000
    name: str = "sha256-chain-checkpointed/v1"

    def evaluate(self, seed: bytes, steps: int) -> Dict[str, Any]:
        """Run the chain and record its checkpoints."""
        if steps < 0:
            raise PacingError("steps must be non-negative")
        interval = max(1, int(self.checkpoint_interval))
        state = bytes(seed)
        checkpoints: List[str] = []
        for index in range(1, steps + 1):
            state = hashlib.sha256(state).digest()
            if index % interval == 0 and index != steps:
                checkpoints.append(mb64(state))
        return {
            "function": self.name,
            "steps": int(steps),
            "checkpointInterval": interval,
            "checkpoints": checkpoints,
            "output": mb64(state),
        }

    def verify(self, seed: bytes, steps: int, proof: Dict[str, Any]) -> bool:
        """Recompute each segment between checkpoints and compare the output."""
        if not isinstance(proof, dict) or proof.get("function") != self.name:
            return False
        if int(proof.get("steps", -1)) != int(steps) or steps < 0:
            return False
        interval = int(proof.get("checkpointInterval", 0))
        if interval < 1:
            return False
        checkpoints = proof.get("checkpoints")
        output = proof.get("output")
        if not isinstance(checkpoints, list) or not isinstance(output, str):
            return False
        expected_count = max(0, (steps - 1) // interval) if steps else 0
        if len(checkpoints) != expected_count:
            return False
        try:
            boundaries = [bytes(seed)] + [unmb64(str(point)) for point in checkpoints]
            boundaries.append(unmb64(output))
        except PacingError:
            return False
        remaining = steps
        for index in range(len(boundaries) - 1):
            segment = min(interval, remaining) if index < len(boundaries) - 2 else remaining
            state = boundaries[index]
            for _ in range(segment):
                state = hashlib.sha256(state).digest()
            if state != boundaries[index + 1]:
                return False
            remaining -= segment
        return remaining == 0


DEFAULT_FUNCTION = CheckpointedHashChain()


def advancement_credential(
    signer: Any,
    *,
    step_id: str,
    increment: float,
    reference_point: float,
    measurement: float,
    log_root: str,
    registration_digest: str,
    parameters: Optional[Dict[str, Any]] = None,
    function: Optional[SequentialFunction] = None,
    deployment_class: str = "internal",
) -> Dict[str, Any]:
    """
    Evaluate the required delay and issue the advancement credential.

    Evaluation happens here, so issuing this credential takes at least as long
    as the increment requires. The credential carries everything a verifier
    needs to recompute the requirement and check the proof.
    """
    params = dict(DEFAULT_PARAMETERS)
    params.update(parameters or {})
    fn = function or DEFAULT_FUNCTION
    steps = required_steps(increment, params)
    seed = derive_seed(log_root, registration_digest)
    proof = fn.evaluate(seed, steps)
    subject: Dict[str, Any] = {
        "id": step_id,
        "operator": signer.get_did(),
        "referencePoint": float(reference_point),
        "measurement": float(measurement),
        "increment": float(increment),
        "delayParameters": params,
        "requiredSteps": int(steps),
        "logRoot": log_root,
        "registrationDigest": registration_digest,
        "delayProof": proof,
        "deploymentClass": deployment_class,
    }
    return base_credential(signer, ADVANCEMENT_TYPE, subject)


def check_advancement(
    credential: Dict[str, Any],
    operator_public_key: Any,
    *,
    log_root: str,
    registration_digest: str,
    parameters: Optional[Dict[str, Any]] = None,
    function: Optional[SequentialFunction] = None,
    expected_increment: Optional[float] = None,
) -> List[str]:
    """
    Decide whether an advancement or deployment may proceed.

    Returns the reasons it is refused. An empty list means the increment was
    computed from the declared measurements, the required interval matches the
    committed parameters, the seed matches the shared log root and the step's
    own registration, and the sequential proof verifies.
    """
    reasons: List[str] = []
    if not verify_credential(credential, operator_public_key, ADVANCEMENT_TYPE):
        return [REASON_INVALID_PROOF]
    subject = subject_of(credential)

    if (
        subject.get("logRoot") != log_root
        or subject.get("registrationDigest") != registration_digest
    ):
        reasons.append(REASON_SEED_MISMATCH)

    declared_increment = subject.get("increment")
    measurement = subject.get("measurement")
    reference = subject.get("referencePoint")
    if isinstance(measurement, (int, float)) and isinstance(reference, (int, float)):
        recomputed = float(measurement) - float(reference)
        if (
            not isinstance(declared_increment, (int, float))
            or abs(float(declared_increment) - recomputed) > 1e-9
        ):
            reasons.append(REASON_INCREMENT_MISMATCH)
    else:
        reasons.append(REASON_INCREMENT_MISMATCH)
    if expected_increment is not None and isinstance(declared_increment, (int, float)):
        if abs(float(declared_increment) - float(expected_increment)) > 1e-9:
            reasons.append(REASON_INCREMENT_MISMATCH)

    committed = dict(DEFAULT_PARAMETERS)
    committed.update(parameters or {})
    declared_params = subject.get("delayParameters") or {}
    if any(float(declared_params.get(key, -1)) != float(value) for key, value in committed.items()):
        reasons.append(REASON_PARAMS_MISMATCH)

    if isinstance(declared_increment, (int, float)):
        needed = required_steps(float(declared_increment), committed)
        declared_steps = subject.get("requiredSteps")
        if not isinstance(declared_steps, int) or declared_steps < needed:
            reasons.append(REASON_STEPS_INSUFFICIENT)
        else:
            fn = function or DEFAULT_FUNCTION
            seed = derive_seed(log_root, registration_digest)
            if not fn.verify(seed, declared_steps, subject.get("delayProof") or {}):
                reasons.append(REASON_DELAY_PROOF_INVALID)

    return reasons


def stage_unlock(cumulative_steps: int, stages: Sequence[Dict[str, Any]]) -> List[str]:
    """
    Which deployment classes are unlocked by the sequential evidence so far.

    Stages are ``{"class": name, "steps": n}``. Breadth of deployment is paced by
    the magnitude of the change, since the steps required grow with the
    increment.
    """
    unlocked: List[str] = []
    for stage in stages:
        needed = stage.get("steps")
        name = stage.get("class")
        if isinstance(needed, int) and isinstance(name, str) and cumulative_steps >= needed:
            unlocked.append(name)
    return unlocked
