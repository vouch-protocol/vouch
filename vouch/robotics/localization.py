"""
Physics-bound trust primitives:

  - PAD-113: distributed proof of location. Independent observers each sign a
    measured range to a target; a claimed position is confirmed only if a
    threshold of independent observations are consistent with it.
  - PAD-114: kinematic-plausibility filtering. Reject a position claim that is
    physically unreachable from a prior attested state within the elapsed time,
    given a declared motion envelope (surface speed, or velocity + delta-v budget).
  - PAD-121: narrow-beam optical alignment as an implicit presence factor. A signed
    exchange over a narrow beam evidences the peer occupied the pointed direction.

Positions are 3-vectors in one shared metric frame (meters); velocities m/s;
angles radians. Acquisition (ranging, attitude) is platform-specific; this module
provides the signed formats and the deterministic predicates.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .identity import RoboticsError
from ._signing import attach_proof
from ._verify import verify_typed_credential

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
RANGE_OBSERVATION_TYPE = "RangeObservationCredential"
PROOF_OF_LOCATION_TYPE = "ProofOfLocationCredential"
BEAM_PRESENCE_TYPE = "BeamPresenceAttestation"

Vec3 = Sequence[float]


def _v3(x: Any, name: str) -> "List[float]":
    if not isinstance(x, (list, tuple)) or len(x) != 3:
        raise RoboticsError(f"{name} must be a 3-vector [x, y, z]")
    return [float(v) for v in x]


def _dist(a: Vec3, b: Vec3) -> float:
    return math.sqrt(sum((float(a[i]) - float(b[i])) ** 2 for i in range(3)))


# --------------------------------------------------------------------------- #
# PAD-113: distributed proof of location
# --------------------------------------------------------------------------- #


def build_range_observation(
    observer_signer: Any,
    *,
    target_did: str,
    observer_position: Vec3,
    measured_range_m: float,
    nonce: str,
    epoch: int,
) -> Dict[str, Any]:
    """One observer signs its measured range to the target, with its own attested position."""
    if not nonce:
        raise RoboticsError("nonce is required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", RANGE_OBSERVATION_TYPE],
        "issuer": observer_signer.get_did(),
        "credentialSubject": {
            "id": target_did,
            "observer": observer_signer.get_did(),
            "observerPosition": _v3(observer_position, "observer_position"),
            "measuredRangeM": float(measured_range_m),
            "nonce": nonce,
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, observer_signer)


def verify_range_observation(
    observation: Dict[str, Any], observer_public_key: Any
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    subject = verify_typed_credential(observation, observer_public_key, RANGE_OBSERVATION_TYPE)
    return (subject is not None), subject


def count_consistent(
    observation_subjects: List[Dict[str, Any]],
    claimed_position: Vec3,
    *,
    tolerance_m: float,
) -> int:
    """
    Count how many range observations are consistent with `claimed_position`, i.e.
    |measured_range - dist(observer, claimed)| <= tolerance.
    """
    p = _v3(claimed_position, "claimed_position")
    n = 0
    for s in observation_subjects:
        obs_pos = s.get("observerPosition")
        measured = s.get("measuredRangeM")
        if not isinstance(obs_pos, list) or len(obs_pos) != 3 or measured is None:
            continue
        if abs(float(measured) - _dist(obs_pos, p)) <= tolerance_m:
            n += 1
    return n


def location_confirmed(
    observation_subjects: List[Dict[str, Any]],
    claimed_position: Vec3,
    *,
    tolerance_m: float,
    threshold: int,
) -> bool:
    """True if at least `threshold` observations are consistent with the claimed position."""
    if threshold <= 0:
        raise RoboticsError("threshold must be positive")
    return (
        count_consistent(observation_subjects, claimed_position, tolerance_m=tolerance_m)
        >= threshold
    )


def build_proof_of_location(
    combiner_signer: Any,
    *,
    target_did: str,
    position: Vec3,
    observer_dids: List[str],
    epoch: int,
) -> Dict[str, Any]:
    """A combiner issues a proof-of-location binding the target, the solved position, and the observers."""
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", PROOF_OF_LOCATION_TYPE],
        "issuer": combiner_signer.get_did(),
        "credentialSubject": {
            "id": target_did,
            "position": _v3(position, "position"),
            "observers": list(observer_dids),
            "epoch": int(epoch),
        },
    }
    return attach_proof(credential, combiner_signer)


# --------------------------------------------------------------------------- #
# PAD-114: kinematic-plausibility filtering
# --------------------------------------------------------------------------- #


def kinematically_reachable(
    *,
    prior_position: Vec3,
    claimed_position: Vec3,
    elapsed_seconds: float,
    envelope: Dict[str, Any],
    prior_velocity: Optional[Vec3] = None,
    tolerance_m: float = 0.0,
) -> bool:
    """
    True if `claimed_position` is reachable from `prior_position` within
    `elapsed_seconds` given the motion `envelope`:

      surface/aerial: {"maxSpeedMps": v}                 -> reach <= v * t
      orbital (ball): {"maxDeltaVMps": dv} with prior_velocity
                      -> reach <= (|v0| + dv) * t         (conservative delta-v ball)
      orbital (two-body): {"model": "two-body", "maxDeltaVMps": dv, "muM3S2": mu?}
                      with prior_velocity -> propagate the coasting orbit precisely,
                      then allow a dv * t maneuver ball around the propagated position.

    The two-body model is the tight, physically-grounded bound for spacecraft; the
    ball models remain for surface/aerial nodes and as a dependency-free fallback.
    """
    if elapsed_seconds < 0:
        raise RoboticsError("elapsed_seconds must be non-negative")

    if envelope.get("model") == "two-body":
        if prior_velocity is None:
            raise RoboticsError("two-body model requires prior_velocity")
        from .orbital import MU_EARTH, reachable_two_body

        return reachable_two_body(
            prior_position=prior_position,
            prior_velocity=prior_velocity,
            claimed_position=claimed_position,
            elapsed_seconds=elapsed_seconds,
            mu=float(envelope.get("muM3S2", MU_EARTH)),
            max_delta_v_mps=float(envelope.get("maxDeltaVMps", 0.0)),
            tolerance_m=tolerance_m,
        )

    d = _dist(prior_position, claimed_position)
    max_speed = float(envelope.get("maxSpeedMps", 0.0))
    if "maxDeltaVMps" in envelope:
        v0 = 0.0
        if prior_velocity is not None:
            v0 = math.sqrt(sum(float(c) ** 2 for c in prior_velocity))
        reach = (v0 + float(envelope["maxDeltaVMps"])) * elapsed_seconds
    else:
        reach = max_speed * elapsed_seconds
    return d <= reach + tolerance_m


# --------------------------------------------------------------------------- #
# PAD-121: narrow-beam optical alignment presence
# --------------------------------------------------------------------------- #


def within_beam(pointing: Vec3, peer_direction: Vec3, beamwidth_rad: float) -> bool:
    """True if `peer_direction` lies within half the beamwidth of the `pointing` axis."""
    if beamwidth_rad < 0:
        raise RoboticsError("beamwidth_rad must be non-negative")
    a = _v3(pointing, "pointing")
    b = _v3(peer_direction, "peer_direction")
    na = math.sqrt(sum(c * c for c in a))
    nb = math.sqrt(sum(c * c for c in b))
    if na == 0 or nb == 0:
        return False
    cos = max(-1.0, min(1.0, sum(a[i] * b[i] for i in range(3)) / (na * nb)))
    return math.acos(cos) <= beamwidth_rad / 2.0


def build_beam_presence(
    signer: Any,
    *,
    peer_did: str,
    nonce: str,
    pointing: Vec3,
    beamwidth_rad: float,
) -> Dict[str, Any]:
    """Bind narrow-beam pointing geometry and a handshake nonce into a signed presence factor."""
    if not nonce:
        raise RoboticsError("nonce is required")
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", BEAM_PRESENCE_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": {
            "id": peer_did,
            "nonce": nonce,
            "pointing": _v3(pointing, "pointing"),
            "beamwidthRad": float(beamwidth_rad),
        },
    }
    return attach_proof(credential, signer)


def verify_beam_presence(
    attestation: Dict[str, Any],
    public_key: Any,
    *,
    peer_direction: Vec3,
    expected_nonce: Optional[str] = None,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """Verify the proof, the nonce, and that the peer's direction lies within the declared beam."""
    subject = verify_typed_credential(attestation, public_key, BEAM_PRESENCE_TYPE)
    if subject is None:
        return False, None
    if expected_nonce is not None and subject.get("nonce") != expected_nonce:
        return False, None
    pointing = subject.get("pointing")
    beamwidth = subject.get("beamwidthRad")
    if not isinstance(pointing, list) or beamwidth is None:
        return False, None
    if not within_beam(pointing, peer_direction, float(beamwidth)):
        return False, None
    return True, subject


__all__ = [
    "RANGE_OBSERVATION_TYPE",
    "PROOF_OF_LOCATION_TYPE",
    "BEAM_PRESENCE_TYPE",
    "build_range_observation",
    "verify_range_observation",
    "count_consistent",
    "location_confirmed",
    "build_proof_of_location",
    "kinematically_reachable",
    "within_beam",
    "build_beam_presence",
    "verify_beam_presence",
]
