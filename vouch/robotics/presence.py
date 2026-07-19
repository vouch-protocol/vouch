"""
Channel-geometry proof of presence (PAD-108).

A DID handshake proves *who* a peer is, not *where* it is. At the disconnected
edge (inter-satellite links, subsea acoustic, through-rock RF) a captured, valid
credential can be replayed from another platform. This module fuses a measured
physical-channel geometry predicate into the signed exchange, so a credential
presented from a location inconsistent with the committed geometry is rejected,
with no shared secret and no live authority.

The physics here is real and deterministic: given the verifier's position and the
peer's *claimed* position, the expected one-way range is the Euclidean distance;
the verifier's *measured* range (from its ranging instrument) must agree within a
tolerance. A Doppler variant compares a measured carrier shift against the shift
predicted from the claimed relative velocity along the line of sight.

This is the open layer: the commitment format and the verifier predicate.
Acquiring the measurement (the radio, laser terminal, or acoustic modem) is the
platform's concern. Positions are in a shared metric frame (meters); velocities in
m/s; the caller is responsible for using one consistent frame.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
PRESENCE_ATTESTATION_TYPE = "ChannelGeometryPresenceAttestation"

# Speed of light in vacuum (m/s); callers on a slower medium (acoustic) pass their
# own propagation speed to the Doppler helper.
SPEED_OF_LIGHT_MPS = 299_792_458.0

Vec3 = Sequence[float]


def expected_range_m(a: Vec3, b: Vec3) -> float:
    """Euclidean distance between two positions in the same metric frame."""
    if len(a) != 3 or len(b) != 3:
        raise RoboticsError("positions must be 3-vectors [x, y, z] in meters")
    return math.sqrt(sum((float(a[i]) - float(b[i])) ** 2 for i in range(3)))


def radial_velocity_mps(
    verifier_pos: Vec3, peer_pos: Vec3, peer_velocity: Vec3
) -> float:
    """
    Component of the peer's velocity along the line of sight from the verifier,
    positive when the peer is receding. Zero range returns 0 (undefined LoS).
    """
    los = [float(peer_pos[i]) - float(verifier_pos[i]) for i in range(3)]
    dist = math.sqrt(sum(c * c for c in los))
    if dist == 0:
        return 0.0
    unit = [c / dist for c in los]
    return sum(unit[i] * float(peer_velocity[i]) for i in range(3))


def expected_doppler_hz(
    verifier_pos: Vec3,
    peer_pos: Vec3,
    peer_velocity: Vec3,
    carrier_hz: float,
    propagation_mps: float = SPEED_OF_LIGHT_MPS,
) -> float:
    """
    Predicted Doppler shift (Hz) of the peer's carrier as seen by the verifier.
    A receding peer (positive radial velocity) shifts the carrier down, so the
    returned shift is negative when receding.
    """
    vr = radial_velocity_mps(verifier_pos, peer_pos, peer_velocity)
    return -(vr / propagation_mps) * float(carrier_hz)


def check_presence(
    *,
    verifier_position: Vec3,
    claimed_peer_position: Vec3,
    measured_range_m: float,
    tolerance_m: float,
) -> "Tuple[bool, float]":
    """
    Decide whether a measured range agrees with the peer's claimed position
    relative to the verifier, within tolerance. Returns (ok, residual_m) where
    residual is |measured - expected|.
    """
    if tolerance_m < 0:
        raise RoboticsError("tolerance_m must be non-negative")
    predicted = expected_range_m(verifier_position, claimed_peer_position)
    residual = abs(float(measured_range_m) - predicted)
    return residual <= tolerance_m, residual


def build_presence_attestation(
    signer: Any,
    *,
    peer_did: str,
    nonce: str,
    claimed_position: Vec3,
    measured_range_m: float,
    tolerance_m: float,
    claimed_velocity: Optional[Vec3] = None,
) -> Dict[str, Any]:
    """
    Build a signed attestation binding a handshake `nonce`, the peer's claimed
    position (and optional velocity), and the verifier's measured range and
    tolerance. Signed by the verifying node, so the record is attributable and
    location-committed.
    """
    if not nonce:
        raise RoboticsError("nonce is required (binds the attestation to one handshake)")
    if len(claimed_position) != 3:
        raise RoboticsError("claimed_position must be a 3-vector [x, y, z]")

    geometry: Dict[str, Any] = {
        "claimedPosition": [float(x) for x in claimed_position],
        "measuredRangeM": float(measured_range_m),
        "toleranceM": float(tolerance_m),
    }
    if claimed_velocity is not None:
        if len(claimed_velocity) != 3:
            raise RoboticsError("claimed_velocity must be a 3-vector [vx, vy, vz]")
        geometry["claimedVelocity"] = [float(v) for v in claimed_velocity]

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", PRESENCE_ATTESTATION_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": {
            "id": peer_did,
            "nonce": nonce,
            "geometry": geometry,
        },
    }
    return attach_proof(credential, signer)


def verify_presence_attestation(
    attestation: Dict[str, Any],
    public_key: Any,
    *,
    verifier_position: Vec3,
    expected_nonce: Optional[str] = None,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a presence attestation offline: the issuer's proof, that the nonce
    echoes (when supplied), and that the measured range agrees with the claimed
    position relative to `verifier_position` within the committed tolerance.
    Returns (ok, credentialSubject). No network call.
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = attestation.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if PRESENCE_ATTESTATION_TYPE not in type_field:
        return False, None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(attestation, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = attestation.get("credentialSubject") or {}
    if expected_nonce is not None and subject.get("nonce") != expected_nonce:
        return False, None

    geometry = subject.get("geometry") or {}
    claimed = geometry.get("claimedPosition")
    measured = geometry.get("measuredRangeM")
    tolerance = geometry.get("toleranceM")
    if not isinstance(claimed, list) or len(claimed) != 3 or measured is None or tolerance is None:
        return False, None

    try:
        ok, _residual = check_presence(
            verifier_position=verifier_position,
            claimed_peer_position=claimed,
            measured_range_m=float(measured),
            tolerance_m=float(tolerance),
        )
    except RoboticsError:
        return False, None
    if not ok:
        return False, None
    return True, subject


__all__ = [
    "PRESENCE_ATTESTATION_TYPE",
    "SPEED_OF_LIGHT_MPS",
    "expected_range_m",
    "radial_velocity_mps",
    "expected_doppler_hz",
    "check_presence",
    "build_presence_attestation",
    "verify_presence_attestation",
]
