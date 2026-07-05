"""
Robot wear and degradation attestation with capability auto-attenuation.

A robot does not stay as capable as it left the factory. Actuators wear, joints
develop backlash, sensors drift out of calibration, and error rates creep up. This
module lets a robot sign its own degradation state, bound to its identity and
hash-linked over time so the history is tamper-evident, and it derives a narrowed
physical capability scope from that state, so a worn robot operates inside a
tighter, verifiable envelope instead of trusting the static limit it shipped with.

A wear attestation carries a normalized wear level (0 for as-new, 1 for fully worn)
and optional detailed metrics (actuator wear, calibration drift, cycle count, fault
rate), signed by the robot. Linking each attestation to the previous one by its
proof forms a chain a verifier walks to see how the robot degraded over its life.
`attenuate_for_wear` derives a physical scope whose numeric caps are scaled down by
the wear level, and the result is a valid attenuation of the original scope, so the
same attenuation rule the rest of Vouch uses carries the derating.

This is the open layer: the robot signs its wear state and derives the narrowed
scope credential in software. Firmware-level enforcement of the narrowed envelope
and managed predictive-maintenance modeling are out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
WEAR_ATTESTATION_TYPE = "RobotWearAttestation"

# Numeric caps that scale down with wear. Zones and shift windows are preserved
# unchanged, so the derived scope stays a valid attenuation of the original.
_DERATED_CAPS = ("maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps")


def build_wear_attestation(
    signer: Any,
    *,
    robot_did: str,
    wear_level: float,
    metrics: Optional[Dict[str, Any]] = None,
    prev_proof: Optional[str] = None,
    attested_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed RobotWearAttestation: the robot attests its own degradation as a
    normalized `wear_level` in [0, 1], optionally with detailed `metrics`. When
    `prev_proof` is the proof value of the previous attestation, the new attestation
    links to it, forming a tamper-evident wear history. Signed by the robot.
    """
    if not robot_did:
        raise RoboticsError("robot_did is required")
    if wear_level < 0.0 or wear_level > 1.0:
        raise RoboticsError("wear_level must be between 0.0 and 1.0")

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    attested = (attested_at or issued).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "wearLevel": wear_level,
        "attestedAt": _iso(attested),
    }
    if metrics is not None:
        subject["metrics"] = dict(metrics)
    if prev_proof is not None:
        subject["prevProof"] = prev_proof

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", WEAR_ATTESTATION_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def verify_wear_attestation(
    credential: Dict[str, Any],
    public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a RobotWearAttestation: the robot's proof, that the issuer is the robot,
    and that the wear level is in range. Returns (ok, credentialSubject).
    """
    ok, subject = _verify_typed(credential, public_key, WEAR_ATTESTATION_TYPE)
    if not ok:
        return False, None
    if credential.get("issuer") != subject.get("id"):
        return False, None
    level = subject.get("wearLevel")
    if not isinstance(level, (int, float)) or level < 0.0 or level > 1.0:
        return False, None
    return True, subject


def verify_wear_chain(
    attestations: List[Dict[str, Any]],
    public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an ordered wear history: each attestation verifies under the robot's key,
    and each one after the first links to the previous by its proof value. Returns
    (ok, latest_subject).
    """
    if not attestations:
        return False, None
    prev_proof: Optional[str] = None
    latest: Optional[Dict[str, Any]] = None
    for att in attestations:
        ok, subject = verify_wear_attestation(att, public_key)
        if not ok or subject is None:
            return False, None
        if prev_proof is not None and subject.get("prevProof") != prev_proof:
            return False, None
        prev_proof = (att.get("proof") or {}).get("proofValue")
        latest = subject
    return True, latest


def attenuate_for_wear(
    scope: Dict[str, Any],
    wear_level: float,
) -> Dict[str, Any]:
    """
    Derive a physical scope narrowed for the given wear level: each numeric cap is
    scaled by (1 - wear_level), and the allowed zones and shift windows are carried
    through unchanged. The result is a valid attenuation of `scope` (never broader
    on any dimension), so the same attenuation check the rest of Vouch uses accepts
    it. A wear level of 0 returns the caps unchanged.
    """
    if wear_level < 0.0 or wear_level > 1.0:
        raise RoboticsError("wear_level must be between 0.0 and 1.0")
    factor = 1.0 - wear_level
    narrowed: Dict[str, Any] = {}
    for key, value in scope.items():
        if key in _DERATED_CAPS and isinstance(value, (int, float)):
            narrowed[key] = value * factor
        elif key == "allowedZones":
            narrowed[key] = list(value)
        elif key == "shiftWindows":
            narrowed[key] = [dict(w) for w in value]
        else:
            narrowed[key] = value
    return narrowed


def _verify_typed(
    credential: Dict[str, Any],
    public_key: Any,
    expected_type: str,
) -> "tuple[bool, Dict[str, Any]]":
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if expected_type not in type_field:
        return False, {}
    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, {}
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, {}
    except ValueError:
        return False, {}
    return True, credential.get("credentialSubject") or {}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "WEAR_ATTESTATION_TYPE",
    "build_wear_attestation",
    "verify_wear_attestation",
    "verify_wear_chain",
    "attenuate_for_wear",
]
