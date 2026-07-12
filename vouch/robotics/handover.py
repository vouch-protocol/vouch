"""
Safe robot-to-human handover.

A robot handing a physical object to a person is one of the most safety-sensitive
things it does, because a human hand is inside the robot's working envelope at the
moment of release. Custody handoff covers a task passing between actors; this covers
the physical safety of the release itself. A human handover credential records that
a robot released an object to a recipient, with the force and speed of the robot at
the moment of handover and whether those stayed inside the near-human safety
envelope, signed by the robot. The recipient can sign an acknowledgement bound to
that one handover, so receipt is mutual and non-repudiable.

This is the open layer: the signed handover credential with its envelope
attestation, the near-human safety check, and the recipient acknowledgement.
Hardware-sensed grip-release safety confirmation is out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
HUMAN_HANDOVER_TYPE = "HumanHandoverCredential"
HANDOVER_ACK_TYPE = "HandoverAcknowledgement"


def _in_envelope(force_n: float, speed_mps: float, scope: Dict[str, Any]) -> bool:
    """A handover is in envelope if force and near-human speed are within the scope."""
    if "maxForceN" in scope and force_n > scope["maxForceN"]:
        return False
    cap = scope.get("maxSpeedNearHumansMps", scope.get("maxSpeedMps"))
    if cap is not None and speed_mps > cap:
        return False
    return True


def build_human_handover(
    robot_signer: Any,
    *,
    robot_did: str,
    recipient: str,
    object_id: str,
    force_n: float,
    speed_mps: float,
    scope: Optional[Dict[str, Any]] = None,
    handover_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed HumanHandoverCredential: the robot released `object_id` to
    `recipient` with the given `force_n` and `speed_mps` at the moment of handover.
    When `scope` is given, whether the handover stayed inside the near-human safety
    envelope is computed and carried. Signed by the robot.
    """
    if not robot_did or not recipient or not object_id:
        raise RoboticsError("robot_did, recipient, and object_id are required")
    issued = (handover_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "recipient": recipient,
        "objectId": object_id,
        "envelope": {"forceN": force_n, "speedMps": speed_mps},
    }
    if scope is not None:
        subject["inEnvelope"] = _in_envelope(force_n, speed_mps, scope)

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", HUMAN_HANDOVER_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, robot_signer)


def verify_human_handover(
    credential: Dict[str, Any],
    robot_public_key: Any,
    *,
    scope: Optional[Dict[str, Any]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a HumanHandoverCredential: the robot's proof and, when `scope` is given,
    that recomputing the near-human envelope check over the attested force and speed
    reproduces the attested `inEnvelope` verdict. Returns (ok, subject).
    """
    ok, subject = _verify_typed(credential, robot_public_key, HUMAN_HANDOVER_TYPE)
    if not ok:
        return False, None
    if credential.get("issuer") != subject.get("id"):
        return False, None
    env = subject.get("envelope") or {}
    if "forceN" not in env or "speedMps" not in env:
        return False, None
    if scope is not None and "inEnvelope" in subject:
        recomputed = _in_envelope(env["forceN"], env["speedMps"], scope)
        if recomputed != bool(subject.get("inEnvelope")):
            return False, None
    return True, subject


def build_handover_ack(
    recipient_signer: Any,
    *,
    recipient_did: str,
    handover: Dict[str, Any],
    acknowledged_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed HandoverAcknowledgement: the recipient confirms receiving the
    object of a specific handover, bound to that handover by its proof value so the
    acknowledgement cannot be reused for another. Signed by the recipient.
    """
    ref = (handover.get("proof") or {}).get("proofValue")
    if not recipient_did or not ref:
        raise RoboticsError("recipient_did and a signed handover are required")
    subject_id = (handover.get("credentialSubject") or {}).get("objectId")
    issued = (acknowledged_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", HANDOVER_ACK_TYPE],
        "issuer": recipient_did,
        "validFrom": _iso(issued),
        "credentialSubject": {"id": recipient_did, "handoverRef": ref, "objectId": subject_id},
    }
    return attach_proof(credential, recipient_signer)


def verify_handover_ack(
    ack: Dict[str, Any],
    recipient_public_key: Any,
    *,
    handover: Dict[str, Any],
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a HandoverAcknowledgement: the recipient's proof, that the issuer is the
    recipient, and that it is bound to the given handover by its proof value. Returns
    (ok, subject).
    """
    ok, subject = _verify_typed(ack, recipient_public_key, HANDOVER_ACK_TYPE)
    if not ok:
        return False, None
    if ack.get("issuer") != subject.get("id"):
        return False, None
    ref = (handover.get("proof") or {}).get("proofValue")
    if not ref or subject.get("handoverRef") != ref:
        return False, None
    return True, subject


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
    "HUMAN_HANDOVER_TYPE",
    "HANDOVER_ACK_TYPE",
    "build_human_handover",
    "verify_human_handover",
    "build_handover_ack",
    "verify_handover_ack",
]
