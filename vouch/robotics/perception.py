"""
Robot perception provenance: signed, tamper-evident provenance for what a robot's
sensors captured.

A robot's cameras, lidar, radar, and microphones produce the evidence it acts on,
and that evidence is exactly what an attacker wants to spoof or an operator wants
to dispute after the fact. This module lets a robot sign the provenance of each
captured frame at capture time: a record binding the frame's hash, the sensor
that produced it, the modality, the capture time, and the robot's DID. The
records are hash-linked into an append-only chain, so the sequence of what the
robot perceived is tamper-evident, and a signed attestation anchors a frame (or a
segment of frames, via the chain head) to the robot's key.

The frames themselves are not carried here, only their hashes, so the log stays
small and the raw sensor data can live wherever the deployment keeps it. A
verifier with the frame recomputes its hash and checks it against the record.

This is the open layer: the robot signs frame hashes in software, reusing the
black-box chain semantics. Hosted signed-sensor storage and a perception
verification network are out of scope for the open layer.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .blackbox import GENESIS_PREV_HASH, _entry_hash, _mb64, verify_blackbox_chain
from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
PERCEPTION_TYPE = "PerceptionProvenanceCredential"
PERCEPTION_LOG_VERSION = "1.0"

# Standard sensor modalities. Implementers MAY use additional values, but these
# are the interoperable set a verifier can rely on.
MODALITIES = frozenset(
    {
        "camera",
        "lidar",
        "radar",
        "depth",
        "audio",
        "thermal",
    }
)


def hash_frame(frame: bytes) -> str:
    """Return the multibase (base64url) SHA-256 of a raw sensor frame."""
    if not isinstance(frame, (bytes, bytearray)):
        raise RoboticsError("frame must be bytes")
    return _mb64(hashlib.sha256(bytes(frame)).digest())


@dataclass
class PerceptionLog:
    """
    Append-only, hash-linked log of sensor-frame provenance records.

    Each entry carries a sequence number, a timestamp, the sensor id, the
    modality, the frame hash, and the hash of the previous entry, so the
    sequence of perceived frames is tamper-evident. The frames are not stored;
    only their hashes are.
    """

    genesis_prev_hash: str = GENESIS_PREV_HASH
    _entries: List[Dict[str, Any]] = field(default_factory=list, init=False)
    _head: str = field(default="", init=False)

    def __post_init__(self) -> None:
        self._head = self.genesis_prev_hash

    def record(
        self,
        *,
        sensor_id: str,
        modality: str,
        frame: Optional[bytes] = None,
        frame_hash: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Append one frame-provenance record and return it. Provide either the raw
        `frame` (it is hashed) or a precomputed `frame_hash`.
        """
        if modality not in MODALITIES:
            raise RoboticsError(f"modality must be one of {sorted(MODALITIES)}, got {modality!r}")
        if not sensor_id:
            raise RoboticsError("sensor_id is required")
        if frame is not None and frame_hash is not None:
            raise RoboticsError("provide either frame or frame_hash, not both")
        if frame is not None:
            frame_hash = hash_frame(frame)
        if not frame_hash:
            raise RoboticsError("frame or frame_hash is required")

        body: Dict[str, Any] = {
            "version": PERCEPTION_LOG_VERSION,
            "seq": len(self._entries),
            "timestamp": timestamp or _iso(datetime.now(timezone.utc)),
            "sensorId": sensor_id,
            "modality": modality,
            "frameHash": frame_hash,
            "prevHash": self._head,
        }
        body["entryHash"] = _entry_hash(body)
        self._entries.append(body)
        self._head = body["entryHash"]
        return body

    def head(self) -> str:
        return self._head

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]


def verify_perception_log(
    entries: List[Dict[str, Any]],
    genesis_prev_hash: str = GENESIS_PREV_HASH,
) -> "tuple[bool, Optional[str]]":
    """Verify the hash chain over the perception log entries. Tamper-evident."""
    return verify_blackbox_chain(entries, genesis_prev_hash)


def build_perception_attestation(
    signer: Any,
    *,
    robot_did: str,
    sensor_id: str,
    modality: str,
    frame_hash: str,
    captured_at: Optional[datetime] = None,
    log_head: Optional[str] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed PerceptionProvenanceCredential attesting that a robot's sensor
    captured a specific frame. When `log_head` is supplied, the attestation also
    anchors the segment of frames up to that chain head.
    """
    if modality not in MODALITIES:
        raise RoboticsError(f"modality must be one of {sorted(MODALITIES)}, got {modality!r}")
    if not frame_hash:
        raise RoboticsError("frame_hash is required")

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    captured = (captured_at or issued).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "sensorId": sensor_id,
        "modality": modality,
        "frameHash": frame_hash,
        "capturedAt": _iso(captured),
    }
    if log_head is not None:
        subject["logHead"] = log_head

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", PERCEPTION_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def verify_perception_attestation(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    frame: Optional[bytes] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a PerceptionProvenanceCredential: the robot's proof and, when the raw
    `frame` is supplied, that its hash reproduces the attested frameHash. Returns
    (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if PERCEPTION_TYPE not in type_field:
        return False, None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = credential.get("credentialSubject") or {}
    if not subject.get("frameHash") or subject.get("modality") not in MODALITIES:
        return False, None

    if frame is not None:
        try:
            if hash_frame(frame) != subject.get("frameHash"):
                return False, None
        except RoboticsError:
            return False, None

    return True, subject


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PERCEPTION_TYPE",
    "MODALITIES",
    "hash_frame",
    "PerceptionLog",
    "verify_perception_log",
    "build_perception_attestation",
    "verify_perception_attestation",
]
