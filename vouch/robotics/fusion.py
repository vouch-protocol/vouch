"""
Fused-sensor provenance: signed provenance for a robot's fused world model.

Perception provenance signs individual sensor frames. A robot rarely acts on one
frame, though: it fuses many frames, from cameras, lidar, radar, and other
sensors, into a single world model, an object set, an occupancy grid, or a pose
estimate, and acts on that. This module binds a fused output to the exact set of
input frames that produced it and the fusion method that produced it, signed by
the robot, so a manipulated fusion result or a silently dropped or substituted
input is detectable at the provenance layer.

A fused-perception attestation carries the hash of the fused output, an ordered
list of the input frame hashes, a digest over those inputs, and a fusion method
identifier, signed by the robot. A verifier reproduces the input digest from the
listed inputs and, when it holds the raw fused output, reproduces its hash, so the
attestation commits to exactly those inputs and that output. Checking each listed
input against the robot's signed perception log confirms every fused input traces
to a frame the robot actually recorded.

The fused output and the frames themselves are not carried here, only their
hashes, so the attestation stays small and the raw data can live wherever the
deployment keeps it. This is the open layer: the robot signs the binding of a
fused output to its inputs in software, reusing the perception frame hashes.
Hardware sensor attestation and managed sensor-fusion orchestration are out of
scope for the open layer.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .blackbox import _mb64
from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
FUSED_PERCEPTION_TYPE = "FusedPerceptionAttestation"


def hash_fused_output(output: bytes) -> str:
    """Return the multibase (base64url) SHA-256 of a raw fused output."""
    if not isinstance(output, (bytes, bytearray)):
        raise RoboticsError("output must be bytes")
    return _mb64(hashlib.sha256(bytes(output)).digest())


def fusion_inputs_digest(input_frame_hashes: List[str]) -> str:
    """
    Return a deterministic multibase digest over an ordered list of input frame
    hashes. The digest commits to the exact inputs and their order, so adding,
    removing, or reordering an input changes it. Reproduced byte-identically
    across language SDKs.
    """
    if not input_frame_hashes:
        raise RoboticsError("input_frame_hashes must be a non-empty list")
    for h in input_frame_hashes:
        if not h or not isinstance(h, str):
            raise RoboticsError("each input frame hash must be a non-empty string")
    joined = "\n".join(input_frame_hashes).encode("utf-8")
    return _mb64(hashlib.sha256(joined).digest())


def build_fused_attestation(
    signer: Any,
    *,
    robot_did: str,
    fusion_method: str,
    input_frame_hashes: List[str],
    fused_output: Optional[bytes] = None,
    fused_output_hash: Optional[str] = None,
    captured_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed FusedPerceptionAttestation: the robot attests that a fused
    output was produced by `fusion_method` from the frames named in
    `input_frame_hashes`. Provide either the raw `fused_output` (it is hashed) or a
    precomputed `fused_output_hash`. The attestation carries a digest over the
    ordered inputs, so the set of inputs is tamper-evident.
    """
    if not robot_did:
        raise RoboticsError("robot_did is required")
    if not fusion_method:
        raise RoboticsError("fusion_method is required")
    if not input_frame_hashes:
        raise RoboticsError("input_frame_hashes must be a non-empty list")
    if fused_output is not None and fused_output_hash is not None:
        raise RoboticsError("provide either fused_output or fused_output_hash, not both")
    if fused_output is not None:
        fused_output_hash = hash_fused_output(fused_output)
    if not fused_output_hash:
        raise RoboticsError("fused_output or fused_output_hash is required")

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    captured = (captured_at or issued).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "fusionMethod": fusion_method,
        "fusedOutputHash": fused_output_hash,
        "inputFrameHashes": list(input_frame_hashes),
        "inputsDigest": fusion_inputs_digest(input_frame_hashes),
        "capturedAt": _iso(captured),
    }

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", FUSED_PERCEPTION_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def verify_fused_attestation(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    fused_output: Optional[bytes] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a FusedPerceptionAttestation: the robot's proof, that the digest over
    the listed inputs reproduces the attested `inputsDigest` (so the inputs are
    internally consistent and tamper-evident), and, when the raw `fused_output` is
    supplied, that its hash reproduces the attested `fusedOutputHash`. Returns
    (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if FUSED_PERCEPTION_TYPE not in type_field:
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
    inputs = subject.get("inputFrameHashes")
    if not subject.get("fusedOutputHash") or not inputs:
        return False, None
    try:
        if fusion_inputs_digest(inputs) != subject.get("inputsDigest"):
            return False, None
    except RoboticsError:
        return False, None

    if fused_output is not None:
        try:
            if hash_fused_output(fused_output) != subject.get("fusedOutputHash"):
                return False, None
        except RoboticsError:
            return False, None

    return True, subject


def verify_fusion_inputs(
    credential: Dict[str, Any],
    log_entries: List[Dict[str, Any]],
) -> "tuple[bool, List[str]]":
    """
    Confirm every input frame the attestation names was actually recorded in the
    robot's perception log. Returns (ok, missing), where `missing` lists the input
    frame hashes that do not appear as a recorded frame, so a dropped or
    substituted fused input is named rather than hidden.
    """
    recorded = {e.get("frameHash") for e in log_entries if e.get("frameHash")}
    subject = credential.get("credentialSubject") or {}
    inputs = subject.get("inputFrameHashes") or []
    missing = [h for h in inputs if h not in recorded]
    return (not missing), missing


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "FUSED_PERCEPTION_TYPE",
    "hash_fused_output",
    "fusion_inputs_digest",
    "build_fused_attestation",
    "verify_fused_attestation",
    "verify_fusion_inputs",
]
