"""
Model-and-config provenance attestation for robots (Phase 5.2).

A signed, verifiable record of the Vision-Language-Action (VLA) model, weights
hash, safety policy, and configuration running on a robot. It is re-signable on
an over-the-air (OTA) update: the new attestation references the one it
supersedes, forming a tamper-evident chain of what software the robot ran and
when.

A ModelProvenanceAttestation is an eddsa-jcs-2022 VC. `weightsHash` is the
multibase SHA-256 of the model weights (supplied by the caller, since the robot
or builder computes it over the artifact); `configHash` is computed here over the
JCS-canonical config so any verifier reproduces it.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from vouch.jcs import canonicalize
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
MODEL_PROVENANCE_TYPE = "ModelProvenanceAttestation"


def config_hash(config: Dict[str, Any]) -> str:
    """Multibase SHA-256 of the JCS-canonical config object."""
    digest = hashlib.sha256(canonicalize(config)).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_provenance_attestation(
    signer: Any,
    *,
    robot_did: str,
    model_name: str,
    weights_hash: str,
    safety_policy: str,
    config: Optional[Dict[str, Any]] = None,
    version: Optional[str] = None,
    supersedes: Optional[str] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed ModelProvenanceAttestation for the software on a robot.

    Args:
      weights_hash: Multibase SHA-256 of the model weights artifact.
      safety_policy: An identifier or multibase hash of the active safety policy.
      config: The runtime config; its JCS SHA-256 is recorded as configHash.
      supersedes: The id (or hash) of the attestation this OTA update replaces.
    """
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    vla: Dict[str, Any] = {
        "modelName": model_name,
        "weightsHash": weights_hash,
        "safetyPolicy": safety_policy,
    }
    if version is not None:
        vla["version"] = version
    if config is not None:
        vla["configHash"] = config_hash(config)

    subject: Dict[str, Any] = {"id": robot_did, "vla": vla}
    if supersedes is not None:
        subject["supersedes"] = supersedes

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", MODEL_PROVENANCE_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def verify_provenance_attestation(
    attestation: Dict[str, Any],
    public_key: Any,
    *,
    config: Optional[Dict[str, Any]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a ModelProvenanceAttestation. When `config` is supplied, also check
    that its hash matches the recorded configHash. Returns (ok, subject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = attestation.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if MODEL_PROVENANCE_TYPE not in type_field:
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
    if config is not None:
        recorded = (subject.get("vla") or {}).get("configHash")
        if recorded != config_hash(config):
            return False, None
    return True, subject


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "MODEL_PROVENANCE_TYPE",
    "config_hash",
    "build_provenance_attestation",
    "verify_provenance_attestation",
]
