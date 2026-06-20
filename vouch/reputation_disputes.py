"""
Reputation disputes (reputation Phase 5).

A `DisputeCredential` challenges a specific receipt by id and content digest,
signed by the challenger. A `DisputeResolution` signed by an arbiter upholds or
dismisses it. When a resolution is upheld and applied to a `ReputationLedger`,
the disputed receipt is excluded from scoring and from the evidence Merkle root.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import data_integrity
from .jcs import canonicalize
from .receipts import receipt_subject

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
DISPUTE_TYPE = "DisputeCredential"
DISPUTE_RESOLUTION_TYPE = "DisputeResolution"


class DisputeError(Exception):
    """Raised on malformed dispute input."""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(receipt: Dict[str, Any]) -> str:
    return "u" + base64.urlsafe_b64encode(hashlib.sha256(canonicalize(receipt)).digest()).rstrip(
        b"="
    ).decode("ascii")


def _type_list(credential: Dict[str, Any]) -> list:
    t = credential.get("type") or []
    return [t] if isinstance(t, str) else list(t)


def _attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise DisputeError("signing requires a Signer with an Ed25519 key")
    credential["proof"] = data_integrity.build_proof(
        credential, raw, signer.verification_method_id()
    )
    return credential


def _verify(credential: Dict[str, Any], public_key: Any) -> bool:
    from .verifier import _coerce_ed25519_public_key

    pub = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if pub is None:
        return False
    try:
        return data_integrity.verify_proof(credential, pub)
    except ValueError:
        return False


def build_dispute(
    challenger_signer: Any,
    *,
    receipt: Dict[str, Any],
    reason: str,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Challenge a specific receipt, binding to its id and content digest."""
    if not receipt.get("id"):
        raise DisputeError("the disputed receipt needs an id")
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", DISPUTE_TYPE],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": challenger_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": {
            "id": receipt_subject(receipt),
            "receipt": {"id": receipt.get("id"), "digest": _digest(receipt)},
            "challenger": challenger_signer.get_did(),
            "reason": reason,
        },
    }
    return _attach_proof(credential, challenger_signer)


def build_dispute_resolution(
    arbiter_signer: Any,
    *,
    dispute: Dict[str, Any],
    upheld: bool,
    rationale: Optional[str] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Uphold or dismiss a dispute, signed by an arbiter."""
    dsub = dispute.get("credentialSubject") or {}
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": dsub.get("id"),
        "dispute": dispute.get("id"),
        "receipt": dsub.get("receipt"),
        "upheld": bool(upheld),
    }
    if rationale is not None:
        subject["rationale"] = rationale
    credential = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", DISPUTE_RESOLUTION_TYPE],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": arbiter_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    return _attach_proof(credential, arbiter_signer)


def verify_dispute(dispute: Dict[str, Any], public_key: Any):
    if DISPUTE_TYPE not in _type_list(dispute):
        return False, None
    if not _verify(dispute, public_key):
        return False, None
    return True, dispute.get("credentialSubject") or {}


def verify_dispute_resolution(resolution: Dict[str, Any], public_key: Any):
    if DISPUTE_RESOLUTION_TYPE not in _type_list(resolution):
        return False, None
    if not _verify(resolution, public_key):
        return False, None
    return True, resolution.get("credentialSubject") or {}


__all__ = [
    "DISPUTE_TYPE",
    "DISPUTE_RESOLUTION_TYPE",
    "DisputeError",
    "build_dispute",
    "build_dispute_resolution",
    "verify_dispute",
    "verify_dispute_resolution",
]
