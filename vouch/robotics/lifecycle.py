"""
Robot lifecycle: ownership transfer, key rotation, and decommissioning.

A robot outlives its first owner. It is commissioned, resold, repurposed, and
eventually scrapped, and each of those transitions needs to be cryptographically
accountable so the chain of custody, the key history, and the end of life are
verifiable.

  - Ownership transfer: the current owner signs a transfer of the robot to a new
    owner. Linking each transfer to the previous one forms a chain of custody.
  - Key rotation: the robot's current key authorizes a new key, forming a key
    history (for a routine rotation or after a compromise).
  - Decommission: an owner or authority signs the retirement of the robot, after
    which a verifier should refuse to trust it.

This is the open layer: plain, signed lifecycle credentials. Hosted ownership
registries, managed rotation pipelines, and fleet decommissioning services are
out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
OWNERSHIP_TRANSFER_TYPE = "RobotOwnershipTransferCredential"
KEY_ROTATION_TYPE = "RobotKeyRotationCredential"
DECOMMISSION_TYPE = "RobotDecommissionCredential"


# ---------------------------------------------------------------------------
# Ownership transfer (chain of custody)
# ---------------------------------------------------------------------------


def build_ownership_transfer(
    current_owner_signer: Any,
    *,
    robot_did: str,
    to_owner: str,
    from_owner: Optional[str] = None,
    prev_transfer_id: Optional[str] = None,
    transferred_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed transfer of `robot_did` from the current owner to `to_owner`.
    The signer is the current owner; `from_owner` defaults to the signer's DID.
    `prev_transfer_id` links this transfer to the previous one, forming a chain.
    """
    if not robot_did or not to_owner:
        raise RoboticsError("robot_did and to_owner are required")
    issued = (transferred_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    seller = from_owner or current_owner_signer.get_did()
    subject: Dict[str, Any] = {
        "id": robot_did,
        "fromOwner": seller,
        "toOwner": to_owner,
    }
    if prev_transfer_id is not None:
        subject["prevTransferId"] = prev_transfer_id

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", OWNERSHIP_TRANSFER_TYPE],
        "issuer": current_owner_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    return attach_proof(credential, current_owner_signer)


def verify_ownership_transfer(
    credential: Dict[str, Any],
    current_owner_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a transfer: the current owner's proof and that the issuer is the
    fromOwner (only the current owner can transfer the robot). Returns
    (ok, credentialSubject).
    """
    ok, subject = _verify_typed(credential, current_owner_public_key, OWNERSHIP_TRANSFER_TYPE)
    if not ok:
        return False, None
    if not subject.get("toOwner") or not subject.get("fromOwner"):
        return False, None
    if credential.get("issuer") != subject.get("fromOwner"):
        return False, None
    return True, subject


def verify_custody_chain(
    transfers: List[Dict[str, Any]],
    public_keys: Dict[str, Any],
    *,
    origin_owner: Optional[str] = None,
) -> "tuple[bool, Optional[str]]":
    """
    Verify an ordered list of transfer credentials forms a valid chain of custody:
    each transfer's proof verifies under the owner who signed it, every link's
    toOwner matches the next link's fromOwner, and (when given) the first
    fromOwner is `origin_owner`. `public_keys` maps an owner DID to its key.
    Returns (ok, current_owner).
    """
    expected_from = origin_owner
    current_owner: Optional[str] = origin_owner
    for transfer in transfers:
        issuer = transfer.get("issuer")
        if issuer not in public_keys:
            return False, None
        ok, subject = verify_ownership_transfer(transfer, public_keys[issuer])
        if not ok:
            return False, None
        if expected_from is not None and subject.get("fromOwner") != expected_from:
            return False, None
        current_owner = subject.get("toOwner")
        expected_from = current_owner
    return True, current_owner


# ---------------------------------------------------------------------------
# Key rotation (key history)
# ---------------------------------------------------------------------------


def build_key_rotation(
    old_key_signer: Any,
    *,
    robot_did: str,
    new_key_multibase: str,
    reason: Optional[str] = None,
    rotated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a key-rotation credential in which the robot's current (old) key
    authorizes a new key. Signed by the old key, so anyone trusting the old key
    can trust the new one.
    """
    if not new_key_multibase:
        raise RoboticsError("new_key_multibase is required")
    issued = (rotated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "previousKey": old_key_signer.get_public_key_multikey(),
        "newKey": new_key_multibase,
    }
    if reason is not None:
        subject["reason"] = reason

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", KEY_ROTATION_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    return attach_proof(credential, old_key_signer)


def verify_key_rotation(
    credential: Dict[str, Any],
    old_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a key rotation: the OLD key signed it, binding the new key. Returns
    (ok, credentialSubject) with `newKey` the authorized successor.
    """
    ok, subject = _verify_typed(credential, old_public_key, KEY_ROTATION_TYPE)
    if not ok:
        return False, None
    if not subject.get("previousKey") or not subject.get("newKey"):
        return False, None
    return True, subject


def verify_key_history(
    rotations: List[Dict[str, Any]],
    origin_key_multibase: str,
    public_keys: Dict[str, Any],
) -> "tuple[bool, Optional[str]]":
    """
    Verify an ordered list of key rotations forms a valid key history starting
    from `origin_key_multibase`: each rotation's previousKey matches the current
    key, and each is signed by the key it rotates from. `public_keys` maps a key
    multibase to the corresponding public key. Returns (ok, current_key).
    """
    current_key = origin_key_multibase
    for rotation in rotations:
        subject = rotation.get("credentialSubject") or {}
        if subject.get("previousKey") != current_key:
            return False, None
        if current_key not in public_keys:
            return False, None
        ok, verified = verify_key_rotation(rotation, public_keys[current_key])
        if not ok:
            return False, None
        current_key = verified.get("newKey")
    return True, current_key


# ---------------------------------------------------------------------------
# Decommission (retirement)
# ---------------------------------------------------------------------------


def build_decommission(
    signer: Any,
    *,
    robot_did: str,
    reason: str,
    final_disposition: Optional[str] = None,
    decommissioned_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed decommission credential retiring `robot_did`. After
    decommissioning, a verifier should refuse to trust the robot. `signer` is the
    owner or an authority; `final_disposition` records the outcome (for example
    recycled, destroyed, or transferred to parts).
    """
    if not reason:
        raise RoboticsError("reason is required")
    issued = (decommissioned_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "reason": reason,
        "decommissionedBy": signer.get_did(),
    }
    if final_disposition is not None:
        subject["finalDisposition"] = final_disposition

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", DECOMMISSION_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def verify_decommission(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    trusted_authorities: Optional[Set[str]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a decommission credential. When `trusted_authorities` is supplied, the
    issuer DID MUST be in it, so only an attested authority can retire the robot.
    Returns (ok, credentialSubject).
    """
    ok, subject = _verify_typed(credential, public_key, DECOMMISSION_TYPE)
    if not ok:
        return False, None
    if trusted_authorities is not None and credential.get("issuer") not in trusted_authorities:
        return False, None
    return True, subject


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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
    "OWNERSHIP_TRANSFER_TYPE",
    "KEY_ROTATION_TYPE",
    "DECOMMISSION_TYPE",
    "build_ownership_transfer",
    "verify_ownership_transfer",
    "verify_custody_chain",
    "build_key_rotation",
    "verify_key_rotation",
    "verify_key_history",
    "build_decommission",
    "verify_decommission",
]
