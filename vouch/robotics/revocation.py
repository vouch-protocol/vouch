"""
Revocation for robot credentials.

Robot identity, provenance, and capability credentials need the same two-level
revocation the rest of Vouch already provides, applied to physical machines:

  - Whole-DID kill (key compromise): a robot whose identity key is leaked or
    whose hardware is captured is revoked at the DID level through the existing
    `vouch.revocation.RevocationRegistry`. A robot DID is an ordinary DID, so the
    registry and the `.well-known/did-revocations.json` distribution path work
    unchanged. This is re-exported here for discoverability.

  - Surgical per-credential revocation: a single capability grant, a superseded
    provenance attestation, or one identity credential is retired without killing
    the robot's whole identity, by carrying a BitstringStatusList entry. This
    module adds the ergonomics for putting that entry on any robot credential and
    checking it, over the existing `vouch.status_list` primitives.

The fleet-scale operation of these (SLA'd propagation, dashboards, cross-fleet
aggregation) is a service concern layered on top; the formats and the verifier
here are the open, free protocol surface.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .. import status_list as _status_list
from ..revocation import RevocationRegistry
from ..status_list import (
    STATUS_PURPOSE_REVOCATION,
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
)
from .identity import RoboticsError
from ._signing import attach_proof


def attach_credential_status(
    credential: Dict[str, Any],
    signer: Any,
    *,
    status_list_credential: str,
    status_list_index: int,
    status_purpose: str = STATUS_PURPOSE_REVOCATION,
    entry_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add a BitstringStatusList `credentialStatus` entry to a robot credential and
    (re)sign it, so the credential can later be revoked or suspended surgically.

    The entry references a bit index in a published status list credential. The
    credential is signed after the entry is added, so the proof covers the status
    binding. Any pre-existing proof is replaced. If the credential already
    carries a credentialStatus, the new entry is appended (the field becomes a
    list), matching the Verifiable Credentials data model.

    Returns the signed credential.
    """
    entry = build_status_list_entry(
        status_list_credential=status_list_credential,
        status_list_index=status_list_index,
        status_purpose=status_purpose,
        entry_id=entry_id,
    )

    existing = credential.get("credentialStatus")
    if existing is None:
        credential["credentialStatus"] = entry
    elif isinstance(existing, list):
        existing.append(entry)
    else:
        credential["credentialStatus"] = [existing, entry]

    # Re-sign: the proof must cover the credentialStatus we just added.
    credential.pop("proof", None)
    return attach_proof(credential, signer)


def _status_entries(credential: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = credential.get("credentialStatus")
    if raw is None:
        return []
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    if isinstance(raw, dict):
        return [raw]
    raise RoboticsError("credentialStatus must be a dict or a list of dicts")


def check_credential_status(
    credential: Dict[str, Any],
    status_list_credential: Dict[str, Any],
    *,
    status_purpose: str = STATUS_PURPOSE_REVOCATION,
) -> bool:
    """
    Return True if the robot credential's status bit for `status_purpose` is set
    (for example, the credential has been revoked) in the supplied status list.

    The caller MUST verify the Data Integrity proof on `status_list_credential`
    before calling this, exactly as for the agent-side `status_list.verify_status`.
    Returns False when the credential carries no matching status entry.
    """
    referenced_id = status_list_credential.get("id")
    for entry in _status_entries(credential):
        if entry.get("statusPurpose") != status_purpose:
            continue
        if entry.get("statusListCredential") != referenced_id:
            continue
        return _status_list.verify_status(
            credential_status=entry,
            status_list_credential=status_list_credential,
        )
    return False


__all__ = [
    "RevocationRegistry",
    "StatusListError",
    "build_status_list_credential",
    "build_status_list_entry",
    "attach_credential_status",
    "check_credential_status",
]
