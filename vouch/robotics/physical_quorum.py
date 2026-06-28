"""
Physical quorum: a cryptographic two-person rule for high-consequence robot acts.

Some physical actions are serious enough that no single authority should be able
to order them alone: applying large force near a person, entering a restricted
area, an irreversible cut or weld. A physical quorum requires M independent
approvals out of an attested set of N approvers before the action is authorized.
Each approver signs an approval over the same action, and the action is
authorized only when at least the threshold number of distinct, valid approvers
from the attested set have approved it.

This is the open layer: a plain M-of-N over distinct approvers. A hosted approval
workflow is out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
ACTION_APPROVAL_TYPE = "PhysicalActionApprovalCredential"
APPROVE = "approve"
REJECT = "reject"


def build_action_approval(
    approver_signer: Any,
    *,
    action_id: str,
    robot_did: str,
    decision: str = APPROVE,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed approval (or rejection) by one approver for a specific
    physical action, identified by `action_id`, that `robot_did` would perform.
    """
    if decision not in (APPROVE, REJECT):
        raise RoboticsError(f"decision must be {APPROVE!r} or {REJECT!r}, got {decision!r}")
    if not action_id:
        raise RoboticsError("action_id is required")

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": approver_signer.get_did(),
        "actionId": action_id,
        "robotDid": robot_did,
        "decision": decision,
    }
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ACTION_APPROVAL_TYPE],
        "issuer": approver_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, approver_signer)


def verify_action_authorization(
    approvals: List[Dict[str, Any]],
    *,
    action_id: str,
    robot_did: str,
    approver_keys: Dict[str, Any],
    threshold: int,
    approver_set: Optional[Set[str]] = None,
    now: Optional[datetime] = None,
) -> "tuple[bool, List[str]]":
    """
    Verify that a high-consequence physical action is authorized by a quorum.

    Each approval must: be the right type, carry an in-date proof signed by the
    approver's key (looked up in `approver_keys` by issuer DID), match `action_id`
    and `robot_did`, and carry an `approve` decision. When `approver_set` is
    supplied, the approver must be in it. The action is authorized when at least
    `threshold` DISTINCT valid approvers have approved. A single approver counts
    once even if it submits several approvals. Returns (authorized, sorted list of
    the distinct approving DIDs).
    """
    if threshold < 1:
        raise RoboticsError("threshold must be at least 1")

    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    approvers: Set[str] = set()

    for approval in approvals:
        type_field = approval.get("type") or []
        if isinstance(type_field, str):
            type_field = [type_field]
        if ACTION_APPROVAL_TYPE not in type_field:
            continue

        subject = approval.get("credentialSubject") or {}
        issuer = approval.get("issuer")
        if subject.get("actionId") != action_id or subject.get("robotDid") != robot_did:
            continue
        if subject.get("decision") != APPROVE:
            continue
        if approver_set is not None and issuer not in approver_set:
            continue
        if issuer not in approver_keys:
            continue
        if not _window_current(approval, moment):
            continue

        resolved = _coerce_ed25519_public_key(approver_keys[issuer])
        if resolved is None:
            continue
        try:
            if not data_integrity.verify_proof(approval, resolved):
                continue
        except ValueError:
            continue

        approvers.add(issuer)

    return len(approvers) >= threshold, sorted(approvers)


def _window_current(credential: Dict[str, Any], moment: datetime) -> bool:
    vf = credential.get("validFrom")
    vu = credential.get("validUntil")
    try:
        if vf and moment < _parse_iso(vf):
            return False
        if vu and moment > _parse_iso(vu):
            return False
    except (ValueError, TypeError):
        return False
    return True


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


__all__ = [
    "ACTION_APPROVAL_TYPE",
    "APPROVE",
    "REJECT",
    "build_action_approval",
    "verify_action_authorization",
]
