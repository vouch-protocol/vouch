"""
Multi-robot swarm accountability.

Robots increasingly act as a group: a fleet of pickers, a formation of drones, a
team clearing a site. When the group takes a physical action together, two
questions follow. Which robots were members of the group with authority to act, and
which of them took part in a specific collective action. This module answers both
with signed credentials, so a collective physical action is attributable to the
members that performed it and the coordinator that authorized the group, rather than
diffused across an anonymous swarm.

A swarm membership credential records that a coordinator admitted a robot to a
swarm, optionally with a role, signed by the coordinator. A collective action
attestation records a physical action taken by the swarm and the members that
participated, signed by the coordinator, and each participant can be checked against
its membership so the action ties only to admitted members.

This is the open layer: signed membership and collective-action credentials and
their verification. Managed swarm orchestration and formation control are out of
scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
SWARM_MEMBERSHIP_TYPE = "SwarmMembershipCredential"
COLLECTIVE_ACTION_TYPE = "CollectiveActionAttestation"


def build_swarm_membership(
    coordinator_signer: Any,
    *,
    swarm_id: str,
    robot_did: str,
    role: Optional[str] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed SwarmMembershipCredential: the coordinator admits `robot_did` to
    `swarm_id`, optionally with a `role`. Signed by the coordinator.
    """
    if not swarm_id or not robot_did:
        raise RoboticsError("swarm_id and robot_did are required")
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {"id": robot_did, "swarmId": swarm_id}
    if role is not None:
        subject["role"] = role
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", SWARM_MEMBERSHIP_TYPE],
        "issuer": coordinator_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, coordinator_signer)


def verify_swarm_membership(
    credential: Dict[str, Any],
    coordinator_public_key: Any,
    *,
    swarm_id: Optional[str] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a SwarmMembershipCredential: the coordinator's proof and, when `swarm_id`
    is given, that the membership is for that swarm. Returns (ok, subject).
    """
    ok, subject = _verify_typed(credential, coordinator_public_key, SWARM_MEMBERSHIP_TYPE)
    if not ok:
        return False, None
    if not subject.get("swarmId") or not subject.get("id"):
        return False, None
    if swarm_id is not None and subject.get("swarmId") != swarm_id:
        return False, None
    return True, subject


def build_collective_action(
    coordinator_signer: Any,
    *,
    swarm_id: str,
    action: str,
    participants: List[str],
    action_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed CollectiveActionAttestation: the coordinator records that the
    members in `participants` took `action` together as `swarm_id`. Signed by the
    coordinator.
    """
    if not swarm_id or not action:
        raise RoboticsError("swarm_id and action are required")
    if not participants:
        raise RoboticsError("participants must be a non-empty list")
    issued = (action_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", COLLECTIVE_ACTION_TYPE],
        "issuer": coordinator_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": {
            "swarmId": swarm_id,
            "action": action,
            "participants": list(participants),
        },
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, coordinator_signer)


def verify_collective_action(
    credential: Dict[str, Any],
    coordinator_public_key: Any,
    *,
    memberships: Optional[List[Dict[str, Any]]] = None,
) -> "tuple[bool, List[str]]":
    """
    Verify a CollectiveActionAttestation: the coordinator's proof and, when
    `memberships` is given, that every participant holds a membership in the same
    swarm signed by the same coordinator. Memberships are coordinator-signed, so they
    verify under the same `coordinator_public_key`. Returns (ok, unverified), where
    `unverified` lists any participant without a valid membership.
    """
    ok, subject = _verify_typed(credential, coordinator_public_key, COLLECTIVE_ACTION_TYPE)
    if not ok:
        return False, []
    swarm_id = subject.get("swarmId")
    participants = subject.get("participants") or []
    if not swarm_id or not participants:
        return False, []

    if memberships is None:
        return True, []

    by_member: Dict[str, Dict[str, Any]] = {}
    for m in memberships:
        msub = m.get("credentialSubject") or {}
        holder = msub.get("id")
        if isinstance(holder, str):
            by_member[holder] = m

    unverified: List[str] = []
    for p in participants:
        m = by_member.get(p)
        if m is None:
            unverified.append(p)
            continue
        mok, _ = verify_swarm_membership(m, coordinator_public_key, swarm_id=swarm_id)
        if not mok:
            unverified.append(p)
    return (not unverified), unverified


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
    "SWARM_MEMBERSHIP_TYPE",
    "COLLECTIVE_ACTION_TYPE",
    "build_swarm_membership",
    "verify_swarm_membership",
    "build_collective_action",
    "verify_collective_action",
]
