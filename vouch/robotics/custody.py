"""
Physical custody handoff: an accountable chain for a task or object across actors.

A physical task or object passes across a chain of actors, human and robot: a
person picks an item, hands it to a robot, that robot hands it to another robot,
which places it. Each handoff is a signed custody transition, so a physical-world
incident (damage, loss, mis-delivery) traces to the exact hop and the actor
responsible.

A custody handoff credential records that a receiving actor accepted custody of a
task or object from a releasing actor, signed by the receiver. Linking each handoff
to the previous forms a chain a verifier walks to establish who held the task at any
time. A condition attested at each handoff lets a physical state change be localized
to the specific hop whose holder was responsible.

This is the open layer: signed handoff credentials, chain verification, a
holder-at-time helper, and software condition localization. Managed logistics
custody orchestration and fleet-scale tracking are out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
CUSTODY_HANDOFF_TYPE = "CustodyHandoffCredential"


# ---------------------------------------------------------------------------
# Handoff credential + custody chain
# ---------------------------------------------------------------------------


def build_handoff(
    receiver_signer: Any,
    *,
    task_id: str,
    from_actor: str,
    to_actor: str,
    condition: Optional[str] = None,
    handoff_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed custody handoff: the receiving actor `to_actor` accepts custody
    of `task_id` from `from_actor`, signed by the receiver (the party taking
    responsibility). `condition` optionally attests the state of the task or object
    as received (for example a status, a quantity, or a hash of an inspection),
    which lets a later state change be localized to a hop. `from_actor` and
    `to_actor` may be human or robot DIDs.
    """
    if not task_id or not from_actor or not to_actor:
        raise RoboticsError("task_id, from_actor, and to_actor are required")
    issued = (handoff_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": task_id,
        "fromActor": from_actor,
        "toActor": to_actor,
    }
    if condition is not None:
        subject["condition"] = condition

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CUSTODY_HANDOFF_TYPE],
        "issuer": to_actor,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, receiver_signer)


def verify_handoff(
    credential: Dict[str, Any],
    receiver_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a custody handoff: the receiver's proof and that the issuer is the
    receiving actor (a party attests its own acceptance of custody). Returns
    (ok, subject).
    """
    ok, subject = _verify_typed(credential, receiver_public_key, CUSTODY_HANDOFF_TYPE)
    if not ok:
        return False, None
    if not subject.get("fromActor") or not subject.get("toActor"):
        return False, None
    if credential.get("issuer") != subject.get("toActor"):
        return False, None
    return True, subject


def verify_handoff_chain(
    handoffs: List[Dict[str, Any]],
    public_keys: Dict[str, Any],
    *,
    origin_actor: Optional[str] = None,
) -> "tuple[bool, Optional[str]]":
    """
    Verify an ordered list of handoff credentials forms a valid custody chain: each
    handoff verifies under its receiver's key, every link's toActor matches the next
    link's fromActor, and (when given) the first fromActor is `origin_actor`.
    `public_keys` maps an actor DID (human or robot) to its key. Returns
    (ok, current_holder).
    """
    expected_from = origin_actor
    current_holder: Optional[str] = origin_actor
    for handoff in handoffs:
        receiver = handoff.get("issuer")
        if receiver not in public_keys:
            return False, None
        ok, subject = verify_handoff(handoff, public_keys[receiver])
        if not ok:
            return False, None
        if expected_from is not None and subject.get("fromActor") != expected_from:
            return False, None
        current_holder = subject.get("toActor")
        expected_from = current_holder
    return True, current_holder


# ---------------------------------------------------------------------------
# Holder-at-time and condition localization
# ---------------------------------------------------------------------------


def holder_at(
    handoffs: List[Dict[str, Any]],
    at: str,
) -> Optional[str]:
    """
    Return the actor holding the task at ISO time `at`: the receiver (toActor) of
    the most recent handoff whose handoff time is at or before `at`. Returns None if
    no handoff had occurred yet. `handoffs` is assumed in chain order.
    """
    when = _parse_iso(at)
    if when is None:
        return None
    holder: Optional[str] = None
    for handoff in handoffs:
        start = _parse_iso(handoff.get("validFrom"))
        subject = handoff.get("credentialSubject") or {}
        if start is not None and start <= when:
            holder = subject.get("toActor")
    return holder


def locate_condition_change(
    handoffs: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Find the first hop where the attested condition differs from the previous
    handoff. The holder responsible for the change is the actor who held the task
    during it (the previous handoff's receiver). Returns a dict with
    responsibleHolder, fromCondition, and toCondition, or None if the condition
    never changed. Handoffs without a condition are skipped for the comparison.
    """
    prev_condition: Optional[str] = None
    prev_holder: Optional[str] = None
    for handoff in handoffs:
        subject = handoff.get("credentialSubject") or {}
        condition = subject.get("condition")
        if condition is None:
            continue
        if prev_condition is not None and condition != prev_condition:
            return {
                "responsibleHolder": prev_holder,
                "fromCondition": prev_condition,
                "toCondition": condition,
            }
        prev_condition = condition
        prev_holder = subject.get("toActor")
    return None


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


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


__all__ = [
    "CUSTODY_HANDOFF_TYPE",
    "build_handoff",
    "verify_handoff",
    "verify_handoff_chain",
    "holder_at",
    "locate_condition_change",
]
