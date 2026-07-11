"""
Accountable teleoperation handoff: who or what was in control of a robot.

Control of a robot passes back and forth between an autonomous policy and one or
more human teleoperators: the autonomy drives, a remote operator takes over for a
hard case, control returns to autonomy. When something goes wrong, the first
question is who or what was in control at that moment. This module makes each
transfer of control a signed record, so the answer is verifiable rather than
asserted by a log.

A control handoff credential records that a receiving controller took control of a
robot from a releasing controller, tagged with the control mode (autonomous,
teleoperated, or shared), signed by the receiver, the party taking responsibility.
Linking each handoff forms a chain a verifier walks to establish who held control,
and a controller-at-time lookup returns who held it at any moment, so an incident
traces to the controller in charge then.

This is the open layer: signed handoff credentials, chain verification, a
controller-at-time helper, and software continuity checking. Latency-bound
safe-takeover enforcement and biometric operator binding are out of scope for the
open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
CONTROL_HANDOFF_TYPE = "ControlHandoffCredential"

# Control modes a verifier can rely on. Implementers MAY use additional values.
CONTROL_MODES = frozenset({"autonomous", "teleoperated", "shared"})


def build_control_handoff(
    receiver_signer: Any,
    *,
    robot_did: str,
    from_controller: str,
    to_controller: str,
    mode: str,
    handoff_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed control handoff: the receiving controller `to_controller` takes
    control of `robot_did` from `from_controller` under `mode`, signed by the
    receiver (the party taking responsibility). A controller is a Vouch identity
    that may be an autonomous policy or a human operator.
    """
    if not robot_did or not from_controller or not to_controller:
        raise RoboticsError("robot_did, from_controller, and to_controller are required")
    if mode not in CONTROL_MODES:
        raise RoboticsError(f"mode must be one of {sorted(CONTROL_MODES)}, got {mode!r}")
    issued = (handoff_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "fromController": from_controller,
        "toController": to_controller,
        "mode": mode,
    }
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONTROL_HANDOFF_TYPE],
        "issuer": to_controller,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, receiver_signer)


def verify_control_handoff(
    credential: Dict[str, Any],
    receiver_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a control handoff: the receiver's proof, that the issuer is the receiving
    controller, and that the mode is one an interoperable verifier accepts. Returns
    (ok, subject).
    """
    ok, subject = _verify_typed(credential, receiver_public_key, CONTROL_HANDOFF_TYPE)
    if not ok:
        return False, None
    if not subject.get("fromController") or not subject.get("toController"):
        return False, None
    if credential.get("issuer") != subject.get("toController"):
        return False, None
    if subject.get("mode") not in CONTROL_MODES:
        return False, None
    return True, subject


def verify_control_chain(
    handoffs: List[Dict[str, Any]],
    public_keys: Dict[str, Any],
    *,
    origin_controller: Optional[str] = None,
) -> "tuple[bool, Optional[str]]":
    """
    Verify an ordered list of control handoffs forms a valid chain: each handoff
    verifies under its receiver's key, every link's toController matches the next
    link's fromController, and (when given) the first fromController is
    `origin_controller`. `public_keys` maps a controller DID to its key. Returns
    (ok, current_controller).
    """
    expected_from = origin_controller
    current: Optional[str] = origin_controller
    for handoff in handoffs:
        receiver = handoff.get("issuer")
        if not isinstance(receiver, str) or receiver not in public_keys:
            return False, None
        ok, subject = verify_control_handoff(handoff, public_keys[receiver])
        if not ok or subject is None:
            return False, None
        if expected_from is not None and subject.get("fromController") != expected_from:
            return False, None
        current = subject.get("toController")
        expected_from = current
    return True, current


def controller_at(
    handoffs: List[Dict[str, Any]],
    at: str,
) -> Optional[str]:
    """
    Return the controller in charge at ISO time `at`: the receiver (toController) of
    the most recent handoff at or before `at`. Returns None if no handoff had
    occurred yet. `handoffs` is assumed in chain order.
    """
    when = _parse_iso(at)
    if when is None:
        return None
    holder: Optional[str] = None
    for handoff in handoffs:
        start = _parse_iso(handoff.get("validFrom"))
        subject = handoff.get("credentialSubject") or {}
        if start is not None and start <= when:
            holder = subject.get("toController")
    return holder


class ControlContinuity:
    """The outcome of a control-continuity check: ok plus any gaps or overlaps."""

    def __init__(self, ok: bool, gaps: List[Dict[str, str]], overlaps: List[Dict[str, str]]):
        self.ok = ok
        self.gaps = gaps
        self.overlaps = overlaps

    def __repr__(self) -> str:
        return f"ControlContinuity(ok={self.ok}, gaps={self.gaps}, overlaps={self.overlaps})"


def check_control_continuity(handoffs: List[Dict[str, Any]]) -> ControlContinuity:
    """
    Confirm the control timeline is continuous and single-held: every handoff after
    the first begins where the previous one left off (its fromController is the
    previous toController), so there is no moment with no attributed controller and
    no moment with two. A link whose fromController is not the previous toController
    is reported as an overlap (two controllers claim authority across the seam); the
    same discontinuity leaves the prior controller's authority unaccounted for and
    is reported as a gap. Returns a ControlContinuity with the offending seams.
    """
    gaps: List[Dict[str, str]] = []
    overlaps: List[Dict[str, str]] = []
    prev_to: Optional[str] = None
    for handoff in handoffs:
        subject = handoff.get("credentialSubject") or {}
        frm = subject.get("fromController")
        to = subject.get("toController")
        if prev_to is not None and frm != prev_to:
            seam = {"expected": prev_to, "found": frm or ""}
            gaps.append(seam)
            overlaps.append(seam)
        prev_to = to
    return ControlContinuity(not gaps and not overlaps, gaps, overlaps)


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
    "CONTROL_HANDOFF_TYPE",
    "CONTROL_MODES",
    "ControlContinuity",
    "build_control_handoff",
    "verify_control_handoff",
    "verify_control_chain",
    "controller_at",
    "check_control_continuity",
]
