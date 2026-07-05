"""
Cross-embodiment identity continuity: one accountable agent across robot bodies.

An AI agent (a "mind": a policy with its own Vouch identity) can run on one robot
body today and a different body tomorrow. This makes that continuous and
accountable. An embodiment credential binds the agent identity to a specific body
(a hardware-rooted robot identity) and that body's hardware root for a period,
signed by the agent's own persistent key. Linking each embodiment to the previous
forms a continuity chain a verifier walks to confirm the same accountable agent
persisted across bodies, re-binding to each body's hardware root as it moved. A
fork check confirms the agent was never actively embodied in two bodies at once.

This is the inverse of the ownership custody chain: there one body passes between
owners; here one mind passes between bodies, and the constant that signs every link
is the agent identity itself.

This is the open layer: plain signed embodiment credentials, continuity-chain
verification, and software fork detection. Managed key custody and fleet-scale
migration are out of scope for the open layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
EMBODIMENT_TYPE = "AgentEmbodimentCredential"


# ---------------------------------------------------------------------------
# Embodiment credential + continuity chain
# ---------------------------------------------------------------------------


def build_embodiment(
    agent_signer: Any,
    *,
    agent_did: str,
    body_did: str,
    body_hardware_root: str,
    from_body: Optional[str] = None,
    embodied_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed embodiment credential: the agent `agent_did` authorizes running
    on `body_did`, re-binding to that body's hardware root `body_hardware_root`.
    Signed by the agent's own persistent key, so the whole continuity chain is
    signed by one accountable identity. `from_body` links this embodiment to the
    body the agent left, forming the chain. `valid_seconds`, when given, bounds the
    active window (used by fork detection).
    """
    if not agent_did or not body_did or not body_hardware_root:
        raise RoboticsError("agent_did, body_did, and body_hardware_root are required")
    issued = (embodied_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": agent_did,
        "body": body_did,
        "bodyHardwareRoot": body_hardware_root,
    }
    if from_body is not None:
        subject["fromBody"] = from_body

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", EMBODIMENT_TYPE],
        "issuer": agent_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, agent_signer)


def verify_embodiment(
    credential: Dict[str, Any],
    agent_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an embodiment credential: the agent's proof and that the issuer is the
    agent itself (a mind authorizes its own embodiment). Returns (ok, subject).
    """
    ok, subject = _verify_typed(credential, agent_public_key, EMBODIMENT_TYPE)
    if not ok:
        return False, None
    if not subject.get("body") or not subject.get("bodyHardwareRoot"):
        return False, None
    if credential.get("issuer") != subject.get("id"):
        return False, None
    return True, subject


def verify_continuity_chain(
    embodiments: List[Dict[str, Any]],
    agent_public_key: Any,
    *,
    origin_body: Optional[str] = None,
) -> "tuple[bool, Optional[str]]":
    """
    Verify an ordered list of embodiment credentials forms a valid continuity chain
    for one agent: every link verifies under the SAME agent key (the persistent
    mind), each link's `fromBody` matches the previous link's `body`, and (when
    given) the first `fromBody` is `origin_body`. Returns (ok, current_body).
    """
    expected_from = origin_body
    current_body: Optional[str] = origin_body
    for embodiment in embodiments:
        ok, subject = verify_embodiment(embodiment, agent_public_key)
        if not ok:
            return False, None
        if expected_from is not None and subject.get("fromBody") != expected_from:
            return False, None
        current_body = subject.get("body")
        expected_from = current_body
    return True, current_body


# ---------------------------------------------------------------------------
# Fork detection (a mind cannot be actively embodied in two bodies at once)
# ---------------------------------------------------------------------------


def check_no_fork(
    embodiments: List[Dict[str, Any]],
) -> "tuple[bool, Optional[Dict[str, str]]]":
    """
    Confirm no two embodiments place the agent in different bodies with overlapping
    active windows. Each embodiment is active from `validFrom` to `validUntil` (a
    missing `validUntil` is treated as open-ended). Two embodiments on different
    bodies whose windows overlap are a fork. Returns (ok, conflict) where conflict,
    when present, names the two conflicting bodies.
    """
    windows = []
    for embodiment in embodiments:
        subject = embodiment.get("credentialSubject") or {}
        body = subject.get("body")
        start = _parse_iso(embodiment.get("validFrom"))
        if body is None or start is None:
            return False, None
        end = _parse_iso(embodiment.get("validUntil"))  # None -> open-ended
        windows.append((body, start, end))

    for i in range(len(windows)):
        body_i, start_i, end_i = windows[i]
        for j in range(i + 1, len(windows)):
            body_j, start_j, end_j = windows[j]
            if body_i == body_j:
                continue
            if _overlaps(start_i, end_i, start_j, end_j):
                return False, {"bodyA": body_i, "bodyB": body_j}
    return True, None


def _overlaps(
    start_a: datetime,
    end_a: Optional[datetime],
    start_b: datetime,
    end_b: Optional[datetime],
) -> bool:
    # Half-open intervals [start, end); a missing end is +infinity. A clean handover
    # sets one window's end to the next window's start, which does not overlap.
    a_before_b = end_a is not None and end_a <= start_b
    b_before_a = end_b is not None and end_b <= start_a
    return not (a_before_b or b_before_a)


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
    "EMBODIMENT_TYPE",
    "build_embodiment",
    "verify_embodiment",
    "verify_continuity_chain",
    "check_no_fork",
]
