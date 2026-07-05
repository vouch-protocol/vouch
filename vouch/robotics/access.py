"""
Robot-to-infrastructure bounded trust: authenticate a robot to physical resources.

A robot in a warehouse, hospital, or building needs to open doors, call elevators,
dock at chargers, and operate machines. This gives it a bounded, revocable,
auditable way to do so. The infrastructure operator issues an access grant naming a
resource, the permitted operations, an optional zone, and a time window, signed by
the operator. The robot presents a signed access request for a specific operation on
a specific resource, and the resource authorizes it offline: the grant must be valid
and operator-signed, the request valid and robot-signed, the operation permitted, and
the moment inside the window. The grant plus the request is a tamper-evident,
attributable record of the access.

This is the open layer: signed grants and requests, an offline authorize decision,
shrink-only attenuation, and the audit record. Hardware-enforced actuation in the
resource and managed fleet access-policy orchestration are out of scope for the open
layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
ACCESS_GRANT_TYPE = "InfrastructureAccessGrant"
ACCESS_REQUEST_TYPE = "InfrastructureAccessRequest"


# ---------------------------------------------------------------------------
# Access grant (operator -> robot)
# ---------------------------------------------------------------------------


def build_access_grant(
    operator_signer: Any,
    *,
    robot_did: str,
    resource: str,
    operations: List[str],
    zone: Optional[str] = None,
    valid_seconds: int,
    granted_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed access grant: the infrastructure operator grants `robot_did`
    permission to perform `operations` on `resource` (optionally within `zone`) for
    `valid_seconds`. Signed by the operator.
    """
    if not robot_did or not resource:
        raise RoboticsError("robot_did and resource are required")
    if not operations:
        raise RoboticsError("operations must be a non-empty list")
    issued = (granted_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "resource": resource,
        "operations": list(operations),
    }
    if zone is not None:
        subject["zone"] = zone

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ACCESS_GRANT_TYPE],
        "issuer": operator_signer.get_did(),
        "validFrom": _iso(issued),
        "validUntil": _iso(issued + timedelta(seconds=valid_seconds)),
        "credentialSubject": subject,
    }
    return attach_proof(credential, operator_signer)


def verify_access_grant(
    grant: Dict[str, Any],
    operator_public_key: Any,
    *,
    now: Optional[datetime] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an access grant: the operator's proof and that the grant is within its
    validity window at `now`. Returns (ok, subject).
    """
    ok, subject = _verify_typed(grant, operator_public_key, ACCESS_GRANT_TYPE)
    if not ok:
        return False, None
    if not subject.get("resource") or not subject.get("operations"):
        return False, None
    if not _within_window(grant, now):
        return False, None
    return True, subject


# ---------------------------------------------------------------------------
# Access request (robot) + authorize decision (resource, offline)
# ---------------------------------------------------------------------------


def build_access_request(
    robot_signer: Any,
    *,
    robot_did: str,
    resource: str,
    operation: str,
    requested_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed access request: the robot requests to perform `operation` on
    `resource`. Signed by the robot.
    """
    if not robot_did or not resource or not operation:
        raise RoboticsError("robot_did, resource, and operation are required")
    issued = (requested_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "resource": resource,
        "operation": operation,
    }
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ACCESS_REQUEST_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    return attach_proof(credential, robot_signer)


class AuthorizeResult:
    """The outcome of an offline access authorization: ok plus any reasons it failed."""

    def __init__(self, ok: bool, reasons: List[str]):
        self.ok = ok
        self.reasons = reasons

    def __repr__(self) -> str:
        return f"AuthorizeResult(ok={self.ok}, reasons={self.reasons})"


def authorize_access(
    grant: Dict[str, Any],
    request: Dict[str, Any],
    operator_public_key: Any,
    robot_public_key: Any,
    *,
    now: Optional[datetime] = None,
) -> AuthorizeResult:
    """
    Decide, offline, whether to allow the requested access. The grant must verify
    under the operator's key and be in window, the request must verify under the
    robot's key, the grant and request must name the same robot and resource, and the
    requested operation must be permitted by the grant. Returns an AuthorizeResult
    with the reasons for any refusal.
    """
    reasons: List[str] = []

    grant_ok, grant_subject = verify_access_grant(grant, operator_public_key, now=now)
    if not grant_ok:
        reasons.append("grant invalid or out of window")
        return AuthorizeResult(False, reasons)

    req_ok, req_subject = _verify_typed(request, robot_public_key, ACCESS_REQUEST_TYPE)
    if not req_ok or request.get("issuer") != req_subject.get("id"):
        reasons.append("request invalid")
        return AuthorizeResult(False, reasons)

    if grant_subject.get("id") != req_subject.get("id"):
        reasons.append("grant and request name different robots")
    if grant_subject.get("resource") != req_subject.get("resource"):
        reasons.append("grant and request name different resources")
    if req_subject.get("operation") not in (grant_subject.get("operations") or []):
        reasons.append("operation not permitted by the grant")

    return AuthorizeResult(not reasons, reasons)


# ---------------------------------------------------------------------------
# Attenuation (a sub-grant may only narrow)
# ---------------------------------------------------------------------------


def attenuates_grant(
    parent: Dict[str, Any],
    child: Dict[str, Any],
) -> bool:
    """
    Return True if `child` is a valid attenuation of `parent`: the same resource, a
    subset of the operations, and the same zone (or the parent had no zone). A
    sub-grant may only narrow, never widen, the access it inherits.
    """
    p = parent.get("credentialSubject") or {}
    c = child.get("credentialSubject") or {}
    if p.get("resource") != c.get("resource"):
        return False
    if not set(c.get("operations") or []).issubset(set(p.get("operations") or [])):
        return False
    if p.get("zone") is not None and c.get("zone") != p.get("zone"):
        return False
    return True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _within_window(credential: Dict[str, Any], now: Optional[datetime]) -> bool:
    at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = _parse_iso(credential.get("validFrom"))
    end = _parse_iso(credential.get("validUntil"))
    if start is not None and at < start:
        return False
    if end is not None and at > end:
        return False
    return True


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
    "ACCESS_GRANT_TYPE",
    "ACCESS_REQUEST_TYPE",
    "AuthorizeResult",
    "build_access_grant",
    "verify_access_grant",
    "build_access_request",
    "authorize_access",
    "attenuates_grant",
]
