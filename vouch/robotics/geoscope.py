"""
Ephemeris-scoped delegation authority (PAD-109).

A delegation lease bounded by a wall-clock window (PAD-076) assumes the holder
knows the current time. A node out of contact for a long period may have a drifted
or reset clock. This module expresses a grant's validity as a *geometric predicate*
over the holder's own navigation state — a bounding sphere, an axis-aligned box, or
an altitude band — evaluated offline by the holder against its measured position.
Authority is tied to *where the vehicle is*, which a disconnected node can decide
from onboard navigation, rather than to a clock it cannot trust.

Regions nest shrink-only: a sub-grant may only intersect (never enlarge) the
inherited region, so authority attenuates across regions down a chain, mirroring
the physical-scope attenuation of the delegation lease.

Region schema (credentialSubject.region):

  {"type": "sphere", "centerM": [x, y, z], "radiusM": <number>}
  {"type": "box",    "minM": [x, y, z], "maxM": [x, y, z]}
  {"type": "altitudeBand", "minM": <number>, "maxM": <number>}   # altitude = z

Positions are in one shared metric frame (meters); the caller is responsible for
using a consistent frame across the grant and the navigation solution.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
GEOSCOPED_GRANT_TYPE = "EphemerisScopedGrantCredential"

Vec3 = Sequence[float]


def _v3(x: Any, name: str) -> "List[float]":
    if not isinstance(x, (list, tuple)) or len(x) != 3:
        raise RoboticsError(f"{name} must be a 3-vector [x, y, z] in meters")
    return [float(v) for v in x]


def region_contains(region: Dict[str, Any], position: Vec3) -> bool:
    """True if `position` lies inside the region predicate."""
    if not isinstance(region, dict):
        raise RoboticsError("region must be an object")
    kind = region.get("type")
    p = _v3(position, "position")

    if kind == "sphere":
        center = _v3(region.get("centerM"), "region.centerM")
        radius = float(region.get("radiusM"))
        if radius < 0:
            raise RoboticsError("region.radiusM must be non-negative")
        d = math.sqrt(sum((p[i] - center[i]) ** 2 for i in range(3)))
        return d <= radius

    if kind == "box":
        lo = _v3(region.get("minM"), "region.minM")
        hi = _v3(region.get("maxM"), "region.maxM")
        return all(lo[i] <= p[i] <= hi[i] for i in range(3))

    if kind == "altitudeBand":
        lo = float(region.get("minM"))
        hi = float(region.get("maxM"))
        return lo <= p[2] <= hi

    raise RoboticsError(f"unknown region type: {kind!r}")


def region_attenuates(parent: Dict[str, Any], child: Dict[str, Any]) -> bool:
    """
    True if `child` is fully contained in `parent` (a valid shrink-only
    sub-region). Supported for matching region types; a type mismatch is not a
    valid attenuation and returns False.
    """
    if not isinstance(parent, dict) or not isinstance(child, dict):
        raise RoboticsError("regions must be objects")
    if parent.get("type") != child.get("type"):
        return False
    kind = parent.get("type")

    if kind == "sphere":
        pc = _v3(parent.get("centerM"), "parent.centerM")
        pr = float(parent.get("radiusM"))
        cc = _v3(child.get("centerM"), "child.centerM")
        cr = float(child.get("radiusM"))
        if cr < 0 or pr < 0:
            raise RoboticsError("radii must be non-negative")
        center_dist = math.sqrt(sum((cc[i] - pc[i]) ** 2 for i in range(3)))
        # child sphere fits inside parent sphere
        return center_dist + cr <= pr

    if kind == "box":
        plo = _v3(parent.get("minM"), "parent.minM")
        phi = _v3(parent.get("maxM"), "parent.maxM")
        clo = _v3(child.get("minM"), "child.minM")
        chi = _v3(child.get("maxM"), "child.maxM")
        return all(plo[i] <= clo[i] and chi[i] <= phi[i] for i in range(3))

    if kind == "altitudeBand":
        return (
            float(parent.get("minM")) <= float(child.get("minM"))
            and float(child.get("maxM")) <= float(parent.get("maxM"))
        )

    raise RoboticsError(f"unknown region type: {kind!r}")


def build_geoscoped_grant(
    signer: Any,
    *,
    holder_did: str,
    grant_id: str,
    region: Dict[str, Any],
    physical_scope: Optional[Dict[str, Any]] = None,
    parent_grant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a signed EphemerisScopedGrantCredential granting `holder_did` authority
    valid only while its navigation state satisfies `region`, optionally bounded
    by a `physical_scope` (same shape as a lease scope). Set `parent_grant_id`
    when sub-granting.
    """
    if not grant_id:
        raise RoboticsError("grant_id is required")
    # Validate the region shape up front (raises on malformed input).
    region_contains(region, [0.0, 0.0, 0.0])

    subject: Dict[str, Any] = {
        "id": holder_did,
        "grantId": grant_id,
        "region": region,
    }
    if physical_scope is not None:
        if not isinstance(physical_scope, dict):
            raise RoboticsError("physical_scope must be a physicalScope object")
        subject["physicalScope"] = physical_scope
    if parent_grant_id is not None:
        subject["parentGrantId"] = parent_grant_id

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", GEOSCOPED_GRANT_TYPE],
        "issuer": signer.get_did(),
        "credentialSubject": subject,
    }
    return attach_proof(credential, signer)


def verify_geoscoped_grant(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    parent_region: Optional[Dict[str, Any]] = None,
) -> "Tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an EphemerisScopedGrantCredential offline: the issuer's proof and
    (when `parent_region` is supplied) that this grant's region attenuates the
    parent. Does NOT evaluate holder position; call `geoscope_permits` at each
    action. Returns (ok, credentialSubject). No network call.
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if GEOSCOPED_GRANT_TYPE not in type_field:
        return False, None

    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = credential.get("credentialSubject") or {}
    region = subject.get("region")
    if not isinstance(region, dict):
        return False, None
    if parent_region is not None and not region_attenuates(parent_region, region):
        return False, None
    return True, subject


def geoscope_permits(subject: Dict[str, Any], position: Vec3) -> bool:
    """
    Decide whether a verified geoscoped grant permits action at `position`: the
    holder's navigation state must satisfy the grant's region.
    """
    region = subject.get("region")
    if not isinstance(region, dict):
        return False
    try:
        return region_contains(region, position)
    except RoboticsError:
        return False


__all__ = [
    "GEOSCOPED_GRANT_TYPE",
    "region_contains",
    "region_attenuates",
    "build_geoscoped_grant",
    "verify_geoscoped_grant",
    "geoscope_permits",
]
