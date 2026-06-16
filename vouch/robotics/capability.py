"""
Physical capability scope schema for robots (Phase 5.3).

Extends the capability/attenuation model to the physical world: the maximum
force and speed a robot may exert, a slower speed cap near humans, the zones it
may operate in, and the shift windows during which it may act. A physical scope
is carried in a signed credential, so the bound is cryptographically enforceable:
a controller checks a proposed physical action against the granted scope before
actuating, and a delegated scope must attenuate (narrow, never broaden) its
parent.

Physical scope schema (credentialSubject.physicalScope):

  {
    "maxForceN": <number, newtons>,
    "maxSpeedMps": <number, m/s>,
    "maxSpeedNearHumansMps": <number, m/s>,
    "allowedZones": [<zone id string>, ...],
    "shiftWindows": [{"start": "HH:MM", "end": "HH:MM"}, ...]
  }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
PHYSICAL_SCOPE_TYPE = "PhysicalCapabilityScope"


class PhysicalScopeError(Exception):
    """Raised on malformed physical-scope input."""


@dataclass
class PhysicalAction:
    """A proposed physical action to check against a scope."""

    force_n: Optional[float] = None
    speed_mps: Optional[float] = None
    near_humans: bool = False
    zone: Optional[str] = None
    time_hm: Optional[str] = None  # "HH:MM" local


@dataclass
class CheckResult:
    ok: bool
    reasons: List[str] = field(default_factory=list)


def build_physical_scope_credential(
    signer: Any,
    *,
    subject_did: str,
    max_force_n: Optional[float] = None,
    max_speed_mps: Optional[float] = None,
    max_speed_near_humans_mps: Optional[float] = None,
    allowed_zones: Optional[List[str]] = None,
    shift_windows: Optional[List[Dict[str, str]]] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a signed PhysicalCapabilityScope credential."""
    scope: Dict[str, Any] = {}
    if max_force_n is not None:
        scope["maxForceN"] = max_force_n
    if max_speed_mps is not None:
        scope["maxSpeedMps"] = max_speed_mps
    if max_speed_near_humans_mps is not None:
        scope["maxSpeedNearHumansMps"] = max_speed_near_humans_mps
    if allowed_zones is not None:
        scope["allowedZones"] = list(allowed_zones)
    if shift_windows is not None:
        scope["shiftWindows"] = list(shift_windows)

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", PHYSICAL_SCOPE_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": {"id": subject_did, "physicalScope": scope},
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def _in_window(hm: str, window: Dict[str, str]) -> bool:
    return window.get("start", "00:00") <= hm <= window.get("end", "23:59")


def check_physical_action(scope: Dict[str, Any], action: PhysicalAction) -> CheckResult:
    """Check a proposed physical action against a physical scope object."""
    reasons: List[str] = []

    if action.force_n is not None and "maxForceN" in scope:
        if action.force_n > scope["maxForceN"]:
            reasons.append(f"force_exceeded: {action.force_n}N > {scope['maxForceN']}N")

    if action.speed_mps is not None:
        cap = scope.get("maxSpeedMps")
        if action.near_humans and "maxSpeedNearHumansMps" in scope:
            cap = scope["maxSpeedNearHumansMps"]
        if cap is not None and action.speed_mps > cap:
            label = "near_humans " if action.near_humans else ""
            reasons.append(f"{label}speed_exceeded: {action.speed_mps} m/s > {cap} m/s")

    if action.zone is not None and "allowedZones" in scope:
        if action.zone not in scope["allowedZones"]:
            reasons.append(f"zone_not_allowed: {action.zone}")

    if action.time_hm is not None and "shiftWindows" in scope:
        windows = scope["shiftWindows"]
        if windows and not any(_in_window(action.time_hm, w) for w in windows):
            reasons.append(f"outside_shift_window: {action.time_hm}")

    return CheckResult(ok=not reasons, reasons=reasons)


def attenuates(parent: Dict[str, Any], child: Dict[str, Any]) -> bool:
    """
    True if `child` is a valid attenuation of `parent`: never broader on any
    physical dimension. Numeric caps may only shrink; allowed zones may only be a
    subset; shift windows must each fit inside some parent window.
    """
    for key in ("maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"):
        if key in parent:
            if key not in child:
                return False  # child must keep (and may lower) a cap the parent set
            if child[key] > parent[key]:
                return False
        # child adding a cap the parent did not set only narrows; allowed.

    if "allowedZones" in parent:
        p_zones = set(parent["allowedZones"])
        c_zones = set(child.get("allowedZones", []))
        if not c_zones or not c_zones.issubset(p_zones):
            return False

    if "shiftWindows" in parent:
        p_windows = parent["shiftWindows"]
        for cw in child.get("shiftWindows", []):
            if not any(
                pw.get("start", "00:00") <= cw.get("start", "00:00")
                and cw.get("end", "23:59") <= pw.get("end", "23:59")
                for pw in p_windows
            ):
                return False
    return True


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PHYSICAL_SCOPE_TYPE",
    "PhysicalScopeError",
    "PhysicalAction",
    "CheckResult",
    "build_physical_scope_credential",
    "check_physical_action",
    "attenuates",
]
