"""
Operating-domain (ODD) conformance for robots.

An autonomous robot is certified to operate inside an operational design domain:
the zones it may work in, a speed regime, the environmental conditions it is rated
for, and the hours it may run. Acting outside that domain is where certification
stops applying and where incidents cluster. This module lets an operator certify a
robot's operating domain as a signed credential, lets the robot self-sign that it
stayed inside the domain over an interval, and provides a deterministic check that
compares observed operating parameters against the certified domain, so operating
out of domain is detectable and attributable.

An operating-domain credential names the allowed zones, a maximum speed, condition
bounds (for example a maximum wind speed and a minimum visibility), and the time
windows the robot is rated for, signed by the operator. An ODD conformance
attestation reports the parameters the robot observed over an interval and whether
they stayed inside the domain, signed by the robot.

This is the open layer: the signed domain credential, the conformance attestation,
and the deterministic in-domain check. Real-time prediction of an imminent
out-of-domain excursion and automatic safe-stop enforcement are out of scope for
the open layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
OPERATING_DOMAIN_TYPE = "OperatingDomainCredential"
ODD_CONFORMANCE_TYPE = "ODDConformanceAttestation"


@dataclass
class ODDResult:
    ok: bool
    reasons: List[str] = field(default_factory=list)


def build_odd_credential(
    operator_signer: Any,
    *,
    robot_did: str,
    allowed_zones: Optional[List[str]] = None,
    max_speed_mps: Optional[float] = None,
    conditions: Optional[Dict[str, float]] = None,
    time_windows: Optional[List[Dict[str, str]]] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed OperatingDomainCredential: the operator certifies `robot_did` to
    operate within the given domain. `conditions` carries upper or lower bounds keyed
    by name (for example maxWindMps or minVisibilityM). Signed by the operator.
    """
    if not robot_did:
        raise RoboticsError("robot_did is required")
    domain: Dict[str, Any] = {}
    if allowed_zones is not None:
        domain["allowedZones"] = list(allowed_zones)
    if max_speed_mps is not None:
        domain["maxSpeedMps"] = max_speed_mps
    if conditions is not None:
        domain["conditions"] = dict(conditions)
    if time_windows is not None:
        domain["timeWindows"] = list(time_windows)

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", OPERATING_DOMAIN_TYPE],
        "issuer": operator_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": {"id": robot_did, "operatingDomain": domain},
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, operator_signer)


def verify_odd_credential(
    credential: Dict[str, Any],
    operator_public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """Verify an OperatingDomainCredential and return (ok, operatingDomain)."""
    ok, subject = _verify_typed(credential, operator_public_key, OPERATING_DOMAIN_TYPE)
    if not ok:
        return False, None
    return True, subject.get("operatingDomain") or {}


def check_in_domain(domain: Dict[str, Any], observed: Dict[str, Any]) -> ODDResult:
    """
    Check observed operating parameters against a certified domain. `observed` may
    carry maxSpeedMps, zones (a list visited), conditions (observed values keyed by
    the same names), and timeHm ("HH:MM"). A condition key prefixed max* is an upper
    bound, min* a lower bound. An absent domain dimension is unconstrained.
    """
    reasons: List[str] = []

    if "maxSpeedMps" in domain and observed.get("maxSpeedMps") is not None:
        if observed["maxSpeedMps"] > domain["maxSpeedMps"]:
            reasons.append(
                f"speed_out_of_domain: {observed['maxSpeedMps']} > {domain['maxSpeedMps']}"
            )

    if "allowedZones" in domain and observed.get("zones") is not None:
        allowed = set(domain["allowedZones"])
        outside = [z for z in observed["zones"] if z not in allowed]
        if outside:
            reasons.append(f"zone_out_of_domain: {outside}")

    if "conditions" in domain and observed.get("conditions") is not None:
        for key, bound in domain["conditions"].items():
            val = observed["conditions"].get(key)
            if val is None:
                continue
            if key.startswith("max") and val > bound:
                reasons.append(f"condition_out_of_domain: {key} {val} > {bound}")
            elif key.startswith("min") and val < bound:
                reasons.append(f"condition_out_of_domain: {key} {val} < {bound}")

    if "timeWindows" in domain and observed.get("timeHm") is not None:
        windows = domain["timeWindows"]
        if windows and not any(_in_window(observed["timeHm"], w) for w in windows):
            reasons.append(f"time_out_of_domain: {observed['timeHm']}")

    return ODDResult(ok=not reasons, reasons=reasons)


def build_odd_conformance(
    robot_signer: Any,
    *,
    robot_did: str,
    domain: Dict[str, Any],
    observed: Dict[str, Any],
    interval_index: int,
    attested_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed ODDConformanceAttestation: the robot reports the `observed`
    operating parameters over interval `interval_index` and whether they stayed
    inside `domain`. The in-domain verdict is computed here and carried in the
    attestation. Signed by the robot.
    """
    if not robot_did:
        raise RoboticsError("robot_did is required")
    result = check_in_domain(domain, observed)
    issued = (attested_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "intervalIndex": interval_index,
        "observed": dict(observed),
        "inDomain": result.ok,
        "reasons": list(result.reasons),
    }
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ODD_CONFORMANCE_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, robot_signer)


def verify_odd_conformance(
    credential: Dict[str, Any],
    robot_public_key: Any,
    *,
    domain: Optional[Dict[str, Any]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify an ODDConformanceAttestation: the robot's proof and, when `domain` is
    supplied, that recomputing the in-domain check over the attested observations
    reproduces the attested `inDomain` verdict, so the robot cannot claim it stayed
    in domain when its own reported observations say otherwise. Returns (ok, subject).
    """
    ok, subject = _verify_typed(credential, robot_public_key, ODD_CONFORMANCE_TYPE)
    if not ok:
        return False, None
    if credential.get("issuer") != subject.get("id"):
        return False, None
    if domain is not None:
        recomputed = check_in_domain(domain, subject.get("observed") or {})
        if recomputed.ok != bool(subject.get("inDomain")):
            return False, None
    return True, subject


def _in_window(hm: str, window: Dict[str, str]) -> bool:
    return window.get("start", "00:00") <= hm <= window.get("end", "23:59")


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
    "OPERATING_DOMAIN_TYPE",
    "ODD_CONFORMANCE_TYPE",
    "ODDResult",
    "build_odd_credential",
    "verify_odd_credential",
    "check_in_domain",
    "build_odd_conformance",
    "verify_odd_conformance",
]
