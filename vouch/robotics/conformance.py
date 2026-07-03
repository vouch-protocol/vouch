"""
Regulatory conformance profiles for robots.

A conformance profile is a machine-checkable mapping from Vouch robotics
credentials to the clauses of a public safety or AI regulation. Given the
credentials a robot presents, the checker reports which clauses are satisfied and
cites each one, and an issuer can sign a point-in-time conformance attestation an
auditor or notified body can consume.

The built-in profiles cover ISO 10218-1/-2 (industrial robots), ISO/TS 15066
(collaborative, power and force limiting), the EU Machinery Regulation 2023/1230,
the EU AI Act high-risk requirements, and UL 3300 (service and mobile robots).
They are a reference crosswalk to make conformance verifiable in the open, not
legal advice; a deployment confirms the mapping against the current text of each
regulation.

This is the open layer: declarative profiles, a deterministic checker, and a
signed point-in-time attestation over the full report. Hosted continuous
monitoring, maintained and certified profiles, and auditor evidence portals are
out of scope for the open layer.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from vouch.jcs import canonicalize

from ._signing import attach_proof
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
CONFORMANCE_ATTESTATION_TYPE = "RobotConformanceAttestation"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------
#
# A requirement is satisfied when the presented credential set contains a
# credential whose `type` includes `credential` and whose credentialSubject has a
# non-null value at every path in `fields` (dot-separated, rooted at the subject).
# Profiles are plain data so every language reproduces them identically.


def _req(rid: str, clause: str, title: str, credential: str, fields: Optional[List[str]] = None):
    return {
        "id": rid,
        "clause": clause,
        "title": title,
        "credential": credential,
        "fields": fields or [],
    }


PROFILES: Dict[str, Dict[str, Any]] = {
    "iso-10218": {
        "regime": "ISO 10218-1/-2 industrial robots",
        "version": "2011",
        "requirements": [
            _req(
                "iso10218-identification",
                "ISO 10218-1:2011, 5.2",
                "Robot identification bound to its hardware",
                "RobotIdentityCredential",
                ["hardwareRoot.kind"],
            ),
            _req(
                "iso10218-software-integrity",
                "ISO 10218-1:2011, 5.3",
                "Control software and configuration integrity",
                "ModelProvenanceAttestation",
                ["vla.weightsHash"],
            ),
            _req(
                "iso10218-limits",
                "ISO 10218-1:2011, 5.6",
                "Limiting of speed, force, and workspace",
                "PhysicalCapabilityScope",
                ["physicalScope.maxForceN", "physicalScope.maxSpeedMps"],
            ),
            _req(
                "iso10218-records",
                "ISO 10218-2:2011, 5.2",
                "Records of safety-relevant events",
                "RobotSafetyRecordCredential",
                ["totalEvents"],
            ),
        ],
    },
    "iso-ts-15066": {
        "regime": "ISO/TS 15066 collaborative robots",
        "version": "2016",
        "requirements": [
            _req(
                "iso15066-power-force-limiting",
                "ISO/TS 15066:2016, 5.5.4",
                "Power and force limiting near humans",
                "PhysicalCapabilityScope",
                ["physicalScope.maxSpeedNearHumansMps", "physicalScope.maxForceN"],
            ),
            _req(
                "iso15066-collaborative-workspace",
                "ISO/TS 15066:2016, 5.5.2",
                "Defined collaborative workspace",
                "PhysicalCapabilityScope",
                ["physicalScope.allowedZones"],
            ),
            _req(
                "iso15066-monitoring",
                "ISO/TS 15066:2016, 5.2",
                "Continuous monitoring of the collaborative operation",
                "RobotHeartbeatCredential",
                ["motionDigest"],
            ),
        ],
    },
    "eu-machinery-2023-1230": {
        "regime": "EU Machinery Regulation 2023/1230",
        "version": "2023",
        "requirements": [
            _req(
                "eu-mr-identification",
                "Reg (EU) 2023/1230, Annex III 1.7.4",
                "Machinery identification and traceability",
                "RobotIdentityCredential",
                ["make", "model", "serial"],
            ),
            _req(
                "eu-mr-software-integrity",
                "Reg (EU) 2023/1230, Annex III 1.1.9",
                "Protection against corruption of safety software",
                "ModelProvenanceAttestation",
                ["vla.weightsHash", "vla.safetyPolicy"],
            ),
            _req(
                "eu-mr-safe-limits",
                "Reg (EU) 2023/1230, Annex III 1.2.1",
                "Safety and reliability of control systems and limits",
                "PhysicalCapabilityScope",
                ["physicalScope.maxForceN"],
            ),
            _req(
                "eu-mr-records",
                "Reg (EU) 2023/1230, Annex III 1.2.1",
                "Recording of safety-relevant data",
                "RobotSafetyRecordCredential",
                ["totalEvents"],
            ),
        ],
    },
    "eu-ai-act-high-risk": {
        "regime": "EU AI Act high-risk systems",
        "version": "2024",
        "requirements": [
            _req(
                "eu-aia-record-keeping",
                "Reg (EU) 2024/1689, Art. 12",
                "Automatic recording of events (logging)",
                "RobotSafetyRecordCredential",
                ["logHead"],
            ),
            _req(
                "eu-aia-transparency",
                "Reg (EU) 2024/1689, Art. 13",
                "Model and configuration transparency",
                "ModelProvenanceAttestation",
                ["vla.modelName", "vla.configHash"],
            ),
            _req(
                "eu-aia-human-oversight",
                "Reg (EU) 2024/1689, Art. 14",
                "Human oversight through enforced operating limits",
                "PhysicalCapabilityScope",
                ["physicalScope.maxSpeedNearHumansMps"],
            ),
            _req(
                "eu-aia-accuracy-robustness",
                "Reg (EU) 2024/1689, Art. 15",
                "Accuracy and robustness traceable to a known build",
                "ModelProvenanceAttestation",
                ["vla.weightsHash"],
            ),
        ],
    },
    "ul-3300": {
        "regime": "UL 3300 service, communication, and mobile robots",
        "version": "2022",
        "requirements": [
            _req(
                "ul3300-identity",
                "UL 3300, identification",
                "Robot identity bound to its hardware",
                "RobotIdentityCredential",
                ["hardwareRoot.kind"],
            ),
            _req(
                "ul3300-operating-limits",
                "UL 3300, operating limits",
                "Enforced speed and zone limits",
                "PhysicalCapabilityScope",
                ["physicalScope.maxSpeedMps", "physicalScope.allowedZones"],
            ),
            _req(
                "ul3300-perception-integrity",
                "UL 3300, sensing integrity",
                "Integrity of perception used for safe operation",
                "PerceptionProvenanceCredential",
                ["frameHash"],
            ),
            _req(
                "ul3300-records",
                "UL 3300, incident records",
                "Records of safety-relevant incidents",
                "RobotSafetyRecordCredential",
                ["totalEvents"],
            ),
        ],
    },
}


def profile(profile_id: str) -> Dict[str, Any]:
    """Return a built-in profile by id, or raise if it is unknown."""
    prof = PROFILES.get(profile_id)
    if prof is None:
        raise RoboticsError(f"unknown conformance profile: {profile_id}")
    return prof


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------


def _types(credential: Dict[str, Any]) -> List[str]:
    field = credential.get("type") or []
    return [field] if isinstance(field, str) else list(field)


def _path_value(subject: Dict[str, Any], path: str) -> Any:
    node: Any = subject
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _credential_satisfies(credential: Dict[str, Any], requirement: Dict[str, Any]) -> bool:
    if requirement["credential"] not in _types(credential):
        return False
    subject = credential.get("credentialSubject") or {}
    for path in requirement["fields"]:
        value = _path_value(subject, path)
        if value is None or value == [] or value == {}:
            return False
    return True


def check_conformance(
    credentials: List[Dict[str, Any]],
    profile_id: str,
) -> Dict[str, Any]:
    """
    Check the presented `credentials` against the named profile and return a
    deterministic report. Each requirement is satisfied when some presented
    credential matches its type and has every required field. The caller is
    expected to have verified the credentials' signatures first; this checks
    structure and coverage, not proofs.

    The report is:
      {
        "profileId", "regime", "version",
        "conforms": bool, "satisfiedCount", "totalCount",
        "requirements": [{"id", "clause", "title", "satisfied"}],
      }
    """
    prof = profile(profile_id)
    results: List[Dict[str, Any]] = []
    satisfied = 0
    for requirement in prof["requirements"]:
        ok = any(_credential_satisfies(c, requirement) for c in credentials)
        if ok:
            satisfied += 1
        results.append(
            {
                "id": requirement["id"],
                "clause": requirement["clause"],
                "title": requirement["title"],
                "satisfied": ok,
            }
        )
    total = len(prof["requirements"])
    return {
        "profileId": profile_id,
        "regime": prof["regime"],
        "version": prof["version"],
        "conforms": satisfied == total,
        "satisfiedCount": satisfied,
        "totalCount": total,
        "requirements": results,
    }


def report_digest(report: Dict[str, Any]) -> str:
    """Multibase SHA-256 of the JCS-canonical report, for binding into an attestation."""
    digest = hashlib.sha256(canonicalize(report)).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Signed conformance attestation
# ---------------------------------------------------------------------------


def build_conformance_attestation(
    signer: Any,
    *,
    robot_did: str,
    report: Dict[str, Any],
    attested_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed point-in-time conformance attestation for `robot_did` over a
    `report` produced by check_conformance. The signer is the robot, its owner, or
    an assessing authority. The report is embedded and bound by digest.
    """
    if not robot_did:
        raise RoboticsError("robot_did is required")
    if "profileId" not in report or "conforms" not in report:
        raise RoboticsError("report must come from check_conformance")
    issued = (attested_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "profileId": report["profileId"],
        "regime": report["regime"],
        "conforms": report["conforms"],
        "satisfiedCount": report["satisfiedCount"],
        "totalCount": report["totalCount"],
        "reportDigest": report_digest(report),
        "report": report,
    }
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONFORMANCE_ATTESTATION_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def verify_conformance_attestation(
    credential: Dict[str, Any],
    public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a conformance attestation: the issuer's proof and that the embedded
    report matches its bound digest. Returns (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    if CONFORMANCE_ATTESTATION_TYPE not in _types(credential):
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
    embedded = subject.get("report")
    if not isinstance(embedded, dict):
        return False, None
    if subject.get("reportDigest") != report_digest(embedded):
        return False, None
    if subject.get("conforms") != embedded.get("conforms"):
        return False, None
    return True, subject


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "CONFORMANCE_ATTESTATION_TYPE",
    "PROFILES",
    "profile",
    "check_conformance",
    "report_digest",
    "build_conformance_attestation",
    "verify_conformance_attestation",
]
