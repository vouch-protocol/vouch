"""
Robot accountable safety record: an incident and near-miss ledger plus a
portable safety-record credential.

Where the black box is an encrypted flight recorder for confidential telemetry,
the safety ledger is its accountable, readable counterpart: an append-only,
hash-linked log of the safety-relevant events in a robot's life (incidents,
near-misses, manual overrides, kill-switch triggers, envelope breaches). The
entries are plaintext on purpose, because their value is that an owner, an
insurer, or a regulator can read and trust them. The chain is tamper-evident, so
no entry can be altered or removed without detection.

A RobotSafetyRecordCredential is an eddsa-jcs-2022 VC that summarizes a stretch
of the ledger (counts by event type and by severity, the period covered, and the
ledger head hash that anchors it) into one portable, signed artifact that travels
with the robot across owners and across organizations. The summary reports the
event and severity counts directly.

The ledger reuses the black-box chain semantics so the two logs verify the same
way. Hosted safety-record registries, cross-fleet aggregation, and insurer feeds
are out of scope for the open layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .blackbox import GENESIS_PREV_HASH, _entry_hash, verify_blackbox_chain
from .identity import RoboticsError
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
SAFETY_RECORD_TYPE = "RobotSafetyRecordCredential"
SAFETY_LOG_VERSION = "1.0"

# Standard safety event types. Implementers MAY use additional types, but these
# are the interoperable set a verifier and an insurer can rely on.
EVENT_TYPES = frozenset(
    {
        "incident",
        "near_miss",
        "manual_override",
        "kill_switch",
        "envelope_breach",
        "maintenance",
    }
)

# Severity bands, ordered from least to most serious.
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class SafetyEventLog:
    """
    Append-only, plaintext, hash-linked safety event ledger.

    Each appended entry carries a sequence number, a timestamp, the event type,
    a severity, optional details, and the hash of the previous entry, so the log
    is tamper-evident. Unlike the black box, entries are not encrypted: a safety
    record is meant to be read and trusted by third parties.
    """

    genesis_prev_hash: str = GENESIS_PREV_HASH
    _entries: List[Dict[str, Any]] = field(default_factory=list, init=False)
    _head: str = field(default="", init=False)

    def __post_init__(self) -> None:
        self._head = self.genesis_prev_hash

    def append(
        self,
        event_type: str,
        *,
        severity: str = "info",
        details: Optional[Dict[str, Any]] = None,
        actor: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append one safety event and return the new entry."""
        if event_type not in EVENT_TYPES:
            raise RoboticsError(
                f"event_type must be one of {sorted(EVENT_TYPES)}, got {event_type!r}"
            )
        if severity not in SEVERITIES:
            raise RoboticsError(f"severity must be one of {SEVERITIES}, got {severity!r}")

        body: Dict[str, Any] = {
            "version": SAFETY_LOG_VERSION,
            "seq": len(self._entries),
            "timestamp": timestamp or _iso(datetime.now(timezone.utc)),
            "eventType": event_type,
            "severity": severity,
            "prevHash": self._head,
        }
        if details is not None:
            body["details"] = details
        if actor is not None:
            body["actor"] = actor
        body["entryHash"] = _entry_hash(body)
        self._entries.append(body)
        self._head = body["entryHash"]
        return body

    def head(self) -> str:
        return self._head

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]

    def summarize(self) -> Dict[str, Any]:
        """Produce a summary object for embedding in a safety-record credential."""
        return summarize_entries(self._entries, head=self._head)


def verify_safety_log(
    entries: List[Dict[str, Any]],
    genesis_prev_hash: str = GENESIS_PREV_HASH,
) -> "tuple[bool, Optional[str]]":
    """Verify the hash chain over the ledger entries. Tamper-evident."""
    return verify_blackbox_chain(entries, genesis_prev_hash)


def summarize_entries(
    entries: List[Dict[str, Any]],
    *,
    head: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Summarize ledger entries into counts by event type and by severity, the total
    event count, and (when supplied) the ledger head hash that anchors the
    summary to a specific chain state.
    """
    event_counts = {t: 0 for t in sorted(EVENT_TYPES)}
    severity_counts = {s: 0 for s in SEVERITIES}
    for e in entries:
        et = e.get("eventType")
        sv = e.get("severity")
        if et in event_counts:
            event_counts[et] += 1
        if sv in severity_counts:
            severity_counts[sv] += 1
    summary: Dict[str, Any] = {
        "eventCounts": event_counts,
        "severityCounts": severity_counts,
        "totalEvents": len(entries),
    }
    if head is not None:
        summary["logHead"] = head
    return summary


def build_safety_record(
    signer: Any,
    *,
    robot_did: str,
    summary: Dict[str, Any],
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed RobotSafetyRecordCredential summarizing a robot's safety
    ledger. The issuer (an owner, an auditor, or the robot itself) attests the
    summary; `summary` is produced by SafetyEventLog.summarize or summarize_entries.
    """
    validate_safety_summary(summary)

    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {"id": robot_did, **summary}
    if period_start is not None or period_end is not None:
        period: Dict[str, Any] = {}
        if period_start is not None:
            period["start"] = _iso(period_start)
        if period_end is not None:
            period["end"] = _iso(period_end)
        subject["period"] = period

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", SAFETY_RECORD_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def validate_safety_summary(summary: Dict[str, Any]) -> None:
    """Structural validation of a safety summary. Raises RoboticsError if malformed."""
    if not isinstance(summary, dict):
        raise RoboticsError("summary must be a dict")
    for name in ("eventCounts", "severityCounts"):
        block = summary.get(name)
        if not isinstance(block, dict):
            raise RoboticsError(f"summary.{name} must be a dict")
        for k, v in block.items():
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise RoboticsError(f"summary.{name}[{k!r}] must be a non-negative integer")
    total = summary.get("totalEvents")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise RoboticsError("summary.totalEvents must be a non-negative integer")


def verify_safety_record(
    credential: Dict[str, Any],
    public_key: Any,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a RobotSafetyRecordCredential: the issuer's proof and the structural
    validity of the embedded summary. Returns (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if SAFETY_RECORD_TYPE not in type_field:
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
    try:
        validate_safety_summary(subject)
    except RoboticsError:
        return False, None
    return True, subject


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "SAFETY_RECORD_TYPE",
    "EVENT_TYPES",
    "SEVERITIES",
    "SafetyEventLog",
    "verify_safety_log",
    "summarize_entries",
    "build_safety_record",
    "verify_safety_record",
    "validate_safety_summary",
]
