"""
Halos safety-evidence recorder (NVIDIA Halos integration).

NVIDIA Halos certifies that a robot's stack is functionally safe and secure by
design. It does not, on its own, produce a verifiable record of what a specific
robot did, or bind that record to the robot's identity. This module is the
evidence layer that sits under a Halos-certified stack.

A `SafetyEventRecorder` captures the safety-relevant event stream produced by the
Halos Outside-In Safety Blueprint components (the Safety AI Monitor, the Safety
Event Integrator, the Safety Decision Maker, and the sensor input pipeline), plus
emergency stops and operator actions, into the tamper-evident, encrypted black-box
(the robot flight recorder). The robot then signs a `HalosSafetyEvidenceCredential`
that seals the black-box chain head and entry count and binds them to the robot's
identity and to the exact Halos stack elements it ran on (the IGX system-on-module,
the Halos Core version, and the Blueprint applications).

A verifier that holds the sealed credential and the entries confirms four things
without needing the black-box key: the record is unaltered, it has not been
truncated or extended since it was sealed, it is attributable to that specific
robot, and it names the certified Halos configuration it was produced on. Only a
holder of the black-box key can read the payloads, so the record stays confidential
while remaining verifiable.

This ships the formats and the reference recorder. It composes the existing
black-box and robot-identity primitives and adds no new cryptography.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .blackbox import GENESIS_PREV_HASH, BlackBoxLog, verify_blackbox_chain
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
HALOS_SAFETY_EVIDENCE_TYPE = "HalosSafetyEvidenceCredential"

# The safety-relevant event producers in a Halos-certified stack: the four
# Outside-In Safety Blueprint components, plus an emergency stop and an operator
# action. A recorder rejects any event from a source outside this set, so the
# record maps to a known part of the certified stack.
HALOS_EVENT_SOURCES = frozenset(
    {
        "SIPP",  # Sensor Input Processing Pipeline
        "SAIM",  # Safety AI Monitor
        "SEI",  # Safety Event Integrator
        "SDM",  # Safety Decision Maker (runs on the IGX Functional Safety Island)
        "estop",  # emergency stop
        "operator",  # human operator action
    }
)


class HalosError(Exception):
    """Raised on invalid Halos safety-evidence input."""


class SafetyEventRecorder:
    """
    Records the Halos safety-event stream into the tamper-evident black-box.

    Wraps a `BlackBoxLog`: each recorded event is encrypted and hash-linked, so
    the stream is confidential yet tamper-evident. `key` is 32 bytes (AES-256).
    """

    def __init__(self, key: bytes) -> None:
        self._log = BlackBoxLog(key=key)

    def record(
        self,
        source: str,
        event: str,
        detail: Optional[Dict[str, Any]] = None,
        *,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record one safety event from a named Halos stack source."""
        if source not in HALOS_EVENT_SOURCES:
            raise HalosError(f"unknown Halos event source: {source!r}")
        payload = {"source": source, "detail": detail or {}}
        return self._log.append(event, payload, timestamp=timestamp)

    def head(self) -> str:
        return self._log.head()

    def count(self) -> int:
        return len(self._log.entries())

    def entries(self) -> List[Dict[str, Any]]:
        return self._log.entries()

    def open_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt one entry with this recorder's black-box key."""
        return self._log.open_entry(entry)


def build_safety_evidence(
    robot_signer: Any,
    *,
    halos_stack: Dict[str, Any],
    window: Dict[str, str],
    recorder: Optional[SafetyEventRecorder] = None,
    blackbox_head: Optional[str] = None,
    entry_count: Optional[int] = None,
    robot_identity: Optional[str] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
    created: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Seal a robot's Halos safety-event record into a signed HalosSafetyEvidenceCredential.

    The robot signs a credential that binds the black-box chain head and entry
    count to its identity, to the Halos stack elements it ran on, and to the time
    window. Pass either a `recorder` or an explicit `blackbox_head` + `entry_count`.

    Args:
      halos_stack: the certified Halos configuration, for example
        {"igxSom": "...", "halosCore": "...", "blueprint": ["SAIM", "SEI", "SDM"]}.
      window: {"from": iso, "to": iso} covering the recorded events.
      robot_identity: optional reference (credential id or hash) to the robot's
        hardware-rooted identity credential, tying the evidence to it.
      created: overrides the proof timestamp for reproducible test vectors.
    """
    if not halos_stack:
        raise HalosError("halos_stack is required")
    if not window or "from" not in window or "to" not in window:
        raise HalosError("window with 'from' and 'to' is required")

    if recorder is not None:
        head = recorder.head()
        count = recorder.count()
    else:
        if blackbox_head is None or entry_count is None:
            raise HalosError("pass a recorder, or both blackbox_head and entry_count")
        head = blackbox_head
        count = entry_count
    if count < 0:
        raise HalosError("entry_count cannot be negative")

    robot_did = robot_signer.get_did()
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "blackboxHead": head,
        "entryCount": count,
        "halosStack": halos_stack,
        "window": {"from": window["from"], "to": window["to"]},
    }
    if robot_identity is not None:
        subject["robotIdentity"] = robot_identity

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", HALOS_SAFETY_EVIDENCE_TYPE],
        "issuer": robot_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, robot_signer, created=created)


def verify_safety_evidence(
    credential: Dict[str, Any],
    robot_public_key: Any,
    *,
    entries: Optional[List[Dict[str, Any]]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a HalosSafetyEvidenceCredential.

    Checks the robot's proof and that the issuer is the robot. When `entries` are
    supplied, also checks that the black-box chain is intact, that its length
    matches the sealed entry count, and that its head matches the sealed head, so a
    truncated, extended, reordered, or tampered record is rejected. Returns
    (ok, credentialSubject).
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if HALOS_SAFETY_EVIDENCE_TYPE not in type_field:
        return False, None

    resolved = (
        _coerce_ed25519_public_key(robot_public_key) if robot_public_key is not None else None
    )
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    subject = credential.get("credentialSubject") or {}
    if subject.get("id") != credential.get("issuer"):
        return False, None

    if entries is not None:
        ok, _ = verify_blackbox_chain(entries)
        if not ok:
            return False, None
        if len(entries) != subject.get("entryCount"):
            return False, None
        head = entries[-1]["entryHash"] if entries else GENESIS_PREV_HASH
        if head != subject.get("blackboxHead"):
            return False, None

    return True, subject


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "HALOS_SAFETY_EVIDENCE_TYPE",
    "HALOS_EVENT_SOURCES",
    "HalosError",
    "SafetyEventRecorder",
    "build_safety_evidence",
    "verify_safety_evidence",
]
