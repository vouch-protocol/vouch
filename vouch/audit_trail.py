"""
Tamper-evident audit trail and human-oversight attestation (Specification §15).

The Shield flight recorder writes plain JSONL: useful, but any line can be
edited or removed without trace. This module formalizes that output into an
append-only, hash-chained audit trail where each entry commits to the previous
one, so any edit, reorder, or deletion breaks the chain. It adds a signed export
that binds the whole trail to one Data Integrity proof, and a human-oversight
attestation credential proving a named principal reviewed a specific action.

These are open formats and reference implementations. Per-regime compliance
packs and hosted report generators are out of scope here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import data_integrity, jcs

GENESIS_HASH = "0" * 64

CONTEXT = "https://vouch-protocol.com/audit/v1"
TRAIL_EXPORT_TYPE = "VouchAuditTrailExport"
OVERSIGHT_TYPE = "VouchHumanOversightAttestation"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_entry(content: Dict[str, Any]) -> str:
    """SHA-256 over the JCS-canonical bytes of the entry content."""
    return hashlib.sha256(jcs.canonicalize(content)).hexdigest()


@dataclass
class AuditEntry:
    """
    One link in the audit chain. `entry_hash` commits to every field above it,
    including `prev_hash`, so the chain is tamper-evident: change any field and
    the hash no longer matches, and every later entry's prev_hash is wrong too.
    """

    seq: int
    timestamp: str
    action: str
    actor: Optional[str] = None
    resource: Optional[str] = None
    decision: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def content(self) -> Dict[str, Any]:
        """The hashed content: every field except entry_hash, no None values."""
        c = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "decision": self.decision,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
        }
        return {k: v for k, v in c.items() if v is not None}

    def compute_hash(self) -> str:
        return _hash_entry(self.content())

    def to_dict(self) -> Dict[str, Any]:
        d = self.content()
        d["entry_hash"] = self.entry_hash
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuditEntry":
        return cls(
            seq=d["seq"],
            timestamp=d["timestamp"],
            action=d["action"],
            actor=d.get("actor"),
            resource=d.get("resource"),
            decision=d.get("decision"),
            metadata=d.get("metadata"),
            prev_hash=d.get("prev_hash", GENESIS_HASH),
            entry_hash=d.get("entry_hash", ""),
        )


class AuditTrail:
    """
    An append-only, hash-chained audit trail. Optionally persists to a JSONL
    file (one entry per line). The chain head (`head`) is the hash of the most
    recent entry and is what a signed export commits to.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._entries: List[AuditEntry] = []
        self._path = path

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    def append(
        self,
        action: str,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        decision: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            seq=len(self._entries),
            timestamp=timestamp or _now_iso(),
            action=action,
            actor=actor,
            resource=resource,
            decision=decision,
            metadata=metadata,
            prev_hash=self.head,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        if self._path:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict()) + "\n")
        return entry

    def verify(self) -> Tuple[bool, Optional[int]]:
        """
        Recompute the chain. Returns (ok, first_broken_seq). ok=True means every
        entry's hash matches its content and links to the prior entry.
        """
        return verify_entries(self._entries)

    @classmethod
    def from_flight_recorder(cls, log_entries: Iterable[Any]) -> "AuditTrail":
        """
        Build a tamper-evident trail from existing flight-recorder LogEntry
        objects (or their dicts). This formalizes the plain JSONL output.
        """
        trail = cls()
        for le in log_entries:
            d = le.to_dict() if hasattr(le, "to_dict") else dict(le)
            trail.append(
                action=d.get("event", d.get("action", "UNKNOWN")),
                actor=d.get("did") or d.get("actor"),
                resource=d.get("tool") or d.get("resource"),
                decision=d.get("reason"),
                metadata=d.get("metadata"),
                timestamp=d.get("timestamp"),
            )
        return trail


def verify_entries(entries: List[AuditEntry]) -> Tuple[bool, Optional[int]]:
    prev = GENESIS_HASH
    for i, e in enumerate(entries):
        if e.seq != i:
            return False, i
        if e.prev_hash != prev:
            return False, i
        if e.compute_hash() != e.entry_hash:
            return False, i
        prev = e.entry_hash
    return True, None


def load_trail(path: str) -> AuditTrail:
    """Load a trail from a JSONL file without re-hashing (for verification)."""
    trail = AuditTrail()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                trail._entries.append(AuditEntry.from_dict(json.loads(line)))
    return trail


# ---------------------------------------------------------------------------
# Signed export
# ---------------------------------------------------------------------------


def _raw_priv(signer: Any):
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise ValueError("signed export requires a Signer with an Ed25519 key")
    return raw


def signed_export(trail: AuditTrail, signer: Any) -> Dict[str, Any]:
    """
    Produce a signed export that commits to the whole trail. The export binds
    the entry count, the genesis prev_hash, and the chain head; signing it makes
    the entire chain non-repudiable. Verifiers recompute the chain and check the
    head matches before trusting the proof.
    """
    entries = trail.entries
    manifest = {
        "@context": CONTEXT,
        "type": TRAIL_EXPORT_TYPE,
        "count": len(entries),
        "head": trail.head,
        "exportedBy": signer.get_did(),
        "exportedAt": _now_iso(),
        "entries": [e.to_dict() for e in entries],
    }
    manifest["proof"] = data_integrity.build_proof(
        manifest, _raw_priv(signer), signer.verification_method_id()
    )
    return manifest


def verify_export(manifest: Dict[str, Any], public_key) -> Tuple[bool, List[str]]:
    """
    Verify a signed audit-trail export: the Data Integrity proof, the chain
    integrity, and that the declared head matches the recomputed head.
    """
    reasons: List[str] = []
    try:
        if not data_integrity.verify_proof(manifest, public_key):
            reasons.append("proof_invalid")
    except Exception as exc:
        reasons.append(f"proof_error:{exc}")

    entries = [AuditEntry.from_dict(d) for d in manifest.get("entries", [])]
    ok, broken = verify_entries(entries)
    if not ok:
        reasons.append(f"chain_broken_at_seq:{broken}")

    declared_head = manifest.get("head", GENESIS_HASH)
    actual_head = entries[-1].entry_hash if entries else GENESIS_HASH
    if declared_head != actual_head:
        reasons.append("head_mismatch")
    if manifest.get("count") != len(entries):
        reasons.append("count_mismatch")

    return (not reasons), reasons


# ---------------------------------------------------------------------------
# Human-oversight attestation credential
# ---------------------------------------------------------------------------


def build_human_oversight_attestation(
    signer: Any,
    *,
    reviewer: str,
    action_ref: str,
    decision: str,
    note: Optional[str] = None,
    reviewed_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    A signed credential proving a named human principal reviewed a specific
    action and reached a decision (for example "approved" or "rejected").

    Args:
      signer: the reviewer's (or the system's) Signer.
      reviewer: DID or identifier of the human who reviewed.
      action_ref: what was reviewed: an audit entry_hash, a credential id, or a
        URL identifying the action.
      decision: the reviewer's decision, e.g. "approved" or "rejected".
      note: optional free-text rationale.
    """
    credential = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            CONTEXT,
        ],
        "type": ["VerifiableCredential", OVERSIGHT_TYPE],
        "issuer": signer.get_did(),
        "validFrom": reviewed_at or _now_iso(),
        "credentialSubject": {
            "reviewer": reviewer,
            "actionRef": action_ref,
            "decision": decision,
        },
    }
    if note:
        credential["credentialSubject"]["note"] = note
    credential["proof"] = data_integrity.build_proof(
        credential, _raw_priv(signer), signer.verification_method_id()
    )
    return credential


def verify_human_oversight_attestation(credential: Dict[str, Any], public_key) -> bool:
    """Verify the Data Integrity proof on a human-oversight attestation."""
    try:
        return data_integrity.verify_proof(credential, public_key)
    except Exception:
        return False
