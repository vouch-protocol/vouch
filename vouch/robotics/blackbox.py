"""
Robot black-box log and kill-switch credential (Phase 5.5).

The black box is an append-only, signed, encrypted event log: the robot flight
recorder. Each entry's payload is encrypted with AES-256-GCM and hash-linked to
the previous entry, so the log is confidential yet tamper-evident, and the chain
head can be signed to anchor the whole log. Only a holder of the black-box key
can read the payloads; anyone can verify the chain.

The kill-switch credential is a verifiable record of an emergency stop: it proves
who issued the stop, what it targets, and (when an authority allowlist is
supplied) that only an attested authority could have triggered it.

This ships the formats and reference libraries. Hosted black-box storage and
fleet-scale kill-switch infrastructure are out of scope.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vouch.jcs import canonicalize
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
KILLSWITCH_TYPE = "KillSwitchCredential"
BLACKBOX_VERSION = "1.0"
GENESIS_PREV_HASH = "u" + base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode("ascii")
EMERGENCY_STOP = "emergency_stop"


class BlackBoxError(Exception):
    """Raised on black-box log or kill-switch errors."""


def _mb64(b: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unmb64(s: str) -> bytes:
    if not s.startswith("u"):
        raise BlackBoxError("expected multibase 'u' prefix")
    payload = s[1:]
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def _entry_hash(body: Dict[str, Any]) -> str:
    clean = {k: v for k, v in body.items() if k != "entryHash"}
    return _mb64(hashlib.sha256(canonicalize(clean)).digest())


@dataclass
class BlackBoxLog:
    """Append-only, encrypted, hash-linked event log. `key` is 32 bytes (AES-256)."""

    key: bytes
    genesis_prev_hash: str = GENESIS_PREV_HASH
    _entries: List[Dict[str, Any]] = field(default_factory=list, init=False)
    _head: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise BlackBoxError("key must be 32 bytes (AES-256)")
        self._head = self.genesis_prev_hash

    def append(
        self,
        event: str,
        payload: Dict[str, Any],
        *,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        nonce = os.urandom(12)
        plaintext = canonicalize(payload)
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, None)
        body = {
            "version": BLACKBOX_VERSION,
            "seq": len(self._entries),
            "timestamp": timestamp or _iso(datetime.now(timezone.utc)),
            "event": event,
            "ciphertext": _mb64(nonce + ciphertext),
            "prevHash": self._head,
        }
        body["entryHash"] = _entry_hash(body)
        self._entries.append(body)
        self._head = body["entryHash"]
        return body

    def head(self) -> str:
        return self._head

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]

    def open_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt one entry's payload with this log's key."""
        return open_entry(entry, self.key)


def open_entry(entry: Dict[str, Any], key: bytes) -> Dict[str, Any]:
    """Decrypt a black-box entry payload. Returns the original payload dict."""
    import json

    blob = _unmb64(entry["ciphertext"])
    nonce, ciphertext = blob[:12], blob[12:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:  # noqa: BLE001 - decryption failure (wrong key/tampered)
        raise BlackBoxError(f"decryption failed: {exc}") from exc
    return json.loads(plaintext.decode("utf-8"))


def verify_blackbox_chain(
    entries: List[Dict[str, Any]],
    genesis_prev_hash: str = GENESIS_PREV_HASH,
) -> "tuple[bool, Optional[str]]":
    """Verify the hash chain over (encrypted) entries. Tamper-evident without the key."""
    prev = genesis_prev_hash
    for i, entry in enumerate(entries):
        if entry.get("seq") != i:
            return False, f"entry {i} seq mismatch"
        if entry.get("prevHash") != prev:
            return False, f"entry {i} prevHash does not link"
        if entry.get("entryHash") != _entry_hash(entry):
            return False, f"entry {i} entryHash mismatch (tampered)"
        prev = entry["entryHash"]
    return True, None


# ---------------------------------------------------------------------------
# Kill-switch credential
# ---------------------------------------------------------------------------


def build_killswitch_credential(
    authority_signer: Any,
    *,
    target: str,
    reason: str,
    command: str = EMERGENCY_STOP,
    scope: Optional[List[str]] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed KillSwitchCredential proving who issued an emergency stop.

    Args:
      target: The robot DID, fleet id, or zone the stop applies to.
      command: The action (default emergency_stop).
    """
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": target,
        "command": command,
        "reason": reason,
        "issuedBy": authority_signer.get_did(),
    }
    if scope is not None:
        subject["scope"] = list(scope)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", KILLSWITCH_TYPE],
        "issuer": authority_signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, authority_signer)


def verify_killswitch_credential(
    credential: Dict[str, Any],
    public_key: Any,
    *,
    trusted_authorities: Optional[Set[str]] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a KillSwitchCredential. When `trusted_authorities` is supplied, the
    issuer DID MUST be in it, so only an attested authority can trigger the stop.
    """
    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = credential.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if KILLSWITCH_TYPE not in type_field:
        return False, None
    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(credential, resolved):
            return False, None
    except ValueError:
        return False, None

    issuer = credential.get("issuer")
    if trusted_authorities is not None and issuer not in trusted_authorities:
        return False, None
    return True, credential.get("credentialSubject") or {}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "KILLSWITCH_TYPE",
    "EMERGENCY_STOP",
    "GENESIS_PREV_HASH",
    "BlackBoxError",
    "BlackBoxLog",
    "open_entry",
    "verify_blackbox_chain",
    "build_killswitch_credential",
    "verify_killswitch_credential",
]
