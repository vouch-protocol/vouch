"""
W3C BitstringStatusList implementation for Vouch Protocol.

Implements credential-level revocation and suspension status per
[VC-BITSTRING-STATUS-LIST] (https://www.w3.org/TR/vc-bitstring-status-list/),
referenced in W3C CG Report §11.2.

This module provides:

- `StatusList`: in-memory bitstring with W3C-compliant gzip + base64url encoding.
- `build_status_list_credential`: constructs an unsigned BitstringStatusListCredential VC.
- `build_status_list_entry`: constructs the `credentialStatus` property for a Vouch Credential.
- `verify_status`: looks up a credential's bit in a fetched status list credential.

The in-memory StatusList is intended as a reference implementation suitable for
development, testing, and small deployments. Production deployments SHOULD pair
this with persistent storage and an HTTP endpoint that publishes the signed
status list credential at the URL referenced by issued credentials.
"""

from __future__ import annotations

import base64
import gzip
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


# W3C BitstringStatusList §4.2: minimum bitstring length is 131,072 bits (16 KiB).
DEFAULT_BITSTRING_LENGTH = 131_072

# W3C BitstringStatusList §4.1
STATUS_PURPOSE_REVOCATION = "revocation"
STATUS_PURPOSE_SUSPENSION = "suspension"
STATUS_PURPOSE_MESSAGE = "message"

VALID_STATUS_PURPOSES = (
    STATUS_PURPOSE_REVOCATION,
    STATUS_PURPOSE_SUSPENSION,
    STATUS_PURPOSE_MESSAGE,
)

BITSTRING_STATUS_LIST_CREDENTIAL_TYPE = "BitstringStatusListCredential"
BITSTRING_STATUS_LIST_SUBJECT_TYPE = "BitstringStatusList"
BITSTRING_STATUS_LIST_ENTRY_TYPE = "BitstringStatusListEntry"

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VC_TYPE = "VerifiableCredential"

# Multibase prefix for base64url-no-pad per multibase spec.
MULTIBASE_BASE64URL_PREFIX = "u"


class StatusListError(Exception):
    """Raised when a status list operation fails."""


@dataclass
class StatusList:
    """
    An in-memory bitstring for credential status tracking.

    Each bit represents the status of one credential. A bit value of 0 is the
    default state (e.g., not revoked); a bit value of 1 indicates the status
    has been set (e.g., revoked, suspended, or message-bit-on).

    Bit ordering follows W3C BitstringStatusList §4.2: bit at index `i` is
    stored at byte `i // 8`, with bit position `7 - (i % 8)` (most significant
    bit first within each byte).

    Attributes:
        status_list_id: Stable URL where the signed BitstringStatusListCredential
            is published (e.g., "https://issuer.example/status/3").
        status_purpose: One of "revocation", "suspension", "message".
        length: Bitstring length in bits. MUST be a multiple of 8 and at least
            DEFAULT_BITSTRING_LENGTH (131,072) per W3C spec.
    """

    status_list_id: str
    status_purpose: str = STATUS_PURPOSE_REVOCATION
    length: int = DEFAULT_BITSTRING_LENGTH
    _bits: bytearray = field(init=False, repr=False)
    _next_index: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.status_purpose not in VALID_STATUS_PURPOSES:
            raise StatusListError(
                f"status_purpose must be one of {VALID_STATUS_PURPOSES}, "
                f"got {self.status_purpose!r}"
            )
        if self.length < DEFAULT_BITSTRING_LENGTH:
            raise StatusListError(
                f"bitstring length must be at least {DEFAULT_BITSTRING_LENGTH} "
                f"per W3C BitstringStatusList §4.2, got {self.length}"
            )
        if self.length % 8 != 0:
            raise StatusListError(
                f"bitstring length must be a multiple of 8, got {self.length}"
            )
        if not self.status_list_id:
            raise StatusListError("status_list_id is required")
        self._bits = bytearray(self.length // 8)

    def allocate_index(self) -> int:
        """
        Return the next unused index and advance the cursor.

        Raises:
            StatusListError: if all indices in the list have been allocated.
        """
        if self._next_index >= self.length:
            raise StatusListError(
                f"status list exhausted: all {self.length} indices allocated"
            )
        idx = self._next_index
        self._next_index += 1
        return idx

    def set_status(self, index: int, value: bool = True) -> None:
        """
        Set the bit at `index` to 1 (default) or 0 if value is False.
        """
        self._check_index(index)
        byte_idx = index // 8
        bit_pos = 7 - (index % 8)
        if value:
            self._bits[byte_idx] |= (1 << bit_pos)
        else:
            self._bits[byte_idx] &= ~(1 << bit_pos) & 0xFF

    def get_status(self, index: int) -> bool:
        """
        Return True if the bit at `index` is set.
        """
        self._check_index(index)
        byte_idx = index // 8
        bit_pos = 7 - (index % 8)
        return bool(self._bits[byte_idx] & (1 << bit_pos))

    def revoke(self, index: int) -> None:
        """Convenience wrapper for set_status(index, True)."""
        self.set_status(index, True)

    def reinstate(self, index: int) -> None:
        """Convenience wrapper for set_status(index, False) (suspension only)."""
        self.set_status(index, False)

    def is_set(self, index: int) -> bool:
        """Convenience wrapper for get_status(index)."""
        return self.get_status(index)

    def encode(self) -> str:
        """
        Return the multibase (base64url, no pad) string of the gzip-compressed
        bitstring, per W3C BitstringStatusList §4.2.

        The gzip mtime field is fixed at 0 so that the encoded output is
        deterministic across runs and across language implementations.
        """
        compressed = gzip.compress(bytes(self._bits), mtime=0)
        b64 = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")
        return MULTIBASE_BASE64URL_PREFIX + b64

    @classmethod
    def decode(
        cls,
        encoded: str,
        status_list_id: str,
        status_purpose: str = STATUS_PURPOSE_REVOCATION,
    ) -> "StatusList":
        """
        Reconstruct a StatusList from its multibase encoding.

        Caller is responsible for verifying the Data Integrity proof on the
        enclosing BitstringStatusListCredential BEFORE calling this method.
        """
        if not encoded.startswith(MULTIBASE_BASE64URL_PREFIX):
            raise StatusListError(
                f"encoded list must use multibase prefix "
                f"{MULTIBASE_BASE64URL_PREFIX!r} (base64url), "
                f"got prefix {encoded[:1]!r}"
            )
        payload = encoded[1:]
        padding = (-len(payload)) % 4
        b64 = payload + ("=" * padding)
        try:
            compressed = base64.urlsafe_b64decode(b64)
            bits = gzip.decompress(compressed)
        except Exception as exc:
            raise StatusListError(f"failed to decode bitstring: {exc}") from exc

        length = len(bits) * 8
        if length < DEFAULT_BITSTRING_LENGTH:
            raise StatusListError(
                f"decoded bitstring length {length} is below the W3C minimum "
                f"({DEFAULT_BITSTRING_LENGTH})"
            )

        lst = cls(
            status_list_id=status_list_id,
            status_purpose=status_purpose,
            length=length,
        )
        lst._bits = bytearray(bits)
        return lst

    def _check_index(self, index: int) -> None:
        if index < 0 or index >= self.length:
            raise StatusListError(
                f"index {index} out of range [0, {self.length})"
            )

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    def to_state_dict(self) -> Dict[str, Any]:
        """
        Serialize the StatusList to a state dict suitable for persistence.

        The state dict carries everything needed to reconstruct the list,
        including `next_index` (which is NOT recoverable from the encoded
        bitstring alone). Issuers SHOULD persist this state after every
        revocation or allocation and reload it on startup to avoid
        re-allocating already-used indices.

        Returns:
            A JSON-serializable dict.
        """
        return {
            "version": 1,
            "status_list_id": self.status_list_id,
            "status_purpose": self.status_purpose,
            "length": self.length,
            "next_index": self._next_index,
            "encoded_list": self.encode(),
        }

    @classmethod
    def from_state_dict(cls, state: Dict[str, Any]) -> "StatusList":
        """
        Reconstruct a StatusList from a state dict produced by `to_state_dict`.
        """
        if not isinstance(state, dict):
            raise StatusListError("state must be a dict")

        required = ("status_list_id", "status_purpose", "length", "next_index", "encoded_list")
        missing = [k for k in required if k not in state]
        if missing:
            raise StatusListError(
                f"state dict missing required keys: {missing}"
            )

        lst = cls.decode(
            encoded=state["encoded_list"],
            status_list_id=state["status_list_id"],
            status_purpose=state["status_purpose"],
        )
        if lst.length != state["length"]:
            raise StatusListError(
                f"length mismatch: state declares {state['length']}, "
                f"decoded bitstring has {lst.length}"
            )

        next_index = int(state["next_index"])
        if next_index < 0 or next_index > lst.length:
            raise StatusListError(
                f"next_index {next_index} out of range [0, {lst.length}]"
            )
        lst._next_index = next_index
        return lst


class FilesystemStatusListStore:
    """
    Reference filesystem-backed store for StatusList persistence.

    Reads and writes a state dict as JSON at the given path. Suitable for
    development, single-process issuers, and small deployments. Production
    deployments with multiple issuer instances SHOULD substitute a shared
    store (Redis, Postgres, S3, etc.) and use the same `to_state_dict` /
    `from_state_dict` API.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def save(self, status_list: "StatusList") -> None:
        """
        Persist the current state of `status_list` to the configured path.

        Writes atomically by writing to a temp file and renaming.
        """
        import json
        import os
        import tempfile

        state = status_list.to_state_dict()
        dir_path = os.path.dirname(os.path.abspath(self.path)) or "."
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=dir_path,
            prefix=".status_list-",
            suffix=".json.tmp",
            delete=False,
        ) as tmp:
            json.dump(state, tmp, indent=2, sort_keys=True)
            tmp.write("\n")
            tmp_name = tmp.name
        os.replace(tmp_name, self.path)

    def load(self) -> "StatusList":
        """
        Load a StatusList from the configured path.

        Raises:
            FileNotFoundError: if no state file exists at the path.
            StatusListError: if the state file is malformed.
        """
        import json

        with open(self.path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        return StatusList.from_state_dict(state)


def build_status_list_credential(
    *,
    issuer_did: str,
    status_list: StatusList,
    credential_id: Optional[str] = None,
    valid_seconds: int = 30 * 24 * 60 * 60,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Construct an unsigned BitstringStatusListCredential VC per W3C BitstringStatusList §4.

    The caller attaches a Data Integrity proof (via `data_integrity.build_proof`)
    before publishing the credential at the URL referenced by issued credentials.

    Args:
        issuer_did: Issuer DID (typically the same authority that issues
            credentials referencing this list).
        status_list: The StatusList to encode into the credentialSubject.
        credential_id: Optional `id` for the credential. Defaults to
            `status_list.status_list_id`.
        valid_seconds: Validity window for the status list credential itself.
            Defaults to 30 days.
        valid_from: Optional override for `validFrom`. Defaults to current UTC.

    Returns:
        A dict suitable for proof attachment.
    """
    issued_at = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = issued_at + timedelta(seconds=valid_seconds)
    list_id = credential_id or status_list.status_list_id

    return {
        "@context": [VC_CONTEXT_V2],
        "id": list_id,
        "type": [VC_TYPE, BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": _iso(issued_at),
        "validUntil": _iso(expires_at),
        "credentialSubject": {
            "id": f"{list_id}#list",
            "type": BITSTRING_STATUS_LIST_SUBJECT_TYPE,
            "statusPurpose": status_list.status_purpose,
            "encodedList": status_list.encode(),
        },
    }


def build_status_list_entry(
    *,
    status_list_credential: str,
    status_list_index: int,
    status_purpose: str = STATUS_PURPOSE_REVOCATION,
    entry_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construct a `credentialStatus` entry for a Vouch Credential, referencing
    a specific bit index in a published BitstringStatusListCredential.

    Args:
        status_list_credential: URL of the published status list credential.
        status_list_index: Bit index for this credential within the list.
        status_purpose: One of "revocation", "suspension", "message".
        entry_id: Optional id for the entry. Defaults to
            "{status_list_credential}#{status_list_index}".

    Returns:
        A dict suitable for inclusion as `credentialStatus` on a Vouch Credential.
    """
    if status_purpose not in VALID_STATUS_PURPOSES:
        raise StatusListError(
            f"status_purpose must be one of {VALID_STATUS_PURPOSES}, "
            f"got {status_purpose!r}"
        )
    if status_list_index < 0:
        raise StatusListError("status_list_index must be non-negative")
    if not status_list_credential:
        raise StatusListError("status_list_credential URL is required")

    return {
        "id": entry_id or f"{status_list_credential}#{status_list_index}",
        "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
        "statusPurpose": status_purpose,
        "statusListIndex": str(status_list_index),
        "statusListCredential": status_list_credential,
    }


def verify_status(
    *,
    credential_status: Dict[str, Any],
    status_list_credential: Dict[str, Any],
) -> bool:
    """
    Verify a credential's status by looking up its bit in a fetched status list credential.

    Returns True if the bit is set (e.g., the credential is revoked, suspended,
    or message-bit-on), False if the bit is in its default state.

    The caller MUST verify the Data Integrity proof on `status_list_credential`
    BEFORE calling this function. This function performs structural validation
    and bit lookup only; it does not re-verify the issuer's signature.

    Raises:
        StatusListError: on structural mismatch between the credentialStatus
            entry and the status list credential.
    """
    if not isinstance(credential_status, dict):
        raise StatusListError("credential_status must be a dict")
    if not isinstance(status_list_credential, dict):
        raise StatusListError("status_list_credential must be a dict")

    if credential_status.get("type") != BITSTRING_STATUS_LIST_ENTRY_TYPE:
        raise StatusListError(
            f"credentialStatus.type must be {BITSTRING_STATUS_LIST_ENTRY_TYPE}, "
            f"got {credential_status.get('type')!r}"
        )

    referenced = credential_status.get("statusListCredential")
    if not referenced:
        raise StatusListError(
            "credentialStatus.statusListCredential is required"
        )

    actual_id = status_list_credential.get("id")
    if actual_id != referenced:
        raise StatusListError(
            f"status list credential id mismatch: credential references "
            f"{referenced!r}, fetched credential has id {actual_id!r}"
        )

    type_field = status_list_credential.get("type") or []
    if BITSTRING_STATUS_LIST_CREDENTIAL_TYPE not in type_field:
        raise StatusListError(
            f"fetched credential is not a {BITSTRING_STATUS_LIST_CREDENTIAL_TYPE}"
        )

    subject = status_list_credential.get("credentialSubject") or {}
    if subject.get("type") != BITSTRING_STATUS_LIST_SUBJECT_TYPE:
        raise StatusListError(
            f"credentialSubject.type must be {BITSTRING_STATUS_LIST_SUBJECT_TYPE}"
        )

    declared_purpose = credential_status.get("statusPurpose")
    actual_purpose = subject.get("statusPurpose")
    if declared_purpose != actual_purpose:
        raise StatusListError(
            f"statusPurpose mismatch: credential entry declares "
            f"{declared_purpose!r}, status list declares {actual_purpose!r}"
        )

    encoded = subject.get("encodedList")
    if not encoded:
        raise StatusListError("credentialSubject.encodedList is required")

    raw_index = credential_status.get("statusListIndex")
    if raw_index is None:
        raise StatusListError("credentialStatus.statusListIndex is required")
    try:
        index = int(raw_index)
    except (TypeError, ValueError) as exc:
        raise StatusListError(
            f"statusListIndex must be a non-negative integer string, "
            f"got {raw_index!r}"
        ) from exc
    if index < 0:
        raise StatusListError("statusListIndex must be non-negative")

    status_list = StatusList.decode(
        encoded=encoded,
        status_list_id=actual_id,
        status_purpose=actual_purpose,
    )
    return status_list.get_status(index)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "DEFAULT_BITSTRING_LENGTH",
    "STATUS_PURPOSE_REVOCATION",
    "STATUS_PURPOSE_SUSPENSION",
    "STATUS_PURPOSE_MESSAGE",
    "VALID_STATUS_PURPOSES",
    "BITSTRING_STATUS_LIST_CREDENTIAL_TYPE",
    "BITSTRING_STATUS_LIST_SUBJECT_TYPE",
    "BITSTRING_STATUS_LIST_ENTRY_TYPE",
    "MULTIBASE_BASE64URL_PREFIX",
    "StatusList",
    "StatusListError",
    "FilesystemStatusListStore",
    "build_status_list_credential",
    "build_status_list_entry",
    "verify_status",
]
