"""
Shared helpers for the Pacing Profile modules.

Every credential in this package is an ordinary Vouch Protocol Verifiable
Credential secured with an ``eddsa-jcs-2022`` Data Integrity proof, so a pacing
artifact verifies through the same path as any other credential and needs no new
proof type. This module holds the small pieces those modules share: canonical
digests, multibase encoding, proof attach and verify, and timestamp handling.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .. import data_integrity
from ..jcs import canonicalize

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
PACING_CONTEXT_V1 = "https://vouch-protocol.com/pacing/v1"

DIGEST_ALGORITHM = "sha-256-jcs"


class PacingError(Exception):
    """Raised when a pacing artifact is malformed or a rule is violated."""


def now_utc() -> datetime:
    """Current time in UTC. Isolated so tests can reason about a single source."""
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Format a datetime in the second-resolution UTC form Vouch Protocol uses."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    """Parse the second-resolution UTC form. Raises PacingError on anything else."""
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise PacingError(f"malformed timestamp: {value!r}") from exc


def mb64(raw: bytes) -> str:
    """Multibase base64url-no-pad, the encoding used by the rest of the protocol."""
    return "u" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unmb64(value: str) -> bytes:
    """Inverse of :func:`mb64`. Raises PacingError on a non-multibase string."""
    if not isinstance(value, str) or not value.startswith("u"):
        raise PacingError(f"expected multibase base64url value, got {value!r}")
    body = value[1:]
    padding = "=" * (-len(body) % 4)
    try:
        return base64.urlsafe_b64decode(body + padding)
    except (ValueError, TypeError) as exc:
        raise PacingError("malformed multibase value") from exc


def digest_of(value: Any) -> str:
    """Multibase SHA-256 over the JCS-canonical form of a JSON value."""
    return mb64(hashlib.sha256(canonicalize(value)).digest())


def digest_bytes(value: Any) -> bytes:
    """Raw SHA-256 over the JCS-canonical form of a JSON value."""
    return hashlib.sha256(canonicalize(value)).digest()


def blinded_commitment(value: Any, blinding: bytes) -> str:
    """
    Commit to a canonical JSON value under a blinding secret.

    The commitment is domain-separated so a commitment computed here can never
    collide with a plain content digest computed elsewhere in the protocol.
    """
    if not isinstance(blinding, (bytes, bytearray)) or len(blinding) < 16:
        raise PacingError("blinding must be at least 16 bytes")
    payload = b"vouch-pacing-commitment\x00" + bytes(blinding) + b"\x00" + canonicalize(value)
    return mb64(hashlib.sha256(payload).digest())


def constant_time_eq(a: str, b: str) -> bool:
    """Constant-time comparison of two ASCII strings."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def raw_priv(signer: Any) -> Any:
    """Extract the raw Ed25519 private key a Signer holds, or fail loudly."""
    raw = getattr(signer, "_raw_priv", None)
    if raw is None:
        raise PacingError("signing requires a Signer holding an Ed25519 key")
    return raw


def attach_proof(credential: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    """Attach an ``eddsa-jcs-2022`` Data Integrity proof in place and return it."""
    credential["proof"] = data_integrity.build_proof(
        credential, raw_priv(signer), signer.verification_method_id()
    )
    return credential


def type_list(credential: Dict[str, Any]) -> List[str]:
    """Normalize a credential's ``type`` to a list."""
    declared = credential.get("type") or []
    return [declared] if isinstance(declared, str) else list(declared)


def verify_credential(credential: Any, public_key: Any, expected_type: str) -> bool:
    """
    Verify a pacing credential's proof and declared type.

    Default-deny: any malformed input, unresolvable key, or failed proof returns
    False rather than raising, because these functions gate authority and a false
    positive is an escalation.
    """
    from ..verifier import _coerce_ed25519_public_key

    if not isinstance(credential, dict):
        return False
    if expected_type not in type_list(credential):
        return False
    if public_key is None:
        return False
    resolved = _coerce_ed25519_public_key(public_key)
    if resolved is None:
        return False
    try:
        return bool(data_integrity.verify_proof(credential, resolved))
    except (ValueError, TypeError, KeyError):
        return False


def base_credential(
    signer: Any,
    credential_type: str,
    subject: Dict[str, Any],
    *,
    valid_from: Optional[datetime] = None,
    credential_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and sign a pacing credential with the standard envelope."""
    issued = (valid_from or now_utc()).astimezone(timezone.utc)
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1, PACING_CONTEXT_V1],
        "type": ["VerifiableCredential", credential_type],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": signer.get_did(),
        "validFrom": iso(issued),
        "credentialSubject": dict(subject),
    }
    return attach_proof(credential, signer)


def subject_of(credential: Dict[str, Any]) -> Dict[str, Any]:
    """Return a credential's subject, or raise if it has none."""
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        raise PacingError("credential has no credentialSubject object")
    return subject


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """
    RFC 6962 tree hash over ordered leaf values, reusing the protocol's Merkle
    domain separation so roots match the transparency log and the heartbeat
    action root.
    """
    from ..transparency import merkle_tree_hash

    return merkle_tree_hash(list(leaves))
