"""
Scannable robot passport (Phase 5.6).

A compact, signed passport that anyone can scan (QR or NFC) to check a robot's
owner, authorized actions, certification, and current standing, offline. The
passport is a small eddsa-jcs-2022 credential; the QR/NFC payload is a
`vouch-passport:` URI carrying the multibase JCS bytes of that credential, so an
offline reader can verify the signature without a network round-trip.

This ships the open verifier and the encoding. Rendering the URI to an actual QR
image or writing an NFC tag is the caller's concern (any QR/NFC library).
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from vouch.jcs import canonicalize
from ._signing import attach_proof

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
ROBOT_PASSPORT_TYPE = "RobotPassport"
PASSPORT_URI_SCHEME = "vouch-passport:"

STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_DECOMMISSIONED = "decommissioned"


class PassportError(Exception):
    """Raised on malformed passport input."""


def build_passport(
    signer: Any,
    *,
    robot_did: str,
    make: str,
    model: str,
    owner: str,
    authorized_actions: List[str],
    certification: Optional[str] = None,
    status: str = STATUS_ACTIVE,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a signed RobotPassport credential (issued by the robot or an authority)."""
    issued = (valid_from or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": robot_did,
        "make": make,
        "model": model,
        "owner": owner,
        "authorizedActions": list(authorized_actions),
        "status": status,
    }
    if certification is not None:
        subject["certification"] = certification
    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", ROBOT_PASSPORT_TYPE],
        "issuer": signer.get_did(),
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, signer)


def encode_passport(passport: Dict[str, Any]) -> str:
    """Encode a passport into a compact vouch-passport: URI for a QR or NFC tag."""
    blob = base64.urlsafe_b64encode(canonicalize(passport)).rstrip(b"=").decode("ascii")
    return PASSPORT_URI_SCHEME + "u" + blob


def decode_passport(uri: str) -> Dict[str, Any]:
    """Decode a vouch-passport: URI back into the passport credential."""
    import json

    if not uri.startswith(PASSPORT_URI_SCHEME):
        raise PassportError(f"not a {PASSPORT_URI_SCHEME} URI")
    body = uri[len(PASSPORT_URI_SCHEME) :]
    if not body.startswith("u"):
        raise PassportError("expected multibase 'u' payload")
    payload = body[1:]
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    return json.loads(raw.decode("utf-8"))


def verify_passport(
    passport: Any,
    public_key: Any,
    *,
    now: Optional[datetime] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a passport (a credential dict or a vouch-passport: URI). Returns
    (ok, summary) where summary is the human-facing fields. A suspended or
    decommissioned status still verifies but is surfaced in the summary so a
    scanner can refuse cooperation.
    """
    if isinstance(passport, str):
        try:
            passport = decode_passport(passport)
        except PassportError:
            return False, None

    from vouch import data_integrity
    from vouch.verifier import _coerce_ed25519_public_key

    type_field = passport.get("type") or []
    if isinstance(type_field, str):
        type_field = [type_field]
    if ROBOT_PASSPORT_TYPE not in type_field:
        return False, None
    resolved = _coerce_ed25519_public_key(public_key) if public_key is not None else None
    if resolved is None:
        return False, None
    try:
        if not data_integrity.verify_proof(passport, resolved):
            return False, None
    except ValueError:
        return False, None

    # Temporal check (a scanner should reject an expired passport).
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    vu = _parse_iso(passport.get("validUntil", "")) if passport.get("validUntil") else None
    if vu is not None and now > vu:
        return False, None

    subject = passport.get("credentialSubject") or {}
    summary = {
        "robot": subject.get("id"),
        "make": subject.get("make"),
        "model": subject.get("model"),
        "owner": subject.get("owner"),
        "authorizedActions": subject.get("authorizedActions", []),
        "certification": subject.get("certification"),
        "status": subject.get("status"),
    }
    return True, summary


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None


__all__ = [
    "ROBOT_PASSPORT_TYPE",
    "PASSPORT_URI_SCHEME",
    "STATUS_ACTIVE",
    "STATUS_SUSPENDED",
    "STATUS_DECOMMISSIONED",
    "PassportError",
    "build_passport",
    "encode_passport",
    "decode_passport",
    "verify_passport",
]
