"""
Bystander-consent evidence for robot capture.

A robot working in a shared or public space captures people incidentally through
its cameras and microphones. This lets the robot record, at capture time, the
basis on which a capture was permitted, bound to the specific capture and to the
robot's identity, and lets a bystander (or their device) sign a consent token
bound to that one capture. Only hashes and a consent basis are stored, never an
image or a bystander's identifying data, so the evidence is verifiable without
retaining anyone's biometrics.

A bystander consent token is signed by the bystander over the hash of the capture
and the robot's DID, so it verifies only against the capture it was given for and
cannot be replayed to a different recording. A bystander-consent evidence
credential is signed by the robot, binding the capture hash to a consent basis
(an explicit token, posted notice, a legitimate interest, or a redaction that was
applied) and, when the basis is explicit consent, to the tokens that cover it.

This is the open layer: the cryptographic binding of a consent basis to a capture,
and its verification, holding only hashes. On-device biometric detection and
redaction, and managed consent-registry orchestration, are out of scope for the
open layer.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ._signing import attach_proof
from .blackbox import _mb64
from .identity import RoboticsError

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1"
CONSENT_EVIDENCE_TYPE = "BystanderConsentEvidence"
CONSENT_TOKEN_TYPE = "BystanderConsentToken"

# Accepted consent bases. Implementers MAY use additional values, but these are
# the interoperable set a verifier can rely on.
CONSENT_BASES = frozenset(
    {
        "explicit-consent",
        "posted-notice",
        "legitimate-interest",
        "redacted",
    }
)


def hash_capture(capture: bytes) -> str:
    """Return the multibase (base64url) SHA-256 of a raw capture."""
    if not isinstance(capture, (bytes, bytearray)):
        raise RoboticsError("capture must be bytes")
    return _mb64(hashlib.sha256(bytes(capture)).digest())


# ---------------------------------------------------------------------------
# Bystander consent token (signed by the bystander, bound to one capture)
# ---------------------------------------------------------------------------


def build_consent_token(
    bystander_signer: Any,
    *,
    bystander_did: str,
    capture_hash: str,
    robot_did: str,
    scope: Optional[str] = None,
    granted_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a signed BystanderConsentToken: a bystander grants consent for a specific
    capture (named by `capture_hash`) by a specific robot (`robot_did`), signed by
    the bystander. Binding the token to the capture hash means it cannot be replayed
    to a different recording. `scope` optionally records what the consent covers.
    """
    if not bystander_did or not capture_hash or not robot_did:
        raise RoboticsError("bystander_did, capture_hash, and robot_did are required")
    issued = (granted_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject: Dict[str, Any] = {
        "id": bystander_did,
        "captureHash": capture_hash,
        "robotDid": robot_did,
    }
    if scope is not None:
        subject["scope"] = scope

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONSENT_TOKEN_TYPE],
        "issuer": bystander_did,
        "validFrom": _iso(issued),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        credential["validUntil"] = _iso(issued + timedelta(seconds=valid_seconds))
    return attach_proof(credential, bystander_signer)


def verify_consent_token(
    token: Dict[str, Any],
    bystander_public_key: Any,
    *,
    capture_hash: str,
    robot_did: str,
    now: Optional[datetime] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a BystanderConsentToken: the bystander's proof, that the issuer is the
    bystander, and that the token is bound to this capture and this robot and is
    within its window. Returns (ok, subject).
    """
    ok, subject = _verify_typed(token, bystander_public_key, CONSENT_TOKEN_TYPE)
    if not ok:
        return False, None
    if token.get("issuer") != subject.get("id"):
        return False, None
    if subject.get("captureHash") != capture_hash or subject.get("robotDid") != robot_did:
        return False, None
    if not _within_window(token, now):
        return False, None
    return True, subject


# ---------------------------------------------------------------------------
# Bystander-consent evidence (signed by the robot)
# ---------------------------------------------------------------------------


def build_consent_evidence(
    robot_signer: Any,
    *,
    robot_did: str,
    capture_hash: str,
    basis: str,
    consent_tokens: Optional[List[Dict[str, Any]]] = None,
    redaction_hash: Optional[str] = None,
    attested_at: Optional[datetime] = None,
    valid_seconds: Optional[int] = None,
    valid_from: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build a signed BystanderConsentEvidence credential: the robot records that a
    capture (named by `capture_hash`) was permitted on `basis`, one of
    CONSENT_BASES. When the basis is explicit consent, `consent_tokens` are the
    bystander tokens that cover it, and the evidence commits to them by their proof
    value (never embedding a bystander's identifying data). `redaction_hash`
    optionally records that a redacted output was produced. Signed by the robot.
    """
    if not robot_did or not capture_hash:
        raise RoboticsError("robot_did and capture_hash are required")
    if basis not in CONSENT_BASES:
        raise RoboticsError(f"basis must be one of {sorted(CONSENT_BASES)}, got {basis!r}")
    tokens = consent_tokens or []
    if basis == "explicit-consent" and not tokens:
        raise RoboticsError("explicit-consent basis requires at least one consent token")

    subject: Dict[str, Any] = {
        "id": robot_did,
        "captureHash": capture_hash,
        "basis": basis,
    }
    if tokens:
        subject["consentTokenRefs"] = [_token_ref(t) for t in tokens]
    if redaction_hash is not None:
        subject["redactionHash"] = redaction_hash

    credential: Dict[str, Any] = {
        "@context": [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
        "type": ["VerifiableCredential", CONSENT_EVIDENCE_TYPE],
        "issuer": robot_did,
        "validFrom": _iso((valid_from or attested_at or datetime.now(timezone.utc))),
        "credentialSubject": subject,
    }
    if valid_seconds is not None:
        start = _parse_iso(credential["validFrom"]) or datetime.now(timezone.utc)
        credential["validUntil"] = _iso(start + timedelta(seconds=valid_seconds))
    return attach_proof(credential, robot_signer)


def verify_consent_evidence(
    evidence: Dict[str, Any],
    robot_public_key: Any,
    *,
    capture: Optional[bytes] = None,
    consent_tokens: Optional[List[Dict[str, Any]]] = None,
    bystander_keys: Optional[Dict[str, Any]] = None,
    now: Optional[datetime] = None,
) -> "tuple[bool, Optional[Dict[str, Any]]]":
    """
    Verify a BystanderConsentEvidence credential: the robot's proof, that the issuer
    is the robot, and that the basis is accepted. When `capture` is supplied, its
    hash must reproduce the attested capture hash. When `consent_tokens` and
    `bystander_keys` (a map of bystander DID to key) are supplied, every token must
    verify, be bound to this capture and this robot, and match a committed reference,
    and an explicit-consent evidence must carry at least one token. Returns
    (ok, subject).
    """
    ok, subject = _verify_typed(evidence, robot_public_key, CONSENT_EVIDENCE_TYPE)
    if not ok:
        return False, None
    if evidence.get("issuer") != subject.get("id"):
        return False, None
    if subject.get("basis") not in CONSENT_BASES:
        return False, None
    capture_hash = subject.get("captureHash")
    if not capture_hash:
        return False, None

    if capture is not None:
        try:
            if hash_capture(capture) != capture_hash:
                return False, None
        except RoboticsError:
            return False, None

    refs = subject.get("consentTokenRefs") or []
    if subject.get("basis") == "explicit-consent" and not refs:
        return False, None

    if consent_tokens is not None and bystander_keys is not None:
        for token in consent_tokens:
            issuer = token.get("issuer")
            key = bystander_keys.get(issuer) if isinstance(issuer, str) else None
            if key is None:
                return False, None
            tok_ok, _ = verify_consent_token(
                token, key, capture_hash=capture_hash, robot_did=subject.get("id"), now=now
            )
            if not tok_ok or _token_ref(token) not in refs:
                return False, None

    return True, subject


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _token_ref(token: Dict[str, Any]) -> str:
    """A privacy-preserving reference to a token: its proof value."""
    ref = (token.get("proof") or {}).get("proofValue")
    if not ref:
        raise RoboticsError("consent token is missing a proof value")
    return ref


def _within_window(credential: Dict[str, Any], now: Optional[datetime]) -> bool:
    at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = _parse_iso(credential.get("validFrom"))
    end = _parse_iso(credential.get("validUntil"))
    if start is not None and at < start:
        return False
    if end is not None and at > end:
        return False
    return True


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


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


__all__ = [
    "CONSENT_EVIDENCE_TYPE",
    "CONSENT_TOKEN_TYPE",
    "CONSENT_BASES",
    "hash_capture",
    "build_consent_token",
    "verify_consent_token",
    "build_consent_evidence",
    "verify_consent_evidence",
]
