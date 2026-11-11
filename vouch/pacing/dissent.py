"""
Sealed Dissent Registration (PAD-134).

A person who sees a problem early can raise it at once, at whatever cost that
carries, or stay quiet and lose the ability to show later that they saw it at
the time. This module removes that choice.

A concern is canonicalized, sealed to an independent escrow, and registered by
appending a blinded commitment to an append-only log. The entry is a fixed-size
digest that discloses neither content nor subject nor author, while its log
index establishes when the concern was registered. Release happens on a declared
condition, and on release the revealed content is checked against the original
commitment, so what emerges is provably what was registered.

A separately blinded subject tag lets independent registrations over the same
subject be counted without any author disclosing first, and that count can itself
be a release condition. The corroboration a lone account cannot obtain becomes
available without anyone having to go first.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..jcs import canonicalize
from ._common import (
    PacingError,
    blinded_commitment,
    constant_time_eq,
    digest_bytes,
    iso,
    mb64,
    now_utc,
    parse_iso,
    unmb64,
)

RELEASE_AUTHOR = "author-release"
RELEASE_QUORUM = "escrow-quorum-release"
RELEASE_TIME_LOCK = "time-lock-expiry"
RELEASE_LIVENESS_LAPSE = "author-liveness-lapse"
RELEASE_CORROBORATION = "corroboration-threshold"

KNOWN_RELEASE_CONDITIONS = frozenset(
    {
        RELEASE_AUTHOR,
        RELEASE_QUORUM,
        RELEASE_TIME_LOCK,
        RELEASE_LIVENESS_LAPSE,
        RELEASE_CORROBORATION,
    }
)

REASON_COMMITMENT_MISMATCH = "commitment_mismatch"
REASON_NO_CONDITION_MET = "no_release_condition_met"
REASON_UNKNOWN_CONDITION = "unknown_release_condition"
REASON_SEAL_INVALID = "seal_does_not_open"


def concern_object(
    *,
    subject_descriptor: str,
    statement: str,
    evidence_anchors: Optional[Dict[str, str]] = None,
    release_conditions: Optional[Sequence[str]] = None,
    time_lock: Optional[datetime] = None,
    corroboration_threshold: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build the canonical concern object.

    Args:
        subject_descriptor: A normalized descriptor of what the concern is about,
            which is what corroboration is counted over.
        statement: The concern itself.
        evidence_anchors: Named artifacts bound by digest at registration time,
            so a concern referring to an artifact that did not then exist is
            distinguishable later.
        release_conditions: Which conditions may open the concern.
        time_lock: When a time lock expires, if one is declared.
        corroboration_threshold: How many independent registrations over the same
            subject open the concern, if that condition is declared.
    """
    if not subject_descriptor or not statement:
        raise PacingError("a concern needs a subject descriptor and a statement")
    conditions = list(release_conditions or [RELEASE_AUTHOR])
    unknown = [item for item in conditions if item not in KNOWN_RELEASE_CONDITIONS]
    if unknown:
        raise PacingError(f"unknown release conditions: {unknown}")
    concern: Dict[str, Any] = {
        "subjectDescriptor": subject_descriptor,
        "statement": statement,
        "releaseConditions": sorted(conditions),
    }
    if evidence_anchors:
        concern["evidenceAnchors"] = {str(k): str(v) for k, v in evidence_anchors.items()}
    if time_lock is not None:
        concern["timeLock"] = iso(time_lock)
    if corroboration_threshold is not None:
        concern["corroborationThreshold"] = int(corroboration_threshold)
    return concern


def subject_tag(subject_descriptor: str, registry_salt: bytes) -> str:
    """
    A blinded tag for a concern's subject.

    Equality between tags is testable across registrations, so convergence is
    countable, while the descriptor is not recoverable from the tag. Resistance
    to a dictionary attack over the tag depends on the descriptor's entropy, so
    a registry that expects low-entropy descriptors should rotate its salt and
    keep it confidential to the registry.
    """
    if not isinstance(registry_salt, (bytes, bytearray)) or len(registry_salt) < 16:
        raise PacingError("registry_salt must be at least 16 bytes")
    tag = hmac.new(
        bytes(registry_salt), subject_descriptor.encode("utf-8"), hashlib.sha256
    ).digest()
    return mb64(tag)


def seal_concern(concern: Dict[str, Any], escrow_public_key: bytes) -> Dict[str, Any]:
    """
    Encrypt a concern to an escrow's X25519 public key.

    An ephemeral key agreement per registration means the sealed object reveals
    nothing about the author, and the escrow alone can open it.
    """
    if not isinstance(escrow_public_key, (bytes, bytearray)) or len(escrow_public_key) != 32:
        raise PacingError("escrow_public_key must be 32 raw X25519 bytes")
    plaintext = canonicalize(concern)
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes(escrow_public_key)))
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"vouch-pacing-dissent/v1"
    ).derive(shared)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"vouch-pacing-dissent")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ephemeral_public = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "algorithm": "x25519-hkdf-sha256-aes256gcm",
        "ephemeralPublicKey": mb64(ephemeral_public),
        "nonce": mb64(nonce),
        "ciphertext": mb64(ciphertext),
    }


def unseal_concern(sealed: Dict[str, Any], escrow_private_key: bytes) -> Dict[str, Any]:
    """Open a sealed concern with the escrow's private key."""
    import json

    if not isinstance(sealed, dict) or sealed.get("algorithm") != "x25519-hkdf-sha256-aes256gcm":
        raise PacingError("unsupported seal algorithm")
    try:
        private = X25519PrivateKey.from_private_bytes(bytes(escrow_private_key))
        peer = X25519PublicKey.from_public_bytes(unmb64(str(sealed["ephemeralPublicKey"])))
        shared = private.exchange(peer)
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"vouch-pacing-dissent/v1"
        ).derive(shared)
        plaintext = AESGCM(key).decrypt(
            unmb64(str(sealed["nonce"])),
            unmb64(str(sealed["ciphertext"])),
            b"vouch-pacing-dissent",
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise PacingError("sealed concern does not open") from exc
    return json.loads(plaintext.decode("utf-8"))


@dataclass(frozen=True)
class Registration:
    """What is appended to the registry, and what the author keeps."""

    commitment: str
    sealed: Dict[str, Any]
    subject_tag: str
    blinding: bytes = field(repr=False, default=b"")

    def log_entry(self) -> Dict[str, Any]:
        """
        The registry entry.

        It carries the commitment, the sealed object, and the subject tag, and
        nothing that identifies the author or the subject.
        """
        return {
            "commitment": self.commitment,
            "sealed": dict(self.sealed),
            "subjectTag": self.subject_tag,
        }

    def entry_digest(self) -> bytes:
        """The log leaf value for this registration."""
        return digest_bytes(self.log_entry())


def register_concern(
    concern: Dict[str, Any],
    *,
    escrow_public_key: bytes,
    registry_salt: bytes,
    blinding: Optional[bytes] = None,
) -> Registration:
    """Seal a concern and produce its registry entry."""
    secret = blinding or secrets.token_bytes(32)
    return Registration(
        commitment=blinded_commitment(concern, secret),
        sealed=seal_concern(concern, escrow_public_key),
        subject_tag=subject_tag(str(concern.get("subjectDescriptor")), registry_salt),
        blinding=secret,
    )


def corroboration_count(entries: Sequence[Dict[str, Any]], tag: str) -> int:
    """How many independent registrations carry the same subject tag."""
    return sum(1 for entry in entries if str(entry.get("subjectTag")) == tag)


@dataclass
class LivenessChain:
    """
    The author's optional liveness chain.

    Each period the author reveals the previous secret and commits to the next.
    A lapse is a declared release condition, so a registration outlives the
    author's capacity or willingness to act.
    """

    commitment: Optional[str] = None
    last_seen: Optional[datetime] = None

    def pulse(self, secret: bytes, next_secret: bytes, at_time: Optional[datetime] = None) -> bool:
        """Reveal the previous secret and commit to the next. False on a break."""
        from ..canary import compute_commitment, verify_reveal

        revealed = mb64(secret)
        if self.commitment is not None and not verify_reveal(revealed, self.commitment):
            return False
        self.commitment = compute_commitment(next_secret)
        self.last_seen = at_time or now_utc()
        return True

    def lapsed(self, max_gap_seconds: int, at_time: Optional[datetime] = None) -> bool:
        """True if the chain has gone quiet for longer than the declared gap."""
        if self.last_seen is None:
            return True
        moment = at_time or now_utc()
        return (moment - self.last_seen).total_seconds() > max_gap_seconds


def evaluate_release(
    concern: Dict[str, Any],
    *,
    author_released: bool = False,
    escrow_quorum_released: bool = False,
    registry_entries: Optional[Sequence[Dict[str, Any]]] = None,
    tag: Optional[str] = None,
    liveness: Optional[LivenessChain] = None,
    max_gap_seconds: Optional[int] = None,
    at_time: Optional[datetime] = None,
) -> Tuple[bool, List[str]]:
    """
    Decide whether any declared release condition is satisfied.

    Returns ``(released, conditions_met)``. Only conditions the concern itself
    declares can release it, so a registry cannot open a concern on a condition
    its author did not accept.
    """
    declared = set(concern.get("releaseConditions") or [])
    moment = at_time or now_utc()
    met: List[str] = []

    if author_released and RELEASE_AUTHOR in declared:
        met.append(RELEASE_AUTHOR)
    if escrow_quorum_released and RELEASE_QUORUM in declared:
        met.append(RELEASE_QUORUM)
    if RELEASE_TIME_LOCK in declared and concern.get("timeLock"):
        if moment >= parse_iso(str(concern["timeLock"])):
            met.append(RELEASE_TIME_LOCK)
    if RELEASE_LIVENESS_LAPSE in declared and liveness is not None:
        gap = max_gap_seconds if max_gap_seconds is not None else 0
        if liveness.lapsed(gap, at_time=moment):
            met.append(RELEASE_LIVENESS_LAPSE)
    if RELEASE_CORROBORATION in declared and tag is not None:
        threshold = concern.get("corroborationThreshold")
        if isinstance(threshold, int):
            if corroboration_count(registry_entries or [], tag) >= threshold:
                met.append(RELEASE_CORROBORATION)

    return (len(met) > 0), met


def verify_release(
    revealed_concern: Dict[str, Any],
    blinding: bytes,
    registration_entry: Dict[str, Any],
) -> List[str]:
    """
    Check a revealed concern against the entry that was registered.

    Returns the reasons the reveal fails. An empty list means the revealed
    concern recomputes to the registered commitment, so it is the concern that
    was registered rather than a later reconstruction.
    """
    commitment = str(registration_entry.get("commitment"))
    try:
        recomputed = blinded_commitment(revealed_concern, blinding)
    except PacingError:
        return [REASON_COMMITMENT_MISMATCH]
    if not constant_time_eq(recomputed, commitment):
        return [REASON_COMMITMENT_MISMATCH]
    return []


def escrow_keypair() -> Tuple[bytes, bytes]:
    """Generate an escrow X25519 keypair as raw (private, public) bytes."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private = X25519PrivateKey.generate()
    return (
        private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )
