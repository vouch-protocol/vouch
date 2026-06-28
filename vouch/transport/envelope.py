"""
The Vouch transport envelope.

A transport moves bytes; Vouch moves *accountable* statements. The envelope is
the bridge: a thin, transport-neutral container that carries a signed Vouch
credential together with the liability and provenance context a peer needs to
hold the sender accountable, without ever touching the signed bytes
themselves.

Three payload compartments, each preserved verbatim:

  * ``payload``: the signed Vouch credential (an ``eddsa-jcs-2022`` or
    hybrid Verifiable Credential, complete with its ``proof`` block). This is
    opaque to the transport layer and is never re-serialized lossily.
  * ``attestations``, zero or more liability attestations (outcome
    commitments, penalty receipts, delegation links) that bind the sender to
    consequences.
  * ``provenance``: provenance metadata (content hashes, C2PA pointers,
    capture context) describing where the payload's subject came from.

Integrity across the transport boundary is enforced by ``content_digest()``: a
SHA-256 over the JCS canonicalization of those three compartments. The manager
stamps the digest at seal time; the receiver (or a fallback transport
re-handling the same envelope) recomputes it and rejects any mismatch. Because
the digest is computed over the canonical form, not the wire bytes, an
envelope survives a UDNA→HTTP transition, re-indentation, or key reordering
with its proofs intact.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .. import jcs

#: Wire-format version. Bump on breaking changes to the envelope shape.
ENVELOPE_VERSION = "1.0"

#: Media type advertised by transports that carry a sealed envelope.
ENVELOPE_CONTENT_TYPE = "application/vouch-envelope+json"


def _now_iso8601() -> str:
    """UTC timestamp, second precision, ``Z`` suffix (matches the signer)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class VouchEnvelope:
    """
    A payload-preserving message addressed by DID.

    The three payload compartments (``payload``, ``attestations``,
    ``provenance``) are treated as immutable cargo: transports route the
    envelope but must not alter them, and the content digest is the proof they
    didn't. Routing metadata (``to_did``, ``from_did``, ``created``,
    ``envelope_id``) lives alongside the cargo but outside the digest, so the
    manager may stamp delivery details without invalidating the seal.
    """

    to_did: str
    from_did: str
    payload: Dict[str, Any]
    attestations: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    created: str = field(default_factory=_now_iso8601)
    envelope_id: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    content_type: str = ENVELOPE_CONTENT_TYPE

    # ------------------------------------------------------------------ #
    # Integrity
    # ------------------------------------------------------------------ #
    def _digest_input(self) -> Dict[str, Any]:
        """The exact subtree the content digest covers (cargo only)."""
        return {
            "payload": self.payload,
            "attestations": self.attestations,
            "provenance": self.provenance,
        }

    def content_digest(self) -> str:
        """
        SHA-256 of the JCS-canonical cargo, as a ``sha256:`` hex string.

        Canonicalization (RFC 8785) makes the digest independent of key order
        and whitespace, so it is stable across serialization round-trips and
        across transports.
        """
        canonical = jcs.canonicalize(self._digest_input())
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def verify_integrity(self, expected_digest: Optional[str] = None) -> bool:
        """
        Recompute the content digest and compare. With no argument, compares
        against the digest carried in this envelope's wire form (a no-op for an
        in-memory envelope, which is always self-consistent); pass the digest
        received out-of-band to detect tampering in transit.
        """
        actual = self.content_digest()
        if expected_digest is None:
            return True
        return _consttime_eq(actual, expected_digest)

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #
    def to_wire(self) -> Dict[str, Any]:
        """
        Full wire representation, including the stamped ``content_digest`` so a
        receiver can verify integrity without re-deriving the seal context.
        """
        return {
            "vouch_envelope": ENVELOPE_VERSION,
            "envelope_id": self.envelope_id,
            "to": self.to_did,
            "from": self.from_did,
            "created": self.created,
            "content_type": self.content_type,
            "content_digest": self.content_digest(),
            "payload": self.payload,
            "attestations": self.attestations,
            "provenance": self.provenance,
        }

    @classmethod
    def from_wire(cls, data: Dict[str, Any]) -> "VouchEnvelope":
        """
        Reconstruct an envelope from its wire form and verify its seal.

        Raises:
          PayloadIntegrityError: if the recomputed digest does not match the
            ``content_digest`` carried on the wire, the cargo was altered.
          ValueError: if the envelope is structurally malformed.
        """
        version = data.get("vouch_envelope")
        if version != ENVELOPE_VERSION:
            raise ValueError(f"unsupported envelope version: {version!r}")

        env = cls(
            to_did=data["to"],
            from_did=data["from"],
            payload=data["payload"],
            attestations=data.get("attestations", []),
            provenance=data.get("provenance", {}),
            created=data.get("created", _now_iso8601()),
            envelope_id=data.get("envelope_id", f"urn:uuid:{uuid.uuid4()}"),
            content_type=data.get("content_type", ENVELOPE_CONTENT_TYPE),
        )

        stamped = data.get("content_digest")
        if stamped is not None and not env.verify_integrity(stamped):
            # Local import to avoid a circular dependency with base.py.
            from .base import PayloadIntegrityError

            raise PayloadIntegrityError(
                "envelope content digest mismatch: payload, attestations, or "
                "provenance were altered in transit"
            )
        return env


def _consttime_eq(a: str, b: str) -> bool:
    """Constant-time-ish string compare for digest equality."""
    import hmac

    return hmac.compare_digest(a, b)


def build_envelope(
    *,
    from_did: str,
    to_did: str,
    payload: Dict[str, Any],
    attestations: Optional[List[Dict[str, Any]]] = None,
    provenance: Optional[Dict[str, Any]] = None,
) -> VouchEnvelope:
    """
    Convenience constructor for a Vouch envelope.

    ``payload`` should be an already-signed Vouch credential, typically the
    dict returned by ``Signer.sign_credential(...)``. It is stored by reference
    and never mutated, so its Data Integrity proof remains valid.
    """
    return VouchEnvelope(
        to_did=to_did,
        from_did=from_did,
        payload=payload,
        attestations=list(attestations) if attestations else [],
        provenance=dict(provenance) if provenance else {},
    )
