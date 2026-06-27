"""
Vouch hybrid transport layer.

A modular, DID-addressed networking layer that lets a Vouch agent dispatch a
message to a peer's *identity* and stay agnostic about how it is routed. Two
transports ship in the box:

  * :class:`UdnaTransport` — identity-first routing via the Sirraya UDNA SDK.
    The DID is the route; delivery rides a Noise-encrypted channel straight to
    the key that owns it. Optional; dormant (and harmless) when the SDK is
    absent.
  * :class:`HttpTransport` — the location-first fallback. Resolve ``did:web``
    to a domain over DNS/IP and POST over TLS. Universally reachable.

:class:`TransportManager` ties them together with graceful fallback: prefer
UDNA, fall back to HTTP when a peer is not on the overlay. The
:class:`VouchEnvelope` carries the signed credential, liability attestations,
and provenance metadata across the transport boundary without altering a byte.

Quick start::

    from vouch import Signer, generate_identity
    from vouch.transport import TransportManager, build_envelope

    kp = generate_identity(domain="agent.example.com")
    signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
    credential = signer.sign_credential(intent={
        "action": "settle_invoice",
        "target": "invoice-42",
        "resource": "https://api.example.com/invoices/42",
    })

    envelope = build_envelope(
        from_did=kp.did,
        to_did="did:web:peer.example.com",
        payload=credential,
    )

    manager = TransportManager.default(private_key_jwk=kp.private_key_jwk)
    result = await manager.dispatch(envelope)
    print(result.transport, result.attempts)   # e.g. "http" ["udna", "http"]
"""

from __future__ import annotations

from .base import (
    DeliveryResult,
    PayloadIntegrityError,
    PeerAddress,
    Transport,
    TransportError,
    TransportUnavailable,
)
from .did_key import (
    did_key_from_ed25519_public,
    did_key_from_public_jwk,
    ed25519_public_from_did_key,
    is_did_key,
)
from .envelope import (
    ENVELOPE_CONTENT_TYPE,
    ENVELOPE_VERSION,
    VouchEnvelope,
    build_envelope,
)
from .http_transport import HttpTransport
from .manager import TransportManager
from .udna import (
    DEFAULT_FACET,
    FACET_CONTROL,
    FACET_MESSAGING,
    FACET_TELEMETRY,
    SirrayaUdnaNode,
    UdnaChannel,
    UdnaNode,
    UdnaTransport,
    udna_address,
)

__all__ = [
    # Core abstractions
    "Transport",
    "TransportManager",
    "PeerAddress",
    "DeliveryResult",
    # Errors
    "TransportError",
    "TransportUnavailable",
    "PayloadIntegrityError",
    # Envelope
    "VouchEnvelope",
    "build_envelope",
    "ENVELOPE_VERSION",
    "ENVELOPE_CONTENT_TYPE",
    # Transports
    "UdnaTransport",
    "UdnaNode",
    "UdnaChannel",
    "SirrayaUdnaNode",
    "udna_address",
    "DEFAULT_FACET",
    "FACET_CONTROL",
    "FACET_MESSAGING",
    "FACET_TELEMETRY",
    "HttpTransport",
    # did:key helpers
    "is_did_key",
    "did_key_from_ed25519_public",
    "did_key_from_public_jwk",
    "ed25519_public_from_did_key",
]
