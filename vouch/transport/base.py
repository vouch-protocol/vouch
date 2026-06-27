"""
Transport abstraction for the Vouch Protocol.

Vouch credentials (signed intents, liability attestations, provenance
metadata) are *what* an agent says; a transport is *how* that statement
reaches a peer. Historically the only transport was DNS/IP + HTTP(S): you
resolve a `did:web` to a domain, then POST to it. That couples delivery to
location — whoever controls the IP controls the route.

This module defines the location-agnostic interface every transport
implements so that a Vouch agent can dispatch a message addressed only to a
peer's DID and remain unaware of whether it travelled over UDNA
(identity-first) or HTTP (location-first). The :class:`Transport` contract is
deliberately small:

  * ``can_route(did)``  — could this transport plausibly reach this DID?
  * ``resolve(did)``    — turn the DID into a concrete :class:`PeerAddress`.
  * ``send(envelope, peer)`` — deliver the payload, returning the peer reply.

A transport signals "not my problem, try the next one" by raising
:class:`TransportUnavailable` (or returning ``None`` from ``resolve``). It
signals a corrupted payload — a bug the caller must not paper over by
silently re-routing — by raising :class:`PayloadIntegrityError`. The
:class:`~vouch.transport.manager.TransportManager` uses exactly that
distinction to decide between graceful fallback and hard failure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class TransportError(Exception):
    """Base class for all transport-layer failures."""


class TransportUnavailable(TransportError):
    """
    Raised when a transport cannot reach a peer — the peer does not advertise
    this transport, resolution failed, or the underlying channel could not be
    established. This is the signal the routing manager treats as "fall back to
    the next transport"; it is never fatal on its own.
    """


class PayloadIntegrityError(TransportError):
    """
    Raised when an envelope's content digest does not match its payload. This
    means the Vouch credential, liability attestations, or provenance metadata
    were altered after sealing. It is fatal: the manager must NOT fall back and
    re-send a payload it can no longer vouch for.
    """


@dataclass
class PeerAddress:
    """
    A resolved, transport-specific way to reach a peer DID.

    The ``did`` is the stable, location-independent identity. ``locator`` is
    the concrete handle the owning transport understands — a UDNA address
    (``udna://…``) or an HTTPS inbox URL — and is meaningful only to the
    transport that produced it. ``verified`` records whether the locator was
    cryptographically bound to the DID during resolution (UDNA verifies the
    DID owns the route; plain DNS does not).
    """

    did: str
    transport: str
    locator: Optional[str] = None
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeliveryResult:
    """
    Outcome of a dispatch. ``attempts`` lists, in order, every transport the
    manager tried, so callers can observe the fallback path (e.g.
    ``["udna", "http"]`` means UDNA was attempted first and HTTP delivered).
    """

    ok: bool
    transport: str
    peer: PeerAddress
    envelope_id: str
    response: Optional[Dict[str, Any]] = None
    attempts: List[str] = field(default_factory=list)


class Transport(ABC):
    """
    Abstract base class for a Vouch message transport.

    Implementations are addressed by DID, never by location. The manager calls
    ``can_route`` as a cheap pre-filter, then ``resolve`` to obtain a
    :class:`PeerAddress`, then ``send``. Implementations must not mutate the
    envelope they are handed — the payload's cryptographic proofs depend on it
    being byte-for-byte preserved across the transport boundary.
    """

    #: Stable, lowercase identifier used in preference ordering and
    #: ``DeliveryResult.attempts`` (e.g. ``"udna"``, ``"http"``).
    name: str = "transport"

    @abstractmethod
    async def can_route(self, did: str) -> bool:
        """
        Cheap, best-effort check of whether this transport could reach ``did``.
        Should not perform network I/O when a syntactic check suffices (e.g.
        HTTP can route any ``did:web``; UDNA can route any DID once a node is
        attached). Returning ``True`` is not a promise of delivery.
        """

    @abstractmethod
    async def resolve(self, did: str) -> Optional[PeerAddress]:
        """
        Resolve ``did`` to a concrete :class:`PeerAddress`, or return ``None``
        if this transport cannot reach the peer (which triggers fallback). May
        raise :class:`TransportUnavailable` for the same effect when it wants
        to attach a diagnostic message.
        """

    @abstractmethod
    async def send(self, envelope: "VouchEnvelope", peer: PeerAddress) -> Dict[str, Any]:
        """
        Deliver ``envelope`` to ``peer`` and return the peer's reply as a dict
        (empty dict if the peer acknowledges without a body).

        Raises:
          TransportUnavailable: the channel could not be established or the
            peer rejected the connection — the manager will fall back.
          PayloadIntegrityError: the envelope failed its own integrity check.
        """

    async def close(self) -> None:
        """Release any held resources (sockets, SDK nodes). Idempotent."""
        return None


# Imported at the bottom to avoid a circular import: ``envelope`` imports
# nothing from this module, but type checkers and the ``send`` signature above
# reference :class:`VouchEnvelope`.
from .envelope import VouchEnvelope  # noqa: E402  (re-exported for typing)
