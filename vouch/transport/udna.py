"""
UDNA transport — identity-first routing via the Sirraya UDNA SDK.

UDNA (Universal DID-Native Addressing) inverts the usual stack: instead of
resolving an identity *down to* a location (DID → domain → IP) and trusting
whoever answers, UDNA treats the DID itself as the routing primitive and
establishes an end-to-end encrypted channel (Noise protocol) directly to the
key that owns it. There is no location to spoof and no domain to seize — the
peer you reach is, by construction, the peer whose key matches the DID.

This adapter wraps the core concepts of ``sirraya-udna-sdk``:

  * **DID generation** — derive a ``did:key`` from an Ed25519 identity
    (:mod:`vouch.transport.did_key`), the same key Vouch already signs with.
  * **UDNA address creation** — project a DID (optionally a *facet*, a named
    capability lane such as ``vouch.message``) into a ``udna://`` address the
    overlay can route.
  * **Secure messaging** — hand the sealed envelope to the SDK node, which
    performs the Noise handshake, verifies the peer's DID, and delivers the
    bytes.

The SDK is an *optional* dependency. To keep the transport usable and testable
without it — and to let the rest of Vouch import this module unconditionally —
all SDK interaction goes through the small :class:`UdnaNode` protocol. A real
deployment passes a node backed by ``sirraya-udna-sdk`` (auto-constructed by
:meth:`UdnaTransport.from_sdk`); when the SDK is absent and no node is
injected, the transport simply reports it ``can_route`` nothing, and the
routing manager falls back to HTTP. Nothing about UDNA being unavailable is
fatal — that is the whole point of the hybrid design.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable

from .base import PeerAddress, Transport, TransportUnavailable
from .did_key import did_key_from_ed25519_public, did_key_from_public_jwk
from .envelope import VouchEnvelope

#: Default facet — the capability lane Vouch messages travel on.
DEFAULT_FACET = "vouch.message"

#: URI scheme for UDNA addresses.
UDNA_SCHEME = "udna"


def udna_address(did: str, facet: str = DEFAULT_FACET) -> str:
    """
    Project a DID into a UDNA address.

    The address binds an identity to a capability lane (*facet*) without
    binding it to a location:

      ``did:key:z6Mk…``  →  ``udna://did:key:z6Mk…/vouch.message``

    Routing is over the DID; the facet selects which of the peer's advertised
    capabilities the message is for.
    """
    if not did:
        raise ValueError("udna_address requires a DID")
    if facet:
        return f"{UDNA_SCHEME}://{did}/{facet}"
    return f"{UDNA_SCHEME}://{did}"


@runtime_checkable
class UdnaNode(Protocol):
    """
    The slice of ``sirraya-udna-sdk`` this adapter depends on.

    Implemented for real by :class:`_SirrayaUdnaNode` (wrapping the SDK) and by
    test doubles. Keeping the surface this small is what lets the UDNA transport
    be exercised end-to-end without the SDK installed.
    """

    async def resolve(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a ``udna://`` address over the overlay. Return a route
        descriptor (implementation-defined) if the peer advertises the facet,
        or ``None`` if it does not (which triggers fallback).
        """
        ...

    async def send_secure(self, address: str, data: bytes) -> bytes:
        """
        Open (or reuse) a Noise channel to ``address``, verify the peer's DID,
        send ``data``, and return the peer's reply bytes. Raise on failure to
        establish the channel.
        """
        ...

    async def close(self) -> None:
        """Tear down channels and overlay sockets."""
        ...


class UdnaTransport(Transport):
    """
    Identity-first transport. Routes any DID for which a UDNA node is attached
    and the peer advertises the configured facet.

    Construct directly with a node (or a test double), or via
    :meth:`from_sdk` to auto-wire the real ``sirraya-udna-sdk``.

    Args:
      node: an object satisfying :class:`UdnaNode`, or ``None`` to leave the
        transport dormant (it will route nothing, forcing fallback).
      facet: the capability lane Vouch messages use.
    """

    name = "udna"

    def __init__(self, node: Optional[UdnaNode] = None, facet: str = DEFAULT_FACET) -> None:
        self._node = node
        self.facet = facet

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_sdk(
        cls,
        *,
        private_key_jwk: Optional[str] = None,
        facet: str = DEFAULT_FACET,
        **sdk_kwargs: Any,
    ) -> "UdnaTransport":
        """
        Build a UDNA transport backed by ``sirraya-udna-sdk``.

        If the SDK is not installed, returns a *dormant* transport (no node)
        rather than raising — so a caller can always wire UDNA in optimistically
        and rely on graceful fallback. Pass ``private_key_jwk`` to give the
        node a stable identity (its own ``did:key`` is derived from it).
        """
        node = _try_build_sirraya_node(private_key_jwk=private_key_jwk, **sdk_kwargs)
        return cls(node=node, facet=facet)

    @property
    def is_active(self) -> bool:
        """True when a UDNA node is attached and able to route."""
        return self._node is not None

    # ------------------------------------------------------------------ #
    # DID / address helpers (pure, usable without a node)
    # ------------------------------------------------------------------ #
    @staticmethod
    def generate_did(public_key_jwk: str) -> str:
        """Derive this transport's native ``did:key`` from an Ed25519 public JWK."""
        return did_key_from_public_jwk(public_key_jwk)

    @staticmethod
    def generate_did_from_raw(raw_public_key: bytes) -> str:
        """Derive a ``did:key`` from a raw 32-byte Ed25519 public key."""
        return did_key_from_ed25519_public(raw_public_key)

    def address_for(self, did: str) -> str:
        """The UDNA address this transport would route ``did`` to."""
        return udna_address(did, self.facet)

    # ------------------------------------------------------------------ #
    # Transport contract
    # ------------------------------------------------------------------ #
    async def can_route(self, did: str) -> bool:
        """
        UDNA can route any DID — *if* a node is attached. With no node the
        transport is dormant and routes nothing, so the manager falls back.
        """
        return self._node is not None and bool(did)

    async def resolve(self, did: str) -> Optional[PeerAddress]:
        """
        Resolve ``did`` over the UDNA overlay.

        Returns ``None`` (→ fallback) when the transport is dormant or the peer
        does not advertise the facet. A successful resolution is marked
        ``verified=True``: UDNA binds the route to the DID's key, so reaching
        the address means reaching the key's owner.
        """
        if self._node is None:
            return None

        address = self.address_for(did)
        try:
            route = await self._node.resolve(address)
        except Exception as exc:
            raise TransportUnavailable(f"UDNA resolution failed for {did}: {exc}") from exc

        if route is None:
            # Peer is not on UDNA / does not advertise this facet → fall back.
            return None

        return PeerAddress(
            did=did,
            transport=self.name,
            locator=address,
            verified=True,
            metadata={"facet": self.facet, "route": route},
        )

    async def send(self, envelope: VouchEnvelope, peer: PeerAddress) -> Dict[str, Any]:
        """
        Deliver the sealed envelope over a Noise channel to the peer's DID.

        The envelope is serialized to its canonical wire form (preserving the
        Vouch credential, liability attestations, and provenance verbatim),
        encrypted by the SDK's Noise channel, and sent. The peer's reply is
        returned as a dict.
        """
        if self._node is None:
            raise TransportUnavailable("UDNA transport is dormant (no node attached)")
        if not peer.locator:
            raise TransportUnavailable("UDNA peer has no address locator")

        import json

        wire = json.dumps(envelope.to_wire(), separators=(",", ":")).encode("utf-8")
        try:
            reply = await self._node.send_secure(peer.locator, wire)
        except Exception as exc:
            # Channel could not be established / peer dropped → fall back.
            raise TransportUnavailable(
                f"UDNA secure delivery to {peer.locator} failed: {exc}"
            ) from exc

        if not reply:
            return {}
        try:
            return json.loads(reply.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"status": "accepted"}

    async def close(self) -> None:
        if self._node is not None:
            await self._node.close()
            self._node = None


def _try_build_sirraya_node(
    *, private_key_jwk: Optional[str] = None, **sdk_kwargs: Any
) -> Optional[UdnaNode]:
    """
    Attempt to construct a node backed by ``sirraya-udna-sdk``.

    Returns ``None`` if the SDK is not importable, so the caller degrades to
    HTTP fallback instead of crashing. The exact SDK surface is wrapped in
    :class:`_SirrayaUdnaNode` so that API drift is contained to one place.
    """
    try:
        import sirraya_udna_sdk  # type: ignore  # noqa: F401
    except ImportError:
        return None
    return _SirrayaUdnaNode(private_key_jwk=private_key_jwk, **sdk_kwargs)


class _SirrayaUdnaNode:
    """
    Thin wrapper translating the :class:`UdnaNode` protocol onto the
    ``sirraya-udna-sdk`` runtime.

    The SDK's concrete API is accessed lazily and defensively: we wrap it here
    so the rest of Vouch depends only on the stable :class:`UdnaNode` shape, and
    any change in the SDK's method names is absorbed in this single class.
    """

    def __init__(self, *, private_key_jwk: Optional[str] = None, **sdk_kwargs: Any) -> None:
        import sirraya_udna_sdk  # type: ignore

        # The SDK exposes a Node/Agent entry point that owns the Noise stack and
        # the DID-native overlay socket. We pass through the agent's identity so
        # its own did:key matches the Vouch signing key.
        node_factory = getattr(sirraya_udna_sdk, "Node", None) or getattr(
            sirraya_udna_sdk, "UdnaNode", None
        )
        if node_factory is None:  # pragma: no cover - depends on SDK version
            raise TransportUnavailable("sirraya-udna-sdk exposes no Node entry point")
        self._node = node_factory(private_key_jwk=private_key_jwk, **sdk_kwargs)

    async def resolve(
        self, address: str
    ) -> Optional[Dict[str, Any]]:  # pragma: no cover - needs SDK
        return await self._node.resolve(address)

    async def send_secure(self, address: str, data: bytes) -> bytes:  # pragma: no cover - needs SDK
        # The SDK performs the Noise handshake + DID verification internally.
        return await self._node.send(address, data)

    async def close(self) -> None:  # pragma: no cover - needs SDK
        close = getattr(self._node, "close", None)
        if close is not None:
            await close()
