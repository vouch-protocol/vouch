"""
UDNA transport — identity-first routing via the Sirraya UDNA SDK.

UDNA (Universal DID-Native Addressing) inverts the usual stack: instead of
resolving an identity *down to* a location (DID → domain → IP) and trusting
whoever answers, UDNA treats the DID itself as the routing primitive and
establishes an end-to-end encrypted channel (Noise protocol) directly to the
key that owns it. There is no location to spoof and no domain to seize — the
peer you reach is, by construction, the peer whose key matches the DID.

This adapter targets the real ``sirraya-udna-sdk`` (distribution
``sirraya-udna-sdk``, import package ``udna_sdk``, v1.0.x). That SDK provides:

  * **DID generation** — ``UdnaSDK.create_did()`` mints a ``did:key`` whose
    encoding (``z`` + base58(``0xed01`` ‖ pubkey)) is byte-identical to Vouch's
    own Multikey, so the two interoperate without translation.
  * **UDNA address creation** — ``UdnaSDK.create_address(did, facet_id, flags)``
    produces a signed, base58 UDNA address. ``facet_id`` selects a capability
    lane (``0x01`` Control, ``0x02`` Messaging, ``0x03`` Telemetry).
  * **Address verification** — ``UdnaSDK.verify_address(address)`` checks the
    address signature against the DID's key.
  * **Secure messaging** — ``udna_sdk.udna.NoiseHandshake`` (a handshake that
    exchanges DID-signed ephemeral keys) plus ``SecureMessaging``
    (ChaCha20-Poly1305 over the derived session key). NOTE: the v1.0.x handshake
    authenticates peers but does *not* provide confidentiality — see the
    security warning on :class:`SirrayaUdnaNode`.

What the SDK deliberately does *not* ship is a production wire transport: byte
delivery to a remote peer is left to the integrator (the bundled DHT is an
in-memory demo). So this adapter splits the two concerns cleanly:

  * a :class:`UdnaNode` (the seam the transport talks to) owns *session +
    delivery*. :class:`SirrayaUdnaNode` implements it by composing the SDK's
    Noise/SecureMessaging crypto with a pluggable :class:`UdnaChannel` that
    actually moves the bytes.
  * everything is *optional*. When the SDK is absent, or no node/channel is
    wired, the transport is **dormant** — ``can_route`` returns nothing and the
    routing manager falls back to HTTP. UDNA being unavailable is never fatal;
    that is the whole point of the hybrid design.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from .base import PeerAddress, Transport, TransportUnavailable
from .did_key import did_key_from_ed25519_public, did_key_from_public_jwk
from .envelope import VouchEnvelope

#: Default facet — the capability lane Vouch messages travel on. Maps to the
#: SDK's Messaging facet (``facet_id=0x02``).
DEFAULT_FACET = "vouch.message"

#: URI scheme for UDNA addresses.
UDNA_SCHEME = "udna"

#: SDK facet identifiers (``udna_sdk``: 0x01 Control, 0x02 Messaging, 0x03
#: Telemetry). Vouch messages ride the Messaging facet.
FACET_CONTROL = 0x01
FACET_MESSAGING = 0x02
FACET_TELEMETRY = 0x03


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
    The session + delivery seam the transport talks to.

    Implemented for real by :class:`SirrayaUdnaNode` (which composes the SDK's
    Noise/SecureMessaging crypto with a :class:`UdnaChannel`) and by test
    doubles. Keeping the surface this small is what lets the UDNA transport be
    exercised end-to-end without the SDK installed.
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


@runtime_checkable
class UdnaChannel(Protocol):
    """
    Moves opaque bytes to/from a peer keyed by its UDNA address.

    This is the piece ``sirraya-udna-sdk`` does *not* provide: the SDK supplies
    DID/address/Noise crypto but no production wire transport (only an in-memory
    demo DHT). A deployment plugs in its own delivery here — a relay, a
    libp2p/QUIC overlay, a websocket bridge — and :class:`SirrayaUdnaNode`
    layers the SDK's Noise handshake and ChaCha20-Poly1305 encryption on top.
    """

    async def reachable(self, udna_address: str) -> bool:
        """Whether the peer at ``udna_address`` is currently on the overlay."""
        ...

    async def exchange(self, udna_address: str, frame: bytes) -> bytes:
        """
        Send one frame to ``udna_address`` and return the peer's response frame
        (empty bytes if the peer acknowledges without a body). Used twice per
        secure send: once for the Noise handshake, once for the ciphertext.
        """
        ...

    async def close(self) -> None:
        """Release the channel's resources."""
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
        channel: Optional["UdnaChannel"] = None,
        facet: str = DEFAULT_FACET,
    ) -> "UdnaTransport":
        """
        Build a UDNA transport backed by ``sirraya-udna-sdk``.

        Returns a *dormant* transport (no node) — never raises — when any
        prerequisite is missing, so a caller can always wire UDNA in
        optimistically and rely on graceful fallback. The prerequisites are:

          * the ``udna_sdk`` package is importable;
          * ``private_key_jwk`` is supplied (the node's own ``did:key`` and the
            Noise handshake are bound to this Ed25519 key — the same key Vouch
            signs with);
          * a ``channel`` is supplied (the SDK provides no wire transport, so
            byte delivery must come from the deployment).
        """
        node = _try_build_sirraya_node(
            private_key_jwk=private_key_jwk, channel=channel, facet=facet
        )
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

    @staticmethod
    def generate_did_via_sdk() -> str:
        """
        Mint a fresh ``did:key`` using the real ``udna_sdk.UdnaSDK.create_did``.

        Unlike :meth:`generate_did`, this generates *new* key material inside the
        SDK (use it when you want a UDNA-managed identity rather than reusing the
        Vouch signing key). Raises if the SDK is not installed.
        """
        from udna_sdk import UdnaSDK  # type: ignore

        return UdnaSDK().create_did().did

    @staticmethod
    def verify_udna_address(address: str) -> bool:
        """
        Verify a base58 UDNA address with ``udna_sdk.UdnaSDK.verify_address``
        (checks the address signature against the DID's key). Raises if the SDK
        is not installed.
        """
        from udna_sdk import UdnaSDK  # type: ignore

        return bool(UdnaSDK().verify_address(address).is_valid)

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


def _ed25519_priv_from_jwk(private_key_jwk: str):
    """Recover an ``Ed25519PrivateKey`` from an Ed25519 private JWK string."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from jwcrypto.common import base64url_decode

    jwk_dict = json.loads(private_key_jwk)
    if jwk_dict.get("kty") != "OKP" or jwk_dict.get("crv") != "Ed25519":
        raise ValueError("UDNA node identity requires an Ed25519 OKP private JWK")
    seed = base64url_decode(jwk_dict["d"])
    return Ed25519PrivateKey.from_private_bytes(seed)


def _try_build_sirraya_node(
    *,
    private_key_jwk: Optional[str] = None,
    channel: Optional["UdnaChannel"] = None,
    facet: str = DEFAULT_FACET,
) -> Optional[UdnaNode]:
    """
    Build a :class:`SirrayaUdnaNode` if every prerequisite is present, else
    ``None`` (so the transport stays dormant and the manager falls back).

    Prerequisites: the ``udna_sdk`` package importable, an identity key, and a
    delivery channel (the SDK ships no wire transport — see :class:`UdnaChannel`).
    """
    try:
        import udna_sdk  # type: ignore  # noqa: F401
    except ImportError:
        return None
    if channel is None or private_key_jwk is None:
        return None

    local_priv = _ed25519_priv_from_jwk(private_key_jwk)
    from cryptography.hazmat.primitives import serialization

    pub_raw = local_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    local_did = did_key_from_ed25519_public(pub_raw)
    return SirrayaUdnaNode(channel=channel, local_did=local_did, local_private_key=local_priv)


class SirrayaUdnaNode:
    """
    Real :class:`UdnaNode` backed by ``udna_sdk`` + a pluggable
    :class:`UdnaChannel`.

    Responsibilities are split exactly along what the SDK does and doesn't
    provide:

      * **crypto (SDK):** ``udna_sdk.udna.NoiseHandshake`` exchanges
        DID-signed ephemeral keys bound to ``local_private_key``;
        ``SecureMessaging`` then frames the envelope with ChaCha20-Poly1305 over
        the derived session key.
      * **delivery (channel):** the resulting handshake and ciphertext frames
        are moved to the peer by the injected :class:`UdnaChannel`.

    A secure send is therefore two channel exchanges: the handshake, then the
    encrypted payload. The peer endpoint is expected to speak the same
    ``udna_sdk`` handshake (``respond_to_handshake``) on the other side.

    .. warning::
       **The bundled ``udna_sdk`` v1.0.x handshake does NOT provide transport
       confidentiality.** Its ``finalize_handshake`` derives the session key as
       ``sha256(local_did ‖ remote_did ‖ both ephemeral *public* keys)`` — every
       input is sent in the clear, with no Diffie-Hellman, so a passive observer
       can recompute the key and decrypt the ChaCha20-Poly1305 frames (the SDK's
       own code comments it as a demo placeholder for "a full Noise
       implementation"). The handshake messages *are* signed, so peer
       authenticity holds, but channel secrecy does not.

       Vouch does not depend on this for security: the envelope payload is a
       signed Vouch credential, so its integrity and authenticity hold
       end-to-end regardless of transport. But do **not** treat a UDNA channel
       as private for sensitive payloads until upstream ships a real DH
       handshake (see ``docs/udna-upstream-proposal.md``). For confidential
       payloads today, encrypt at the application layer before sealing, or
       prefer a transport with real channel encryption.

    Args:
      channel: the byte-delivery overlay.
      local_did: this node's ``did:key`` (derived from ``local_private_key``).
      local_private_key: the Ed25519 key the handshake authenticates with.
    """

    def __init__(self, *, channel: "UdnaChannel", local_did: str, local_private_key: Any) -> None:
        from udna_sdk.udna import Did, NoiseHandshake, SecureMessaging  # type: ignore

        self._channel = channel
        self._noise = NoiseHandshake()
        self._secure = SecureMessaging()
        self._Did = Did
        self._local_did = Did.parse(local_did)
        self._local_priv = local_private_key

    @staticmethod
    def _remote_did_of(address: str) -> str:
        """Extract the peer DID from a ``udna://<did>/<facet>`` address."""
        body = address.split("://", 1)[1] if "://" in address else address
        return body.rsplit("/", 1)[0] if "/" in body else body

    async def resolve(self, address: str) -> Optional[Dict[str, Any]]:
        if not await self._channel.reachable(address):
            return None
        return {"address": address, "transport": "sirraya-udna-sdk"}

    async def send_secure(self, address: str, data: bytes) -> bytes:
        remote_did = self._Did.parse(self._remote_did_of(address))

        # 1. DID-authenticated Noise handshake over the delivery channel.
        session_id, init_frame = self._noise.initiate_handshake(
            self._local_did, self._local_priv, remote_did
        )
        response_frame = await self._channel.exchange(address, init_frame)
        session_key = self._noise.finalize_handshake(session_id, response_frame)

        # 2. Encrypt the sealed envelope and deliver it on the same channel.
        ciphertext = self._secure.encrypt_message(session_key, data)
        reply = await self._channel.exchange(address, ciphertext)
        if not reply:
            return b""
        return self._secure.decrypt_message(session_key, reply)

    async def close(self) -> None:
        await self._channel.close()
