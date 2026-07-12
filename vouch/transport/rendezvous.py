"""
Reference resolver for identity-first routing (proof of concept).

This is the piece UDNA needs and the reference SDK does not yet have: a way to
resolve a DID to the agent's current network location, with the mapping signed
by the agent itself. It answers the one question ``did:key`` cannot, "where is
this agent right now," without DNS and without a domain.

The contract is three steps:

  1. **Announce.** An agent publishes a :class:`RouteRecord`, a small object that
     binds its DID to a current endpoint and an expiry, signed by the DID's
     Ed25519 key. Because it is signed, anyone can verify the agent itself
     asserted this route.
  2. **Resolve.** A sender looks up a DID, the registry returns the latest valid
     record, and the sender verifies the signature and the expiry before using
     the endpoint.
  3. **Deliver.** The sender sends to the resolved endpoint.

The lookup here is a single in-memory :class:`RendezvousRegistry`, deliberately
not a distributed hash table. It proves the announce-resolve-verify contract end
to end so the design can be exercised and tested. Swapping the single rendezvous
for a real overlay (a Kademlia DHT, or an existing one like libp2p) is a later
step and does not change this record format or the verification logic, which are
the parts worth pinning down first.

:class:`RendezvousChannel` adapts this resolver to the :class:`UdnaChannel`
protocol, so it drops in behind the rest of the transport stack: resolve the
DID, then deliver the bytes to the registered inbox for that endpoint.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from .. import jcs
from ..multikey import _b58decode, _b58encode
from .did_key import ed25519_public_from_did_key, is_did_key
from .udna import DEFAULT_FACET

ROUTE_RECORD_TYPE = "UdnaRouteRecord"
DEFAULT_TTL_SECONDS = 3600


def route_fingerprint(did: str) -> str:
    """
    The routing key for a DID: ``sha256(did)`` as hex.

    This is the handle an overlay would index on, matching the fingerprint the
    UDNA SDK uses for DHT routing. The identity is the key; no location leaks
    into it.
    """
    return hashlib.sha256(did.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _format_iso8601(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso8601(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@dataclass
class RouteRecord:
    """
    A signed mapping from a DID to its current endpoint.

    The signature covers everything except itself, so the record is
    tamper-evident and self-authenticating: the verifier recovers the public key
    from the DID and checks that the holder of that key produced this route.
    """

    did: str
    endpoint: str
    facet: str = DEFAULT_FACET
    expires: str = ""
    nonce: str = ""
    signature: Optional[str] = None

    def _unsigned(self) -> Dict[str, str]:
        return {
            "type": ROUTE_RECORD_TYPE,
            "did": self.did,
            "endpoint": self.endpoint,
            "facet": self.facet,
            "expires": self.expires,
            "nonce": self.nonce,
        }

    def to_wire(self) -> Dict[str, str]:
        body = self._unsigned()
        if self.signature is not None:
            body["signature"] = self.signature
        return body

    @classmethod
    def from_wire(cls, data: Dict[str, str]) -> "RouteRecord":
        return cls(
            did=data["did"],
            endpoint=data["endpoint"],
            facet=data.get("facet", DEFAULT_FACET),
            expires=data.get("expires", ""),
            nonce=data.get("nonce", ""),
            signature=data.get("signature"),
        )

    def is_expired(self, at: Optional[datetime] = None) -> bool:
        if not self.expires:
            return True
        return (at or _now()) >= _parse_iso8601(self.expires)

    def verify(self) -> bool:
        """
        True when the signature is valid, the DID owns the signing key, and the
        record has not expired. Only ``did:key`` is supported here, since the key
        is in the identifier and needs no network lookup.
        """
        if self.signature is None or not self.signature.startswith("z"):
            return False
        if not is_did_key(self.did):
            return False
        if self.is_expired():
            return False
        try:
            raw_pub = ed25519_public_from_did_key(self.did)
        except ValueError:
            return False
        try:
            sig = _b58decode(self.signature[1:])
            Ed25519PublicKey.from_public_bytes(raw_pub).verify(
                sig, jcs.canonicalize(self._unsigned())
            )
            return True
        except (InvalidSignature, ValueError):
            return False


def build_route_record(
    *,
    did: str,
    endpoint: str,
    private_key: Ed25519PrivateKey,
    facet: str = DEFAULT_FACET,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> RouteRecord:
    """
    Build and sign a :class:`RouteRecord`. The agent calls this to announce
    where it can currently be reached. ``private_key`` must be the Ed25519 key
    behind ``did`` (a ``did:key``).
    """
    record = RouteRecord(
        did=did,
        endpoint=endpoint,
        facet=facet,
        expires=_format_iso8601(_now() + timedelta(seconds=ttl_seconds)),
        nonce=os.urandom(12).hex(),
    )
    sig = private_key.sign(jcs.canonicalize(record._unsigned()))
    record.signature = "z" + _b58encode(sig)
    return record


class RendezvousRegistry:
    """
    A single in-memory rendezvous point: agents announce signed route records,
    senders resolve them by DID. This is the simplest thing that proves the
    contract; a production deployment replaces it with a real overlay while
    keeping the same record format and verification.
    """

    def __init__(self) -> None:
        # (fingerprint, facet) -> RouteRecord
        self._records: Dict[Tuple[str, str], RouteRecord] = {}

    def announce(self, record: RouteRecord) -> None:
        """
        Store a route record after verifying it. A record that fails
        verification (bad signature, wrong DID, expired) is rejected, so the
        registry never serves a route the DID holder did not sign.
        """
        if not record.verify():
            raise ValueError("route record failed verification; not announced")
        self._records[(route_fingerprint(record.did), record.facet)] = record

    def resolve(self, did: str, facet: str = DEFAULT_FACET) -> Optional[str]:
        """
        Return the current endpoint for ``did`` on ``facet``, or ``None`` if the
        DID is unknown or its record has expired. The record is re-verified on
        read, so an entry that aged out is not served.
        """
        record = self._records.get((route_fingerprint(did), facet))
        if record is None or not record.verify():
            return None
        return record.endpoint

    def get(self, fingerprint: str, facet: str = DEFAULT_FACET) -> Optional[RouteRecord]:
        """
        Return the full signed :class:`RouteRecord` indexed under ``fingerprint``
        on ``facet``, re-verified on read, or ``None``. An HTTP rendezvous serves
        by fingerprint (the DID never appears in the request path) and returns
        the whole signed record so the client can verify it for itself.
        """
        record = self._records.get((fingerprint, facet))
        if record is None or not record.verify():
            return None
        return record


# An inbox handler takes a request frame and returns a reply frame.
InboxHandler = Callable[[bytes], Awaitable[bytes]]


class RendezvousChannel:
    """
    A :class:`UdnaChannel` backed by a :class:`RendezvousRegistry`.

    It proves the full identity-first path with no DNS: resolve a ``udna://``
    address to the DID's current endpoint, then deliver the frame to the inbox
    registered for that endpoint. Delivery here is in-process (a registered
    coroutine), which keeps the proof self-contained; a real channel would carry
    the same frame to that endpoint over the network.
    """

    def __init__(self, registry: RendezvousRegistry) -> None:
        self._registry = registry
        self._inboxes: Dict[str, InboxHandler] = {}

    def register_inbox(self, endpoint: str, handler: InboxHandler) -> None:
        """Bind an endpoint string to an in-process handler (the loopback)."""
        self._inboxes[endpoint] = handler

    @staticmethod
    def _split(udna_address: str) -> Tuple[str, str]:
        body = udna_address.split("://", 1)[1] if "://" in udna_address else udna_address
        if "/" in body:
            did, facet = body.rsplit("/", 1)
            return did, facet
        return body, DEFAULT_FACET

    async def reachable(self, udna_address: str) -> bool:
        did, facet = self._split(udna_address)
        endpoint = self._registry.resolve(did, facet)
        return endpoint is not None and endpoint in self._inboxes

    async def exchange(self, udna_address: str, frame: bytes) -> bytes:
        did, facet = self._split(udna_address)
        endpoint = self._registry.resolve(did, facet)
        if endpoint is None:
            raise KeyError(f"no route record for {did} on facet {facet}")
        handler = self._inboxes.get(endpoint)
        if handler is None:
            raise KeyError(f"no inbox registered for endpoint {endpoint}")
        return await handler(frame)

    async def close(self) -> None:
        self._inboxes.clear()
