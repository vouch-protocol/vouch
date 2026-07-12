"""
HTTP transport, the location-first fallback.

This is the transport Vouch has always implicitly used: resolve a ``did:web``
to a domain via DNS/IP, then POST the sealed envelope to that domain's Vouch
inbox over TLS. It is the universal lowest common denominator, any peer that
publishes a ``did:web`` document and runs an HTTPS endpoint is reachable, and
so it serves as the graceful-fallback target when an identity-first transport
(UDNA) is unavailable or the peer does not support it.

Resolution path for ``did:web:example.com``:

  1. Fetch and parse the DID Document (reusing :func:`resolve_did_web`).
  2. If the document advertises a ``VouchInbox`` service, use its
     ``serviceEndpoint``.
  3. Otherwise fall back to the conventional well-known inbox,
     ``https://example.com/.well-known/vouch/inbox``.

Every outbound URL is run through :mod:`vouch.ssrf` (https-only, public IPs
only, redirects disabled) before any request, because the target host is
derived from a potentially attacker-controlled DID.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from .. import ssrf
from ..did_web import did_web_to_url, is_did_web, resolve_did_web
from .base import PeerAddress, Transport, TransportUnavailable
from .envelope import VouchEnvelope

#: Service ``type`` a DID Document uses to advertise a Vouch message inbox.
VOUCH_INBOX_SERVICE = "VouchInbox"

#: Conventional inbox path when the DID Document declares no explicit service.
WELL_KNOWN_INBOX = "/.well-known/vouch/inbox"

DEFAULT_TIMEOUT = 10.0


class HttpTransport(Transport):
    """
    DNS/IP + HTTPS transport keyed on ``did:web``.

    Args:
      timeout: per-request timeout in seconds.
      verify_ssl: whether to verify TLS certificates (leave on in production).
      client: an optional pre-built ``httpx.AsyncClient`` (mainly for tests).
    """

    name = "http"

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client = client
        self._owns_client = client is None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=False,
            )
        return self._client

    async def can_route(self, did: str) -> bool:
        """HTTP can route any ``did:web``, that's the only location-bound DID."""
        return is_did_web(did)

    async def resolve(self, did: str) -> Optional[PeerAddress]:
        """
        Resolve ``did:web`` to a Vouch inbox URL.

        Returns ``None`` (→ fallback) for any non-``did:web`` identifier, since
        HTTP has no way to locate a location-independent DID. Raises
        :class:`TransportUnavailable` if the DID Document cannot be fetched.
        """
        if not is_did_web(did):
            return None

        inbox = await self._discover_inbox(did)
        ssrf.validate_url(inbox)  # https-only, public IPs only
        # DNS does not bind the route to the DID's key, so this peer is reached
        # but not cryptographically *verified* at the transport layer.
        return PeerAddress(
            did=did,
            transport=self.name,
            locator=inbox,
            verified=False,
            metadata={"resolution": "did:web"},
        )

    async def _discover_inbox(self, did: str) -> str:
        """Find the inbox URL: explicit service first, well-known second."""
        try:
            doc = await resolve_did_web(did, timeout=self.timeout, verify_ssl=self.verify_ssl)
        except Exception as exc:
            raise TransportUnavailable(f"did:web resolution failed for {did}: {exc}") from exc

        # The parsed DIDDocument does not expose `service`, so read the raw
        # field defensively if a richer document was provided.
        services = getattr(doc, "service", None) or []
        for svc in services:
            if isinstance(svc, dict) and svc.get("type") == VOUCH_INBOX_SERVICE:
                endpoint = svc.get("serviceEndpoint")
                if isinstance(endpoint, str) and endpoint:
                    return endpoint

        # Conventional well-known inbox derived from the DID's domain.
        doc_url = did_web_to_url(did)
        parsed = urlparse(doc_url)
        return f"{parsed.scheme}://{parsed.netloc}{WELL_KNOWN_INBOX}"

    async def send(self, envelope: VouchEnvelope, peer: PeerAddress) -> Dict[str, Any]:
        """POST the sealed envelope to the peer's inbox over TLS."""
        if not peer.locator:
            raise TransportUnavailable("HTTP peer has no inbox locator")
        ssrf.validate_url(peer.locator)

        client = self._get_client()
        try:
            response = await client.post(
                peer.locator,
                json=envelope.to_wire(),
                headers={
                    "Content-Type": envelope.content_type,
                    "Accept": "application/json",
                },
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            # Network-level failure → let the manager fall back.
            raise TransportUnavailable(f"HTTP delivery to {peer.locator} failed: {exc}") from exc

        if response.status_code >= 400:
            raise TransportUnavailable(
                f"HTTP inbox {peer.locator} rejected envelope: {response.status_code}"
            )

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"status": "accepted"}

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None
