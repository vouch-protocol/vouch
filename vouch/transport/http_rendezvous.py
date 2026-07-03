"""
A deployable HTTPS rendezvous for identity-first routing.

:mod:`vouch.transport.rendezvous` proves the announce-resolve-verify contract
with an in-memory registry. This module makes that contract real over commodity
infrastructure: a small HTTPS service any operator can run, plus a client that
resolves a DID to the agent's current endpoint without DNS and without a domain
of its own.

The point worth stressing is the trust model. The rendezvous is *untrusted*. It
stores signed :class:`RouteRecord` objects and serves them back, but it never
needs to be believed: the client re-verifies every record's signature locally
and checks that the record's DID is the one it asked for. A malicious or
compromised rendezvous can withhold a record or serve a stale one, but it cannot
forge a route, because it does not hold the agent's Ed25519 key. This is the
property that lets identity-first routing run on a host you do not control.

Three parts:

  * :class:`RendezvousService` is the server logic, free of any web framework so
    it can be tested directly and embedded anywhere. It verifies on write and on
    read, and serves records by fingerprint, so the DID never appears in a URL.
  * :func:`build_rendezvous_app` wraps the service in a FastAPI app for
    deployment. FastAPI is imported lazily, so the rest of this module (and the
    client) works without it installed.
  * :class:`HttpRendezvousResolver` is the client: announce a signed record,
    resolve a DID to an endpoint, re-verifying locally before trusting it.
  * :class:`HttpRendezvousChannel` completes the path. It resolves a ``udna://``
    address to an ``https://`` inbox and delivers the frame there over TLS, so
    the full identity-first round trip works today on plain HTTPS, with UDNA able
    to drop in behind the same :class:`UdnaChannel` seam later.

Wire contract:

  * ``POST {base}/vouch/rendezvous/records`` with a route-record JSON body
    announces a route. ``204`` on success, ``400`` if the record fails
    verification.
  * ``GET {base}/vouch/rendezvous/records/{fingerprint}?facet={facet}`` returns
    the current signed record as JSON, or ``404`` if there is none.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import httpx

from .. import ssrf
from .rendezvous import (
    RendezvousRegistry,
    RouteRecord,
    route_fingerprint,
)
from .udna import DEFAULT_FACET

#: Path prefix the service mounts its two routes under.
RECORDS_PATH = "/vouch/rendezvous/records"

DEFAULT_TIMEOUT = 10.0


# --------------------------------------------------------------------------- #
# Server: framework-free core
# --------------------------------------------------------------------------- #
class RendezvousService:
    """
    The rendezvous server logic, with no web framework attached.

    It owns a :class:`RendezvousRegistry` and exposes the two operations a
    deployment needs as plain methods that return ``(status_code, body)``. Both
    verify the record: ``put`` rejects anything the DID holder did not sign, and
    ``get`` re-verifies before serving, so an expired or tampered entry is never
    returned.
    """

    def __init__(self, registry: Optional[RendezvousRegistry] = None) -> None:
        self._registry = registry or RendezvousRegistry()

    @property
    def registry(self) -> RendezvousRegistry:
        return self._registry

    def put(self, wire: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """
        Announce a route record. Returns ``(204, {})`` when stored, or
        ``(400, {"error": ...})`` when the record is malformed or fails
        verification. The registry verifies, so a forged or expired record is
        never accepted.
        """
        try:
            record = RouteRecord.from_wire(wire)
        except (KeyError, TypeError) as exc:
            return 400, {"error": f"malformed route record: {exc}"}
        try:
            self._registry.announce(record)
        except ValueError as exc:
            return 400, {"error": str(exc)}
        return 204, {}

    def get(self, fingerprint: str, facet: str = DEFAULT_FACET) -> Tuple[int, Dict[str, Any]]:
        """
        Resolve a fingerprint to its current signed record. Returns
        ``(200, record_wire)`` or ``(404, {"error": ...})``. The record is
        re-verified on read, so a stale entry returns ``404`` rather than a dead
        route.
        """
        record = self._registry.get(fingerprint, facet)
        if record is None:
            return 404, {"error": "no route record for fingerprint on this facet"}
        return 200, record.to_wire()


def build_rendezvous_app(service: Optional[RendezvousService] = None) -> Any:
    """
    Build a FastAPI app exposing a :class:`RendezvousService`.

    FastAPI is imported here, not at module load, so importing this module (and
    using the client) does not require the web framework. Run the returned app
    under any ASGI server::

        uvicorn.run(build_rendezvous_app(), host="0.0.0.0", port=8080)
    """
    try:
        from fastapi import FastAPI, Request, Response
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover - exercised only without FastAPI
        raise RuntimeError(
            "build_rendezvous_app requires FastAPI; install vouch with the server "
            "extra or add fastapi to the environment"
        ) from exc

    service = service or RendezvousService()
    app = FastAPI(title="Vouch Rendezvous", version="1")

    @app.post(RECORDS_PATH)
    async def _put(request: Request) -> Response:
        body = await request.json()
        status, payload = service.put(body)
        if status == 204:
            return Response(status_code=204)
        return JSONResponse(status_code=status, content=payload)

    @app.get(RECORDS_PATH + "/{fingerprint}")
    async def _get(fingerprint: str, facet: str = DEFAULT_FACET) -> Response:
        status, payload = service.get(fingerprint, facet)
        return JSONResponse(status_code=status, content=payload)

    return app


# --------------------------------------------------------------------------- #
# Client: announce and resolve over HTTPS, verifying locally
# --------------------------------------------------------------------------- #
class HttpRendezvousResolver:
    """
    Client for an HTTPS rendezvous.

    The resolver never trusts the rendezvous. It announces signed records and,
    on resolve, re-verifies the returned record's signature and confirms the
    record's DID is the one requested before handing back an endpoint. The
    fingerprint sent on the wire is ``sha256(did)``, so the DID itself never
    appears in the request path.

    Args:
      base_url: the rendezvous root, for example ``https://rv.example.com``.
        Validated against SSRF rules (https-only, public IPs) before each call.
      client: an optional pre-built ``httpx.AsyncClient`` (mainly for tests).
      timeout: per-request timeout in seconds.
      verify_ssl: whether to verify TLS certificates (leave on in production).
      validate_target: SSRF-validate ``base_url`` before each request. Leave on
        in production; tests against an in-process app turn it off.
    """

    def __init__(
        self,
        base_url: str,
        *,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
        validate_target: bool = True,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._validate_target = validate_target

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                verify=self._verify_ssl,
                follow_redirects=False,
            )
        return self._client

    def _records_url(self, suffix: str = "") -> str:
        url = f"{self._base}{RECORDS_PATH}{suffix}"
        if self._validate_target:
            ssrf.validate_url(url)
        return url

    async def announce(self, record: RouteRecord) -> None:
        """
        Publish a signed route record. Verifies the record locally first, so a
        caller never ships an unsigned or expired record, then POSTs it. Raises
        :class:`ValueError` if the record does not verify, or
        :class:`httpx.HTTPStatusError` if the rendezvous rejects it.
        """
        if not record.verify():
            raise ValueError("refusing to announce a route record that fails verification")
        client = self._get_client()
        response = await client.post(self._records_url(), json=record.to_wire())
        response.raise_for_status()

    async def resolve(self, did: str, facet: str = DEFAULT_FACET) -> Optional[str]:
        """
        Resolve ``did`` to its current endpoint, or ``None`` if the rendezvous
        has no live record. The returned record is re-verified locally and its
        DID is checked against ``did``, so a rendezvous cannot substitute another
        agent's route or serve a forged one.
        """
        record = await self.resolve_record(did, facet)
        return record.endpoint if record is not None else None

    async def resolve_record(self, did: str, facet: str = DEFAULT_FACET) -> Optional[RouteRecord]:
        """Resolve to the full verified :class:`RouteRecord`, or ``None``."""
        fingerprint = route_fingerprint(did)
        client = self._get_client()
        response = await client.get(self._records_url(f"/{fingerprint}"), params={"facet": facet})
        if response.status_code == 404:
            return None
        response.raise_for_status()

        record = RouteRecord.from_wire(response.json())
        # Trust the signature, not the server: the record must verify, and it
        # must be the DID we asked for (a rendezvous cannot redirect us to a
        # different identity it happens to hold a record for).
        if not record.verify() or record.did != did:
            return None
        return record

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None


# --------------------------------------------------------------------------- #
# Channel: resolve a udna:// address, then deliver over HTTPS
# --------------------------------------------------------------------------- #
class HttpRendezvousChannel:
    """
    A :class:`UdnaChannel` that runs entirely on commodity HTTPS.

    It resolves a ``udna://`` address through an :class:`HttpRendezvousResolver`
    to the agent's announced ``https://`` inbox, then POSTs the frame there over
    TLS. No DNS binds the agent's identity to a location; the only fixed host is
    the rendezvous, and even that is not trusted, since the resolved record is
    verified before any byte is sent. This is the shippable identity-first path,
    and it sits behind the same seam UDNA will plug into.

    Args:
      resolver: the rendezvous client used to turn a DID into an endpoint.
      client: an optional ``httpx.AsyncClient`` for delivery (mainly for tests).
      timeout: per-request timeout in seconds.
      verify_ssl: whether to verify TLS certificates for delivery.
      validate_endpoint: SSRF-validate the resolved endpoint before POSTing.
        Leave on in production; tests against an in-process app turn it off.
    """

    def __init__(
        self,
        resolver: HttpRendezvousResolver,
        *,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
        validate_endpoint: bool = True,
    ) -> None:
        self._resolver = resolver
        self._client = client
        self._owns_client = client is None
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._validate_endpoint = validate_endpoint

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                verify=self._verify_ssl,
                follow_redirects=False,
            )
        return self._client

    @staticmethod
    def _split(udna_address: str) -> Tuple[str, str]:
        body = udna_address.split("://", 1)[1] if "://" in udna_address else udna_address
        if "/" in body:
            did, facet = body.rsplit("/", 1)
            return did, facet
        return body, DEFAULT_FACET

    async def reachable(self, udna_address: str) -> bool:
        did, facet = self._split(udna_address)
        return await self._resolver.resolve(did, facet) is not None

    async def exchange(self, udna_address: str, frame: bytes) -> bytes:
        did, facet = self._split(udna_address)
        endpoint = await self._resolver.resolve(did, facet)
        if endpoint is None:
            raise KeyError(f"no route record for {did} on facet {facet}")
        if self._validate_endpoint:
            ssrf.validate_url(endpoint)

        client = self._get_client()
        response = await client.post(
            endpoint,
            content=frame,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response.raise_for_status()
        return response.content

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None
        await self._resolver.close()
