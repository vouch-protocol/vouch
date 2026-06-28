"""
Tests for the deployable HTTPS rendezvous.

These drive the real client (:class:`HttpRendezvousResolver`) against the real
server logic (:class:`RendezvousService`) over an in-process ``httpx`` transport,
so the announce/resolve/verify/deliver contract is exercised end to end with no
network and no web framework. The trust model is the point: the client verifies
every record itself, so a lying rendezvous cannot forge or substitute a route.
"""

from __future__ import annotations

import json

import httpx
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.common import base64url_decode

from vouch import Signer, generate_identity
from vouch.transport import (
    HttpRendezvousChannel,
    HttpRendezvousResolver,
    RendezvousService,
    build_envelope,
    build_route_record,
    route_fingerprint,
    udna_address,
)
from vouch.transport.did_key import did_key_from_public_jwk
from vouch.transport.http_rendezvous import RECORDS_PATH


def _identity():
    kp = generate_identity()
    did = did_key_from_public_jwk(kp.public_key_jwk)
    seed = base64url_decode(json.loads(kp.private_key_jwk)["d"])
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return kp, did, priv


def _service_client(service: RendezvousService) -> httpx.AsyncClient:
    """An httpx client that dispatches requests straight into the service."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == RECORDS_PATH:
            status, body = service.put(json.loads(request.content))
            if status == 204:
                return httpx.Response(204)
            return httpx.Response(status, json=body)
        if request.method == "GET" and path.startswith(RECORDS_PATH + "/"):
            fingerprint = path.rsplit("/", 1)[1]
            facet = request.url.params.get("facet", "vouch.message")
            status, body = service.get(fingerprint, facet)
            return httpx.Response(status, json=body)
        return httpx.Response(404, json={"error": "not found"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _resolver(service: RendezvousService) -> HttpRendezvousResolver:
    return HttpRendezvousResolver(
        "https://rv.example.com",
        client=_service_client(service),
        validate_target=False,
    )


# --------------------------------------------------------------------------- #
# Service: verify on write and read
# --------------------------------------------------------------------------- #
class TestService:
    def test_put_then_get_by_fingerprint(self):
        _, did, priv = _identity()
        svc = RendezvousService()
        rec = build_route_record(did=did, endpoint="https://a.example/inbox", private_key=priv)
        assert svc.put(rec.to_wire())[0] == 204
        status, body = svc.get(route_fingerprint(did))
        assert status == 200
        assert body["endpoint"] == "https://a.example/inbox"
        assert body["did"] == did

    def test_get_unknown_is_404(self):
        _, did, _ = _identity()
        status, _ = RendezvousService().get(route_fingerprint(did))
        assert status == 404

    def test_put_rejects_forged_record(self):
        _, did, priv = _identity()
        svc = RendezvousService()
        rec = build_route_record(did=did, endpoint="https://a.example/inbox", private_key=priv)
        wire = rec.to_wire()
        wire["endpoint"] = "https://attacker.example/inbox"  # break the signature
        status, body = svc.put(wire)
        assert status == 400
        assert "error" in body

    def test_put_malformed_is_400(self):
        status, body = RendezvousService().put({"did": "did:key:z6Mk"})
        assert status == 400


# --------------------------------------------------------------------------- #
# Client: announce / resolve, verifying locally
# --------------------------------------------------------------------------- #
class TestResolver:
    async def test_announce_then_resolve(self):
        _, did, priv = _identity()
        resolver = _resolver(RendezvousService())
        await resolver.announce(
            build_route_record(did=did, endpoint="https://a.example/inbox", private_key=priv)
        )
        assert await resolver.resolve(did) == "https://a.example/inbox"
        await resolver.close()

    async def test_resolve_unknown_returns_none(self):
        _, did, _ = _identity()
        resolver = _resolver(RendezvousService())
        assert await resolver.resolve(did) is None
        await resolver.close()

    async def test_announce_refuses_unsigned_record(self):
        from vouch.transport import RouteRecord

        _, did, _ = _identity()
        resolver = _resolver(RendezvousService())
        with pytest.raises(ValueError):
            await resolver.announce(RouteRecord(did=did, endpoint="x", signature="zbad"))
        await resolver.close()

    async def test_client_rejects_a_lying_rendezvous(self):
        """
        A rendezvous that returns a record for a different DID than asked is
        rejected: the client checks record.did against the requested DID.
        """
        _, alice, _ = _identity()
        _, bob, bob_priv = _identity()

        # Bob has a validly signed record; the rendezvous will try to pass it off
        # as Alice's when Alice is queried.
        bob_rec = build_route_record(
            did=bob, endpoint="https://bob.example/inbox", private_key=bob_priv
        )

        def handler(request: httpx.Request) -> httpx.Response:
            # However Alice is queried, hand back Bob's (validly signed) record.
            return httpx.Response(200, json=bob_rec.to_wire())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        resolver = HttpRendezvousResolver(
            "https://rv.example.com", client=client, validate_target=False
        )
        # The signature is valid, but it is not Alice's route, so resolve refuses.
        assert await resolver.resolve(alice) is None
        await resolver.close()


# --------------------------------------------------------------------------- #
# Channel: resolve a udna:// address and deliver over HTTPS
# --------------------------------------------------------------------------- #
class TestChannel:
    async def test_resolve_and_deliver_preserves_payload(self):
        kp, did, priv = _identity()
        svc = RendezvousService()

        received = {}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if request.method == "POST" and path == RECORDS_PATH:
                status, body = svc.put(json.loads(request.content))
                return httpx.Response(204) if status == 204 else httpx.Response(status, json=body)
            if request.method == "GET" and path.startswith(RECORDS_PATH + "/"):
                fingerprint = path.rsplit("/", 1)[1]
                facet = request.url.params.get("facet", "vouch.message")
                status, body = svc.get(fingerprint, facet)
                return httpx.Response(status, json=body)
            # The agent's inbox: capture the delivered frame, reply ok.
            if request.method == "POST" and path == "/inbox":
                received["frame"] = request.content
                return httpx.Response(200, json={"status": "ok"})
            return httpx.Response(404)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        resolver = HttpRendezvousResolver(
            "https://rv.example.com", client=client, validate_target=False
        )
        channel = HttpRendezvousChannel(resolver, client=client, validate_endpoint=False)

        # The agent announces an https inbox as its route.
        await resolver.announce(
            build_route_record(did=did, endpoint="https://agent.example/inbox", private_key=priv)
        )

        addr = udna_address(did)
        assert await channel.reachable(addr) is True

        signer = Signer(private_key=kp.private_key_jwk, did="did:web:sender.example.com")
        cred = signer.sign_credential(
            intent={"action": "ping", "target": "t", "resource": "https://x/t"}
        )
        env = build_envelope(from_did="did:web:sender.example.com", to_did=did, payload=cred)
        reply = await channel.exchange(addr, json.dumps(env.to_wire()).encode("utf-8"))

        assert json.loads(reply) == {"status": "ok"}
        delivered = json.loads(received["frame"])
        assert delivered["payload"]["proof"] == cred["proof"]
        await channel.close()

    async def test_unreachable_when_not_announced(self):
        _, did, _ = _identity()
        resolver = _resolver(RendezvousService())
        channel = HttpRendezvousChannel(
            resolver, client=_service_client(RendezvousService()), validate_endpoint=False
        )
        assert await channel.reachable(udna_address(did)) is False
        with pytest.raises(KeyError):
            await channel.exchange(udna_address(did), b"{}")
        await channel.close()
