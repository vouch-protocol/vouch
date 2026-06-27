"""
Tests for the hybrid transport layer (UDNA + HTTP fallback).

The Sirraya UDNA SDK is not a test dependency, so the UDNA transport is
exercised through the :class:`UdnaNode` protocol with in-memory fakes. This is
the same seam a real deployment uses, so the routing logic under test is the
production path, not a mock of it.
"""

from __future__ import annotations

import json

import pytest

from vouch import Signer, generate_identity
from vouch.transport import (
    DeliveryResult,
    HttpTransport,
    PayloadIntegrityError,
    PeerAddress,
    TransportError,
    TransportManager,
    UdnaTransport,
    VouchEnvelope,
    build_envelope,
    ed25519_public_from_did_key,
    is_did_key,
    udna_address,
)
from vouch.transport.envelope import ENVELOPE_VERSION


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _signed_credential(domain: str = "agent.example.com"):
    kp = generate_identity(domain=domain)
    signer = Signer(private_key=kp.private_key_jwk, did=kp.did)
    cred = signer.sign_credential(
        intent={
            "action": "settle_invoice",
            "target": "invoice-42",
            "resource": "https://api.example.com/invoices/42",
        }
    )
    return kp, cred


class FakeUdnaNode:
    """In-memory stand-in for a sirraya-udna-sdk node."""

    def __init__(self, reachable=True, reply=None):
        self.reachable = reachable
        self.reply = reply if reply is not None else {"status": "delivered"}
        self.sent = []
        self.closed = False

    async def resolve(self, address):
        if not self.reachable:
            return None
        return {"address": address, "hops": 1}

    async def send_secure(self, address, data):
        self.sent.append((address, data))
        return json.dumps(self.reply).encode("utf-8")

    async def close(self):
        self.closed = True


# --------------------------------------------------------------------------- #
# Envelope: payload preservation + integrity
# --------------------------------------------------------------------------- #
class TestEnvelope:
    def test_build_preserves_signed_payload_by_reference(self):
        _, cred = _signed_credential()
        env = build_envelope(
            from_did="did:web:a.example.com",
            to_did="did:web:b.example.com",
            payload=cred,
        )
        # The credential dict is carried verbatim — proof intact.
        assert env.payload is cred
        assert "proof" in env.payload

    def test_wire_roundtrip_preserves_proof_and_attestations(self):
        _, cred = _signed_credential()
        env = build_envelope(
            from_did="did:web:a.example.com",
            to_did="did:web:b.example.com",
            payload=cred,
            attestations=[{"type": "OutcomeCommitment", "id": "urn:c:1"}],
            provenance={"contentHash": "sha256:abcd"},
        )
        wire = env.to_wire()
        assert wire["vouch_envelope"] == ENVELOPE_VERSION
        restored = VouchEnvelope.from_wire(wire)
        assert restored.payload == cred
        assert restored.payload["proof"] == cred["proof"]
        assert restored.attestations[0]["id"] == "urn:c:1"
        assert restored.provenance["contentHash"] == "sha256:abcd"

    def test_digest_is_order_independent(self):
        env1 = build_envelope(from_did="a", to_did="b", payload={"x": 1, "y": 2})
        env2 = build_envelope(from_did="a", to_did="b", payload={"y": 2, "x": 1})
        assert env1.content_digest() == env2.content_digest()

    def test_tampered_cargo_fails_integrity_on_decode(self):
        _, cred = _signed_credential()
        env = build_envelope(from_did="a", to_did="b", payload=cred)
        wire = env.to_wire()
        # Mutate the payload after the digest was stamped.
        wire["payload"]["credentialSubject"] = {"action": "tampered"}
        with pytest.raises(PayloadIntegrityError):
            VouchEnvelope.from_wire(wire)

    def test_verify_integrity_detects_external_digest_mismatch(self):
        env = build_envelope(from_did="a", to_did="b", payload={"x": 1})
        assert env.verify_integrity(env.content_digest()) is True
        assert env.verify_integrity("sha256:deadbeef") is False


# --------------------------------------------------------------------------- #
# did:key generation (UDNA identity)
# --------------------------------------------------------------------------- #
class TestDidKey:
    def test_generate_did_key_from_identity(self):
        kp = generate_identity()
        did = UdnaTransport.generate_did(kp.public_key_jwk)
        assert is_did_key(did)
        assert did.startswith("did:key:z6Mk")

    def test_did_key_roundtrips_to_public_key(self):
        kp = generate_identity()
        did = UdnaTransport.generate_did(kp.public_key_jwk)
        raw = ed25519_public_from_did_key(did)
        assert len(raw) == 32

    def test_udna_address_binds_did_and_facet(self):
        addr = udna_address("did:key:z6MkABC", facet="vouch.message")
        assert addr == "udna://did:key:z6MkABC/vouch.message"


# --------------------------------------------------------------------------- #
# UDNA transport
# --------------------------------------------------------------------------- #
class TestUdnaTransport:
    async def test_dormant_without_node_routes_nothing(self):
        udna = UdnaTransport(node=None)
        assert udna.is_active is False
        assert await udna.can_route("did:key:z6MkABC") is False
        assert await udna.resolve("did:key:z6MkABC") is None

    async def test_resolve_marks_peer_verified(self):
        udna = UdnaTransport(node=FakeUdnaNode())
        peer = await udna.resolve("did:key:z6MkABC")
        assert peer is not None
        assert peer.verified is True
        assert peer.transport == "udna"
        assert peer.locator == "udna://did:key:z6MkABC/vouch.message"

    async def test_resolve_returns_none_when_peer_not_on_overlay(self):
        udna = UdnaTransport(node=FakeUdnaNode(reachable=False))
        assert await udna.resolve("did:key:z6MkABC") is None

    async def test_send_delivers_over_secure_channel(self):
        node = FakeUdnaNode(reply={"status": "ok"})
        udna = UdnaTransport(node=node)
        _, cred = _signed_credential()
        env = build_envelope(from_did="a", to_did="did:key:z6MkABC", payload=cred)
        peer = await udna.resolve("did:key:z6MkABC")
        reply = await udna.send(env, peer)
        assert reply == {"status": "ok"}
        # The bytes that hit the wire are the canonical envelope, proof intact.
        sent_address, sent_bytes = node.sent[0]
        decoded = json.loads(sent_bytes.decode("utf-8"))
        assert decoded["payload"]["proof"] == cred["proof"]


# --------------------------------------------------------------------------- #
# Fallback routing manager
# --------------------------------------------------------------------------- #
class TestTransportManager:
    async def test_prefers_udna_when_available(self):
        node = FakeUdnaNode()
        manager = TransportManager.default(udna_node=node)
        _, cred = _signed_credential()
        env = build_envelope(from_did="a", to_did="did:key:z6MkABC", payload=cred)
        result = await manager.dispatch(env)
        assert isinstance(result, DeliveryResult)
        assert result.ok is True
        assert result.transport == "udna"
        assert result.attempts == ["udna"]

    async def test_falls_back_to_http_when_udna_dormant(self):
        # No node and no SDK → UDNA dormant. did:web is HTTP-routable.
        captured = {}

        class FakeHttp(HttpTransport):
            async def resolve(self, did):
                return PeerAddress(did=did, transport="http", locator="https://b.example.com/inbox")

            async def send(self, envelope, peer):
                captured["wire"] = envelope.to_wire()
                return {"status": "accepted"}

        manager = TransportManager([UdnaTransport(node=None), FakeHttp()])
        _, cred = _signed_credential()
        env = build_envelope(from_did="a", to_did="did:web:b.example.com", payload=cred)
        result = await manager.dispatch(env)
        assert result.transport == "http"
        # UDNA dormant → can_route False → not even attempted.
        assert result.attempts == ["http"]
        assert captured["wire"]["payload"]["proof"] == cred["proof"]

    async def test_falls_back_when_udna_peer_not_reachable(self):
        # UDNA node present but peer not on overlay → fall through to HTTP.
        node = FakeUdnaNode(reachable=False)

        class FakeHttp(HttpTransport):
            async def resolve(self, did):
                return PeerAddress(did=did, transport="http", locator="https://b.example.com/inbox")

            async def send(self, envelope, peer):
                return {"status": "accepted"}

        manager = TransportManager([UdnaTransport(node=node), FakeHttp()])
        _, cred = _signed_credential()
        env = build_envelope(from_did="a", to_did="did:web:b.example.com", payload=cred)
        result = await manager.dispatch(env)
        assert result.transport == "http"
        assert result.attempts == ["udna", "http"]

    async def test_raises_when_no_transport_can_deliver(self):
        manager = TransportManager([UdnaTransport(node=None), HttpTransport()])
        _, cred = _signed_credential()
        # did:key is not HTTP-routable and UDNA is dormant → nothing can deliver.
        env = build_envelope(from_did="a", to_did="did:key:z6MkABC", payload=cred)
        with pytest.raises(TransportError):
            await manager.dispatch(env)

    async def test_close_propagates_to_transports(self):
        node = FakeUdnaNode()
        manager = TransportManager.default(udna_node=node)
        await manager.close()
        assert node.closed is True
