"""
Tests for the identity-first rendezvous resolver.

These exercise the announce, resolve, verify, and deliver contract end to end
with no network and no SDK: an agent publishes a signed route record under its
DID, a sender resolves the DID to the current endpoint, verifies it, and
delivers a sealed Vouch envelope whose proof survives the trip.
"""

from __future__ import annotations

import json

import pytest

from vouch import Signer, generate_identity
from vouch.transport import (
    RendezvousChannel,
    RendezvousRegistry,
    RouteRecord,
    build_envelope,
    build_route_record,
    route_fingerprint,
    udna_address,
)
from vouch.transport.did_key import did_key_from_public_jwk
from vouch.transport.rendezvous import _format_iso8601, _now
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.common import base64url_decode


def _identity():
    kp = generate_identity()
    did = did_key_from_public_jwk(kp.public_key_jwk)
    seed = base64url_decode(json.loads(kp.private_key_jwk)["d"])
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return kp, did, priv


# --------------------------------------------------------------------------- #
# Route record: sign, verify, tamper, expiry
# --------------------------------------------------------------------------- #
class TestRouteRecord:
    def test_sign_and_verify_roundtrip(self):
        _, did, priv = _identity()
        rec = build_route_record(did=did, endpoint="inproc://a", private_key=priv)
        assert rec.signature.startswith("z")
        assert rec.verify() is True

    def test_tampered_endpoint_fails(self):
        _, did, priv = _identity()
        rec = build_route_record(did=did, endpoint="inproc://a", private_key=priv)
        rec.endpoint = "inproc://attacker"
        assert rec.verify() is False

    def test_wrong_key_fails(self):
        _, did, _ = _identity()
        other = Ed25519PrivateKey.generate()
        rec = build_route_record(did=did, endpoint="inproc://a", private_key=other)
        # Signed by a key that does not match the DID.
        assert rec.verify() is False

    def test_expired_record_fails(self):
        _, did, priv = _identity()
        rec = build_route_record(did=did, endpoint="inproc://a", private_key=priv, ttl_seconds=1)
        rec.expires = _format_iso8601(_now() - timedelta(seconds=5))
        # expires is part of the signed body, so this also breaks the signature,
        # but is_expired alone must already reject it.
        assert rec.is_expired() is True

    def test_wire_roundtrip(self):
        _, did, priv = _identity()
        rec = build_route_record(did=did, endpoint="inproc://a", private_key=priv)
        restored = RouteRecord.from_wire(rec.to_wire())
        assert restored.verify() is True
        assert restored.endpoint == "inproc://a"


# --------------------------------------------------------------------------- #
# Fingerprint
# --------------------------------------------------------------------------- #
def test_fingerprint_is_stable_and_did_keyed():
    _, did, _ = _identity()
    fp = route_fingerprint(did)
    assert fp == route_fingerprint(did)
    assert len(fp) == 64  # sha256 hex
    assert did not in fp  # the location-independent key does not leak the DID


# --------------------------------------------------------------------------- #
# Registry: announce / resolve
# --------------------------------------------------------------------------- #
class TestRegistry:
    def test_announce_then_resolve(self):
        _, did, priv = _identity()
        reg = RendezvousRegistry()
        reg.announce(build_route_record(did=did, endpoint="inproc://inbox-1", private_key=priv))
        assert reg.resolve(did) == "inproc://inbox-1"

    def test_resolve_unknown_returns_none(self):
        _, did, _ = _identity()
        assert RendezvousRegistry().resolve(did) is None

    def test_announce_rejects_unverified_record(self):
        _, did, _ = _identity()
        bad = RouteRecord(did=did, endpoint="inproc://x", signature="zdeadbeef")
        with pytest.raises(ValueError):
            RendezvousRegistry().announce(bad)

    def test_reannounce_updates_endpoint(self):
        _, did, priv = _identity()
        reg = RendezvousRegistry()
        reg.announce(build_route_record(did=did, endpoint="inproc://old", private_key=priv))
        reg.announce(build_route_record(did=did, endpoint="inproc://new", private_key=priv))
        assert reg.resolve(did) == "inproc://new"


# --------------------------------------------------------------------------- #
# Channel: resolve a DID and deliver, no DNS
# --------------------------------------------------------------------------- #
class TestRendezvousChannel:
    async def test_resolve_and_deliver_preserves_payload(self):
        kp, did, priv = _identity()
        reg = RendezvousRegistry()
        channel = RendezvousChannel(reg)

        # The receiving agent registers an inbox and announces its route.
        received = {}

        async def inbox(frame: bytes) -> bytes:
            received["frame"] = frame
            return json.dumps({"status": "ok"}).encode("utf-8")

        channel.register_inbox("inproc://inbox-1", inbox)
        reg.announce(build_route_record(did=did, endpoint="inproc://inbox-1", private_key=priv))

        # The sender knows only the DID. Resolve and deliver a sealed envelope.
        addr = udna_address(did)
        assert await channel.reachable(addr) is True

        signer = Signer(private_key=kp.private_key_jwk, did="did:web:sender.example.com")
        cred = signer.sign(intent={"action": "ping", "target": "t", "resource": "https://x/t"})
        env = build_envelope(from_did="did:web:sender.example.com", to_did=did, payload=cred)
        reply = await channel.exchange(addr, json.dumps(env.to_wire()).encode("utf-8"))

        assert json.loads(reply) == {"status": "ok"}
        delivered = json.loads(received["frame"])
        assert delivered["payload"]["proof"] == cred["proof"]

    async def test_unreachable_when_not_announced(self):
        _, did, _ = _identity()
        channel = RendezvousChannel(RendezvousRegistry())
        assert await channel.reachable(udna_address(did)) is False
        with pytest.raises(KeyError):
            await channel.exchange(udna_address(did), b"{}")
