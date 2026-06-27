"""
Integration tests against the *real* ``sirraya-udna-sdk`` (import: ``udna_sdk``).

These are skipped unless the SDK is installed (``pip install
vouch-protocol[udna]``), so the default test run does not depend on it. When it
is present, they exercise Vouch's UDNA adapter against the genuine SDK API —
``UdnaSDK.create_did`` / ``create_address`` / ``verify_address`` and the
``NoiseHandshake`` + ``SecureMessaging`` crypto — proving the adapter is wired
to real method names, not guessed ones.
"""

from __future__ import annotations

import json

import pytest

udna_sdk = pytest.importorskip("udna_sdk")

from vouch import generate_identity  # noqa: E402
from vouch.transport import (  # noqa: E402
    SirrayaUdnaNode,
    UdnaTransport,
    build_envelope,
    is_did_key,
)
from vouch.transport.udna import FACET_MESSAGING  # noqa: E402


# --------------------------------------------------------------------------- #
# Real SDK: DID + address primitives
# --------------------------------------------------------------------------- #
def test_sdk_create_did_returns_did_key():
    did = UdnaTransport.generate_did_via_sdk()
    assert is_did_key(did)
    assert did.startswith("did:key:z6Mk")


def test_sdk_address_create_and_verify_roundtrip():
    from udna_sdk import UdnaSDK

    sdk = UdnaSDK()
    did = sdk.create_did().did
    addr = sdk.create_address(did, facet_id=FACET_MESSAGING, flags=["messaging", "routing"])
    # The adapter's verify helper wraps the real verify_address.
    assert UdnaTransport.verify_udna_address(addr.address) is True


def test_vouch_did_key_matches_sdk_encoding():
    """Vouch's Multikey did:key must be byte-identical to the SDK's encoding."""
    from cryptography.hazmat.primitives import serialization
    from udna_sdk.udna import DidKeyMethod

    sdk_did, priv = DidKeyMethod.generate()
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    vouch_did = UdnaTransport.generate_did_from_raw(raw_pub)
    assert vouch_did == str(sdk_did)


# --------------------------------------------------------------------------- #
# Real SDK: Noise handshake + secure messaging through the adapter
# --------------------------------------------------------------------------- #
class PeerChannel:
    """
    A delivery channel that plays the *peer* using the real SDK:
    it answers the Noise handshake with ``respond_to_handshake`` and
    acknowledges the encrypted payload.
    """

    def __init__(self):
        from udna_sdk.udna import DidKeyMethod, NoiseHandshake

        self._noise = NoiseHandshake()
        self._peer_did, self._peer_priv = DidKeyMethod.generate()
        self.received_ciphertext = None

    async def reachable(self, address):
        return True

    async def exchange(self, address, frame):
        # Distinguish the handshake frame (JSON with a 'type') from ciphertext.
        try:
            msg = json.loads(frame.decode("utf-8"))
            is_handshake = isinstance(msg, dict) and msg.get("type") == "handshake_init"
        except (ValueError, UnicodeDecodeError):
            is_handshake = False

        if is_handshake:
            _session_id, response = self._noise.respond_to_handshake(
                self._peer_did, self._peer_priv, frame
            )
            return response
        # Encrypted payload: record it and acknowledge with no body.
        self.received_ciphertext = frame
        return b""

    async def close(self):
        pass


async def test_secure_send_runs_real_noise_handshake():
    kp = generate_identity()
    node = SirrayaUdnaNode(
        channel=PeerChannel(),
        local_did=UdnaTransport.generate_did(kp.public_key_jwk),
        local_private_key=_priv_obj(kp.private_key_jwk),
    )
    transport = UdnaTransport(node=node)

    peer_did = UdnaTransport.generate_did_via_sdk()
    env = build_envelope(from_did=kp.did, to_did=peer_did, payload={"hello": "udna"})
    peer = await transport.resolve(peer_did)
    assert peer is not None and peer.verified is True

    # Completes a real initiate→respond→finalize handshake and encrypts the
    # envelope with ChaCha20-Poly1305 — no exception means the real API matched.
    reply = await transport.send(env, peer)
    assert reply == {}  # peer acknowledged without a body
    assert node._channel.received_ciphertext is not None


def test_secure_messaging_encrypt_decrypt_roundtrip():
    from udna_sdk.udna import SecureMessaging

    sm = SecureMessaging()
    key = b"\x01" * 32
    blob = b'{"vouch_envelope":"1.0"}'
    ct = sm.encrypt_message(key, blob)
    assert sm.decrypt_message(key, ct) == blob


def _priv_obj(private_key_jwk: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from jwcrypto.common import base64url_decode

    seed = base64url_decode(json.loads(private_key_jwk)["d"])
    return Ed25519PrivateKey.from_private_bytes(seed)
