"""Smoke tests for the vouch-safetensors package.

A minimal valid safetensors file is built in-test (8-byte little-endian header
length, a JSON header with one tensor, then the tensor data buffer), so the test
has no torch/numpy dependency.
"""

import json
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto.common import base64url_decode

from vouch import Signer, generate_identity


def _pub(kp):
    return Ed25519PublicKey.from_public_bytes(base64url_decode(json.loads(kp.public_key_jwk)["x"]))


def _make_safetensors(path, data: bytes = b"\x00\x00\x00\x00"):
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, len(data)]}}
    hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hb)))
        f.write(hb)
        f.write(data)


def test_package_exports():
    import vouch_safetensors

    assert vouch_safetensors.sign_safetensors is not None
    assert vouch_safetensors.verify_safetensors is not None


def test_sign_and_verify(tmp_path):
    from vouch_safetensors import sign_safetensors, verify_safetensors, read_embedded_credential

    model = tmp_path / "model.safetensors"
    _make_safetensors(str(model))

    kp = generate_identity()
    signer = Signer(private_key=kp.private_key_jwk, did="did:web:ml.acme.com")

    cred = sign_safetensors(signer, str(model), name="m")
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    # credential is embedded and readable back
    assert read_embedded_credential(str(model)) is not None

    ok, _ = verify_safetensors(str(model), public_key=_pub(kp))
    assert ok is True


def test_tampered_weights_fail(tmp_path):
    from vouch_safetensors import sign_safetensors, verify_safetensors

    model = tmp_path / "model.safetensors"
    _make_safetensors(str(model), data=b"\x01\x02\x03\x04")

    kp = generate_identity()
    signer = Signer(private_key=kp.private_key_jwk, did="did:web:ml.acme.com")
    sign_safetensors(signer, str(model))

    # Rewrite with different tensor bytes (keep it a valid file).
    _make_safetensors(str(model), data=b"\x09\x09\x09\x09")

    ok, _ = verify_safetensors(str(model), public_key=_pub(kp))
    assert ok is False


def test_unsigned_fails_closed(tmp_path):
    from vouch_safetensors import verify_safetensors

    model = tmp_path / "plain.safetensors"
    _make_safetensors(str(model))
    ok, passport = verify_safetensors(str(model), public_key=None)
    assert ok is False
    assert passport is None
