"""Tests for Multikey encoding (Controlled Identifiers)."""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from vouch import multikey


def _fresh_ed25519_public_bytes() -> bytes:
    priv = Ed25519PrivateKey.generate()
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_ed25519_round_trip():
    raw = _fresh_ed25519_public_bytes()
    encoded = multikey.encode_ed25519_public(raw)
    assert encoded.startswith("z6Mk")  # standard Ed25519 multikey prefix
    alg, decoded = multikey.decode(encoded)
    assert alg == "Ed25519"
    assert decoded == raw


def test_ed25519_known_vector():
    # 32 zero bytes encodes deterministically
    raw = bytes(32)
    encoded = multikey.encode_ed25519_public(raw)
    alg, decoded = multikey.decode(encoded)
    assert alg == "Ed25519"
    assert decoded == raw


def test_invalid_length_rejected():
    with pytest.raises(ValueError):
        multikey.encode_ed25519_public(b"too short")


def test_unknown_prefix_rejected():
    # Forge a multibase string that has the right format but unknown multicodec
    bogus = "z" + multikey._b58encode(b"\xfa\xfb" + bytes(32))
    with pytest.raises(ValueError, match="Unknown multicodec prefix"):
        multikey.decode(bogus)


def test_non_base58btc_rejected():
    with pytest.raises(ValueError, match="base58btc"):
        multikey.decode("Q-not-a-multikey")


def test_random_round_trip_many():
    for _ in range(20):
        raw = os.urandom(32)
        encoded = multikey.encode_ed25519_public(raw)
        alg, decoded = multikey.decode(encoded)
        assert alg == "Ed25519"
        assert decoded == raw
