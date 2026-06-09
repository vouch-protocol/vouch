"""
Multikey encoding for verification methods.

Per the Controlled Identifiers specification, public keys in DID Documents
are encoded as a `Multikey` with the format:

  publicKeyMultibase = base58btc( multicodec_prefix || raw_public_key_bytes )

The leading `z` character of the multibase output indicates base58btc.

Supported algorithms (Vouch Protocol Specification §13.5):
  Ed25519    multicodec prefix 0xed01 (32-byte key)
  ML-DSA-44   multicodec prefix 0x1207 (1312-byte key, provisional)

This module provides encode/decode helpers and is dependency-free.
"""

from __future__ import annotations

from typing import Tuple


# Multicodec prefixes (varint-encoded as 2 bytes for these values).
ED25519_PUB_PREFIX = bytes([0xED, 0x01])
ED25519_PRIV_PREFIX = bytes([0x80, 0x26])  # ed25519-priv multicodec
MLDSA44_PUB_PREFIX = bytes([0x87, 0x24])  # provisional 0x1207 varint-encoded
MLDSA44_PRIV_PREFIX = bytes([0x88, 0x24])  # provisional

# Reverse lookup
_PREFIX_TO_ALG = {
    ED25519_PUB_PREFIX: ("Ed25519", "public"),
    ED25519_PRIV_PREFIX: ("Ed25519", "private"),
    MLDSA44_PUB_PREFIX: ("ML-DSA-44", "public"),
    MLDSA44_PRIV_PREFIX: ("ML-DSA-44", "private"),
}

# base58btc alphabet (Bitcoin's standard alphabet)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def encode_ed25519_public(raw_key: bytes) -> str:
    """Encode a 32-byte Ed25519 public key as a Multikey string (z-prefixed base58btc)."""
    if len(raw_key) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw_key)}")
    return "z" + _b58encode(ED25519_PUB_PREFIX + raw_key)


def encode_mldsa44_public(raw_key: bytes) -> str:
    """Encode an ML-DSA-44 public key (1312 bytes) as a Multikey string.

    Used in the hybrid post-quantum profile (Specification §13.2). The
    DID Document publishes this alongside an Ed25519 Multikey under a
    parallel `verificationMethod` slot.
    """
    if len(raw_key) != 1312:
        raise ValueError(f"ML-DSA-44 public key must be 1312 bytes, got {len(raw_key)}")
    return "z" + _b58encode(MLDSA44_PUB_PREFIX + raw_key)


def decode(multikey: str) -> Tuple[str, bytes]:
    """
    Decode a Multikey string. Returns (algorithm_name, raw_key_bytes).

    Raises ValueError if the format is unrecognized or the key is malformed.
    """
    if not multikey.startswith("z"):
        raise ValueError("Multikey must use base58btc encoding (z-prefix)")
    decoded = _b58decode(multikey[1:])
    if len(decoded) < 2:
        raise ValueError("Multikey too short")
    prefix = decoded[:2]
    if prefix not in _PREFIX_TO_ALG:
        raise ValueError(f"Unknown multicodec prefix: {prefix.hex()}")
    alg, kind = _PREFIX_TO_ALG[prefix]
    if kind == "private":
        # A verificationMethod must carry a PUBLIC key. Refuse a private-key
        # multicodec prefix so private material is never treated as a key.
        raise ValueError("Multikey carries a private-key prefix; a public key is required")
    raw = decoded[2:]
    expected = 32 if alg == "Ed25519" else 1312
    if len(raw) != expected:
        raise ValueError(f"{alg} public key must be {expected} bytes, got {len(raw)}")
    return alg, raw


def algorithm_of(multikey: str) -> str:
    """Return the algorithm name encoded in `multikey` without exposing key bytes."""
    alg, _ = decode(multikey)
    return alg


# ---- base58btc primitive (vendored to avoid a dependency) ----


def _b58encode(data: bytes) -> str:
    if not data:
        return ""
    n_zero = 0
    for byte in data:
        if byte == 0:
            n_zero += 1
        else:
            break
    num = int.from_bytes(data, "big")
    encoded = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(_B58_ALPHABET[rem])
    encoded.extend(b"1" * n_zero)
    encoded.reverse()
    return encoded.decode("ascii")


def _b58decode(s: str) -> bytes:
    if not s:
        return b""
    n_zero = 0
    for ch in s:
        if ch == "1":
            n_zero += 1
        else:
            break
    num = 0
    for ch in s:
        idx = _B58_INDEX.get(ord(ch))
        if idx is None:
            raise ValueError(f"Invalid base58 character: {ch!r}")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * n_zero + body
