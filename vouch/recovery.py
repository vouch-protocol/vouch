"""
Root-identity recovery by Shamir secret sharing (the OSS recovery path).

A root identity is the durable anchor that issues per-device grants (see
:mod:`vouch.fleet`). If every device is lost, the root must still be
recoverable. This module splits the root's Ed25519 seed into ``n`` shares so
that any ``t`` of them reconstruct it, and none fewer reveal anything. Hand the
shares to guardians, a safe-deposit box, or separate locations; gather ``t`` only
during a deliberate recovery.

This is the recovery / escrow primitive. It is distinct from threshold signing
(FROST), where the key is never reassembled: here the seed IS reconstructed at
recovery time, so do it on a trusted device and re-seal afterwards. Use it for
cold recovery of a root, not for hot signing.

  shares = split_identity(keypair, threshold=2, shares=3)   # give one each to 3 guardians
  recovered = recover_identity(shares[:2])                   # any 2 rebuild the identity

The arithmetic is textbook Shamir over GF(2^8) (the AES field). Shares carry no
integrity tag, so a corrupted share yields a wrong secret rather than an error;
pair with your own checksum if you need to detect a bad share.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.keys import KeyPair

# ---------------------------------------------------------------------------
# GF(2^8) arithmetic (AES field, reducing polynomial 0x11b)
# ---------------------------------------------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    # 3 (not 2) is a primitive element of GF(2^8) under 0x11b, so powers of 3
    # cycle through all 255 non-zero elements. Multiply by 3 = (x*2) XOR x.
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 in GF(2^8)")
    return _EXP[255 - _LOG[a]]


def _eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate a polynomial (coeffs low-order first) at x in GF(2^8)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_mul(result, x) ^ coeff
    return result


def _interpolate_at_zero(points: List[tuple]) -> int:
    """Lagrange-interpolate the points and return the value at x = 0."""
    result = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _yj) in enumerate(points):
            if i == j:
                continue
            num = _gf_mul(num, xj)  # (0 - xj) == xj in GF(2^8)
            den = _gf_mul(den, xi ^ xj)  # (xi - xj) == xi ^ xj
        result ^= _gf_mul(yi, _gf_mul(num, _gf_inv(den)))
    return result


# ---------------------------------------------------------------------------
# Byte-level split / combine
# ---------------------------------------------------------------------------


def split_secret(secret: bytes, *, threshold: int, shares: int) -> List[bytes]:
    """Split `secret` into `shares` pieces; any `threshold` reconstruct it.

    Each returned share is ``bytes([index]) + share_body`` where index is in
    1..shares. Fewer than `threshold` shares reveal nothing about the secret.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ValueError("secret must be non-empty bytes")
    if not (2 <= threshold <= shares <= 255):
        raise ValueError("require 2 <= threshold <= shares <= 255")

    out = [bytearray([x]) for x in range(1, shares + 1)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i, x in enumerate(range(1, shares + 1)):
            out[i].append(_eval_poly(coeffs, x))
    return [bytes(s) for s in out]


def combine_shares(shares: List[bytes]) -> bytes:
    """Reconstruct a secret from `threshold` (or more) shares.

    Shares are the byte strings returned by :func:`split_secret`. Supplying
    fewer than the original threshold returns a wrong value, not an error.
    """
    if not shares or len(shares) < 2:
        raise ValueError("need at least 2 shares")
    bodies = []
    xs = []
    for s in shares:
        if len(s) < 2:
            raise ValueError("malformed share")
        xs.append(s[0])
        bodies.append(s[1:])
    if len(set(xs)) != len(xs):
        raise ValueError("shares must have distinct indices")
    length = len(bodies[0])
    if any(len(b) != length for b in bodies):
        raise ValueError("shares have inconsistent length")

    secret = bytearray()
    for j in range(length):
        points = [(xs[k], bodies[k][j]) for k in range(len(shares))]
        secret.append(_interpolate_at_zero(points))
    return bytes(secret)


# ---------------------------------------------------------------------------
# Vouch identity recovery
# ---------------------------------------------------------------------------


def _seed_from_private_jwk(private_key_jwk: str) -> bytes:
    from jwcrypto.common import base64url_decode

    data = json.loads(private_key_jwk)
    if data.get("kty") != "OKP" or data.get("crv") != "Ed25519" or not data.get("d"):
        raise ValueError("expected an Ed25519 private JWK with a 'd' seed")
    return base64url_decode(data["d"])


def split_identity(
    keypair: Any,
    *,
    threshold: int,
    shares: int,
) -> List[str]:
    """Split a root identity's Ed25519 seed into base64 recovery shares.

    Accepts a :class:`~vouch.keys.KeyPair`, an Agent (anything exposing
    ``private_key_jwk``), or a private JWK string. Returns `shares` base64
    strings; any `threshold` of them recover the identity via
    :func:`recover_identity`. Distribute them to separate guardians or locations.
    """
    if isinstance(keypair, str):
        private_jwk = keypair
    else:
        private_jwk = getattr(keypair, "private_key_jwk", None)
        if private_jwk is None:
            raise TypeError("split_identity needs a KeyPair, Agent, or private JWK string")
    seed = _seed_from_private_jwk(private_jwk)
    return [
        base64.b64encode(s).decode("ascii")
        for s in split_secret(seed, threshold=threshold, shares=shares)
    ]


def recover_identity(shares: List[str], *, did: Optional[str] = None) -> KeyPair:
    """Recover a root identity from `threshold` base64 recovery shares.

    Returns a :class:`~vouch.keys.KeyPair` with the original private and public
    keys (the seed is deterministic, so the rebuilt key is identical). Pass
    ``did`` to set it on the returned KeyPair.
    """
    from jwcrypto import jwk as jwk_mod

    raw = [base64.b64decode(s) for s in shares]
    seed = combine_shares(raw)
    if len(seed) != 32:
        raise ValueError("recovered seed is not 32 bytes; wrong or too few shares")

    # Rebuild the JWK through jwcrypto (as generate_identity does) so the
    # recovered key's serialization matches a freshly minted one byte for byte.
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    key = jwk_mod.JWK.from_pyca(priv)
    return KeyPair(
        private_key_jwk=key.export_private(),
        public_key_jwk=key.export_public(),
        did=did,
    )


__all__ = [
    "split_secret",
    "combine_shares",
    "split_identity",
    "recover_identity",
]
