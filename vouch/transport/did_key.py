"""
``did:key`` helpers for identity-first (UDNA) routing.

Where ``did:web`` anchors trust in a domain, ``did:key`` anchors it in the key
itself: the DID *is* the public key, multibase-encoded. That makes it the
natural addressing primitive for UDNA, which routes to a cryptographic identity
rather than to a location. These helpers are pure functions over the same
Ed25519 + Multikey machinery the rest of Vouch already uses (see
:mod:`vouch.multikey`), so a UDNA address can be derived offline, with no
registry and no network.

Method spec: ``did:key`` for Ed25519 is ``did:key:z6Mk…`` where the suffix is
the ``Multikey`` encoding of the public key (multicodec ``0xed01`` || raw key,
base58btc, ``z`` prefix), identical to the ``publicKeyMultibase`` Vouch
publishes in DID Documents.
"""

from __future__ import annotations

import json

from .. import multikey

DID_KEY_PREFIX = "did:key:"


def is_did_key(did: str) -> bool:
    """True if ``did`` is a ``did:key`` identifier."""
    return did.startswith(DID_KEY_PREFIX)


def did_key_from_ed25519_public(raw_public_key: bytes) -> str:
    """
    Build a ``did:key`` from a 32-byte raw Ed25519 public key.

    >>> did_key_from_ed25519_public(os.urandom(32)).startswith("did:key:z6Mk")
    True
    """
    return DID_KEY_PREFIX + multikey.encode_ed25519_public(raw_public_key)


def did_key_from_public_jwk(public_jwk: str) -> str:
    """
    Build a ``did:key`` from an Ed25519 public JWK (the JSON string form
    produced by :func:`vouch.generate_identity`).

    Raises:
      ValueError: if the JWK is not an Ed25519 OKP key.
    """
    from jwcrypto.common import base64url_decode

    jwk_dict = json.loads(public_jwk)
    if jwk_dict.get("kty") != "OKP" or jwk_dict.get("crv") != "Ed25519":
        raise ValueError("did:key generation requires an Ed25519 OKP public JWK")
    x = jwk_dict.get("x")
    if not x:
        raise ValueError("public JWK is missing the 'x' coordinate")
    return did_key_from_ed25519_public(base64url_decode(x))


def ed25519_public_from_did_key(did: str) -> bytes:
    """
    Recover the raw 32-byte Ed25519 public key from a ``did:key``.

    This is what lets a UDNA peer verify, with no registry lookup, that the
    party it established a Noise channel with actually owns the DID it claims -
    the key is right there in the identifier.

    Raises:
      ValueError: if ``did`` is not an Ed25519 ``did:key``.
    """
    if not is_did_key(did):
        raise ValueError(f"not a did:key identifier: {did}")
    alg, raw = multikey.decode(did[len(DID_KEY_PREFIX) :])
    if alg != "Ed25519":
        raise ValueError(f"unsupported did:key algorithm: {alg}")
    return raw
