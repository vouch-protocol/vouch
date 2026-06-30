"""
Tests for root-identity recovery by Shamir secret sharing (vouch.recovery).

The model: split a root identity's seed into n shares so any t reconstruct it and
fewer reveal nothing. Recovery rebuilds the exact same key (the seed is
deterministic), proven by signing with the recovered key and verifying against
the original public key.
"""

import os

import pytest

from vouch import (
    Verifier,
    combine_shares,
    generate_identity,
    recover_identity,
    split_identity,
    split_secret,
    Signer,
)


# ---------------------------------------------------------------------------
# Byte-level Shamir
# ---------------------------------------------------------------------------


def test_split_and_combine_roundtrip():
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, shares=5)
    assert len(shares) == 5
    # Any 3 of the 5 reconstruct.
    assert combine_shares(shares[:3]) == secret
    assert combine_shares(shares[2:5]) == secret
    assert combine_shares([shares[0], shares[2], shares[4]]) == secret
    # All 5 also reconstruct.
    assert combine_shares(shares) == secret


def test_threshold_minus_one_does_not_reveal_secret():
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, shares=5)
    # Two shares (below threshold) must not yield the secret.
    assert combine_shares(shares[:2]) != secret


def test_two_of_two():
    secret = b"a-32-byte-seed-for-shamir-test!!"
    shares = split_secret(secret, threshold=2, shares=2)
    assert combine_shares(shares) == secret


def test_invalid_parameters():
    with pytest.raises(ValueError):
        split_secret(b"", threshold=2, shares=3)
    with pytest.raises(ValueError):
        split_secret(b"x", threshold=1, shares=3)  # threshold must be >= 2
    with pytest.raises(ValueError):
        split_secret(b"x", threshold=4, shares=3)  # threshold > shares


def test_combine_rejects_inconsistent_shares():
    secret = os.urandom(16)
    shares = split_secret(secret, threshold=2, shares=3)
    with pytest.raises(ValueError):
        combine_shares([shares[0], shares[0]])  # duplicate index
    with pytest.raises(ValueError):
        combine_shares([shares[0], shares[1][:5]])  # inconsistent length


# ---------------------------------------------------------------------------
# Identity recovery
# ---------------------------------------------------------------------------


def test_split_and_recover_identity_signs_identically():
    keys = generate_identity("root.example")
    shares = split_identity(keys, threshold=2, shares=3)
    assert len(shares) == 3

    recovered = recover_identity(shares[:2], did=keys.did)
    assert recovered.did == keys.did
    # The recovered key is the original key: a credential it signs verifies
    # against the ORIGINAL public key.
    signer = Signer(private_key=recovered.private_key_jwk, did=recovered.did)
    cred = signer.sign_credential(action="read", target="t", resource="https://x/y")
    ok, _ = Verifier.verify_credential(cred, public_key=keys.public_key_jwk)
    assert ok
    assert recovered.public_key_jwk == keys.public_key_jwk


def test_recover_from_private_jwk_string():
    keys = generate_identity("root.example")
    shares = split_identity(keys.private_key_jwk, threshold=2, shares=3)
    recovered = recover_identity([shares[0], shares[2]])
    assert recovered.public_key_jwk == keys.public_key_jwk


def test_too_few_shares_does_not_recover_identity():
    keys = generate_identity("root.example")
    shares = split_identity(keys, threshold=3, shares=5)
    # Two shares when three are required: the recovered seed is wrong, so the
    # public key does not match (and may not even be 32 bytes).
    try:
        recovered = recover_identity(shares[:2])
        assert recovered.public_key_jwk != keys.public_key_jwk
    except ValueError:
        pass  # also acceptable: wrong-length seed is rejected
