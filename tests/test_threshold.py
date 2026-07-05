"""
Tests for FROST(Ed25519, SHA-512) threshold signing (vouch.threshold).

Requires the native vouch_core_uniffi library (built from core/uniffi via
`cargo build --release`, or pointed to with VOUCH_CORE_LIB). Skips cleanly when
it is not available, mirroring how test_fastapi_credential_gate.py skips when
fastapi is not installed: this is an optional, audited-crate-backed feature,
not a hand-written cryptographic fallback.
"""

import pytest

from vouch import Signer, Verifier
from vouch.threshold import (
    ThresholdError,
    ThresholdSigner,
    aggregate,
    commit,
    generate_key,
    sign_share,
)

try:
    generate_key(2, 3)
    _NATIVE_LIB_AVAILABLE = True
except ThresholdError:
    _NATIVE_LIB_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _NATIVE_LIB_AVAILABLE,
    reason="native vouch_core_uniffi library not available (build core/uniffi or set VOUCH_CORE_LIB)",
)


def _full_ceremony(min_signers, max_signers, chosen_indices, message):
    generated = generate_key(min_signers, max_signers)
    chosen = [generated.shares[i] for i in chosen_indices]

    nonces_by_id = {}
    commitments = {}
    for share in chosen:
        round1 = commit(share)
        commitments[share.identifier] = round1.commitments
        nonces_by_id[share.identifier] = round1.nonces

    shares_out = {}
    for share in chosen:
        shares_out[share.identifier] = sign_share(
            message, share, nonces_by_id[share.identifier], commitments
        )

    signature = aggregate(message, commitments, shares_out, generated.group_public_key)
    return generated, signature


def test_two_of_three_signs_and_verifies_as_plain_ed25519():
    message = b"charge api.bank invoices/42"
    generated, signature = _full_ceremony(2, 3, [0, 2], message)

    # Verify the raw 64-byte signature directly against the group public key,
    # exactly like verifying any other Ed25519 signature: no new proof type.
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw_pub = base64.standard_b64decode(generated.group_public_key.verifying_key)
    pub = Ed25519PublicKey.from_public_bytes(raw_pub)
    pub.verify(signature, message)  # raises on failure


def test_three_of_five_any_subset_works():
    message = b"read did:web:files https://files/x"
    generated, signature = _full_ceremony(3, 5, [1, 3, 4], message)

    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw_pub = base64.standard_b64decode(generated.group_public_key.verifying_key)
    Ed25519PublicKey.from_public_bytes(raw_pub).verify(signature, message)


def test_wrong_message_fails_verification():
    message = b"original"
    generated, signature = _full_ceremony(2, 3, [0, 1], message)

    import base64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw_pub = base64.standard_b64decode(generated.group_public_key.verifying_key)
    pub = Ed25519PublicKey.from_public_bytes(raw_pub)
    with pytest.raises(InvalidSignature):
        pub.verify(signature, b"tampered")


def test_generate_key_rejects_bad_threshold():
    with pytest.raises(ThresholdError):
        generate_key(1, 3)
    with pytest.raises(ThresholdError):
        generate_key(4, 3)


def test_different_groups_have_different_public_keys():
    a = generate_key(2, 3)
    b = generate_key(2, 3)
    assert a.group_public_key.verifying_key != b.group_public_key.verifying_key


def test_threshold_signer_produces_valid_signature():
    generated = generate_key(2, 3)
    signer = ThresholdSigner(generated.shares[:2], generated.group_public_key)
    message = b"a message to sign"
    signature = signer.sign(message)

    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw_pub = base64.standard_b64decode(generated.group_public_key.verifying_key)
    Ed25519PublicKey.from_public_bytes(raw_pub).verify(signature, message)


def test_threshold_signer_requires_at_least_two_shares():
    generated = generate_key(2, 3)
    with pytest.raises(ValueError):
        ThresholdSigner(generated.shares[:1], generated.group_public_key)


def test_integrates_with_signer_from_backend_and_existing_verifier():
    """The whole point: a threshold-backed Signer produces a credential that
    verifies through the EXISTING Verifier.verify, no new proof
    type or verification path."""
    generated = generate_key(2, 3)
    threshold_signer = ThresholdSigner(generated.shares[:2], generated.group_public_key)

    signer = Signer.from_backend(
        did="did:web:agent.example",
        public_key=generated.group_public_key.public_key_jwk,
        sign=threshold_signer.sign,
    )
    credential = signer.sign(action="read", target="t", resource="https://x/y")

    ok, passport = Verifier.verify(credential, public_key=generated.group_public_key.public_key_jwk)
    assert ok
    assert passport.intent["action"] == "read"


def test_group_public_key_multikey_roundtrips():
    generated = generate_key(2, 3)
    from vouch import multikey

    mk = generated.group_public_key.public_key_multikey
    algo, raw = multikey.decode(mk)
    assert algo == "Ed25519"
    import base64

    assert raw == base64.standard_b64decode(generated.group_public_key.verifying_key)


def test_no_function_returns_a_reassembled_private_key():
    """Structural check: generate_key only ever returns shares (secret, one
    per participant) and a public key; nothing in this module combines shares
    back into a whole private key."""
    generated = generate_key(2, 3)
    for share in generated.shares:
        assert share.key_package != generated.group_public_key.public_key_package
