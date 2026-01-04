"""
Unit tests for the Signer class.
"""

import pytest
import json
import time

from vouch import Signer, generate_identity


class TestSignerInitialization:
    """Tests for Signer initialization."""

    def test_init_with_valid_keys(self, keypair):
        """Signer initializes successfully with valid keys."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        assert signer.get_did() == keypair.did

    def test_init_missing_private_key(self, keypair):
        """Signer raises ValueError when private_key is missing."""
        with pytest.raises(ValueError, match="private_key"):
            Signer(private_key="", did=keypair.did)

    def test_init_missing_did(self, keypair):
        """Signer raises ValueError when DID is missing."""
        with pytest.raises(ValueError, match="did"):
            Signer(private_key=keypair.private_key_jwk, did="")

    def test_init_invalid_key_format(self, keypair):
        """Signer raises ValueError for invalid key format."""
        with pytest.raises(ValueError, match="Invalid JWK"):
            Signer(private_key="not-valid-json", did=keypair.did)

    def test_init_wrong_key_type(self, keypair):
        """Signer raises ValueError for non-Ed25519 key."""
        # Create an RSA key instead of Ed25519
        from jwcrypto import jwk

        rsa_key = jwk.JWK.generate(kty="RSA", size=2048)

        with pytest.raises(ValueError, match="Ed25519"):
            Signer(private_key=rsa_key.export_private(), did=keypair.did)


class TestSignerSigning:
    """Tests for Signer.sign() method."""

    def test_sign_returns_string(self, signer, sample_payload):
        """sign() returns a non-empty string token."""
        token = signer.sign(sample_payload)
        assert isinstance(token, str)
        assert len(token) > 100  # JWS tokens are typically 300+ chars

    def test_sign_produces_valid_jws(self, signer, sample_payload):
        """sign() produces a valid JWS compact serialization."""
        token = signer.sign(sample_payload)
        parts = token.split(".")
        assert len(parts) == 3  # header.payload.signature

    def test_sign_unique_tokens(self, signer, sample_payload):
        """Each call to sign() produces a unique token (unique JTI)."""
        token1 = signer.sign(sample_payload)
        token2 = signer.sign(sample_payload)
        assert token1 != token2

    def test_sign_with_empty_payload(self, signer):
        """sign() works with empty payload."""
        token = signer.sign({})
        assert isinstance(token, str)

    def test_sign_with_nested_payload(self, signer):
        """sign() handles nested dictionaries."""
        nested_payload = {
            "action": "transfer",
            "details": {
                "amount": 100,
                "currency": "USD",
                "recipient": {"name": "Bob", "account": "123"},
            },
        }
        token = signer.sign(nested_payload)
        assert isinstance(token, str)

    def test_sign_custom_expiry(self, keypair, sample_payload):
        """sign() respects custom expiry_seconds parameter."""
        signer = Signer(
            private_key=keypair.private_key_jwk, did=keypair.did, default_expiry_seconds=600
        )
        # Override with 10 seconds
        token = signer.sign(sample_payload, expiry_seconds=10)

        # Decode and check exp claim
        import base64

        parts = token.split(".")
        # Add padding for base64
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        expected_exp = payload["iat"] + 10
        assert payload["exp"] == expected_exp


class TestSignerPublicKey:
    """Tests for Signer.get_public_key_jwk() method."""

    def test_get_public_key_returns_json(self, signer):
        """get_public_key_jwk() returns valid JSON."""
        pub_key = signer.get_public_key_jwk()
        parsed = json.loads(pub_key)
        assert parsed["kty"] == "OKP"
        assert parsed["crv"] == "Ed25519"

    def test_public_key_has_no_private_component(self, signer):
        """get_public_key_jwk() does not include private key component."""
        pub_key = signer.get_public_key_jwk()
        parsed = json.loads(pub_key)
        assert "d" not in parsed  # 'd' is the private key component


class TestKeyGeneration:
    """Tests for generate_identity() function."""

    def test_generate_identity_with_domain(self):
        """generate_identity() creates valid keypair with DID."""
        keys = generate_identity(domain="example.com")
        assert keys.did == "did:web:example.com"
        assert keys.private_key_jwk is not None
        assert keys.public_key_jwk is not None

    def test_generate_identity_without_domain(self):
        """generate_identity() works without domain (no DID)."""
        keys = generate_identity()
        assert keys.did is None
        assert keys.private_key_jwk is not None

    def test_generate_identity_unique_keys(self):
        """Each call generates unique keys."""
        keys1 = generate_identity(domain="test.com")
        keys2 = generate_identity(domain="test.com")
        assert keys1.private_key_jwk != keys2.private_key_jwk
