"""
Unit tests for the Verifier class.
"""

import pytest
import json
import time

from vouch import Signer, Verifier, generate_identity
from vouch.verifier import Passport, VerificationError


class TestVerifierStaticVerify:
    """Tests for Verifier.verify() static method."""

    def test_verify_valid_token(self, signer, keypair, sample_payload):
        """verify() returns True for valid token with correct key."""
        token = signer.sign(sample_payload)
        is_valid, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)

        assert is_valid is True
        assert passport is not None
        assert passport.sub == keypair.did
        assert passport.iss == keypair.did

    def test_verify_returns_passport(self, signer, keypair, sample_payload):
        """verify() returns a Passport with correct claims."""
        token = signer.sign(sample_payload)
        is_valid, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)

        assert isinstance(passport, Passport)
        assert passport.payload == sample_payload
        assert passport.jti is not None
        assert passport.iat > 0
        assert passport.exp > passport.iat

    def test_verify_empty_token(self):
        """verify() returns False for empty token."""
        is_valid, passport = Verifier.verify("")
        assert is_valid is False
        assert passport is None

    def test_verify_none_token(self):
        """verify() returns False for None token."""
        is_valid, passport = Verifier.verify(None)
        assert is_valid is False
        assert passport is None

    def test_verify_malformed_token(self, keypair):
        """verify() returns False for malformed token."""
        is_valid, passport = Verifier.verify(
            "not.a.valid.token", public_key_jwk=keypair.public_key_jwk
        )
        assert is_valid is False

    def test_verify_wrong_public_key(self, signer, sample_payload):
        """verify() returns False when using wrong public key."""
        token = signer.sign(sample_payload)

        # Use a different keypair
        other_keys = generate_identity(domain="other-agent.com")

        is_valid, passport = Verifier.verify(token, public_key_jwk=other_keys.public_key_jwk)
        assert is_valid is False

    def test_verify_expired_token(self, expired_signer, keypair, sample_payload):
        """verify() returns False for expired token."""
        token = expired_signer.sign(sample_payload)
        is_valid, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)

        assert is_valid is False

    def test_verify_without_public_key(self, signer, sample_payload):
        """verify() without public key only validates structure."""
        token = signer.sign(sample_payload)
        is_valid, passport = Verifier.verify(token)  # No public key

        # Should return True (structure OK) but signature not verified
        assert is_valid is True
        assert passport is not None


class TestVerifierInstance:
    """Tests for Verifier instance methods."""

    def test_verifier_with_trusted_roots(self, keypair, sample_payload):
        """Verifier instance uses trusted roots for verification."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)

        verifier = Verifier(
            trusted_roots={keypair.did: keypair.public_key_jwk}, allow_did_resolution=False
        )

        token = signer.sign(sample_payload)
        is_valid, passport = verifier.check_vouch(token)

        assert is_valid is True
        assert passport.sub == keypair.did

    def test_verifier_unknown_did(self, sample_payload):
        """check_vouch() returns False for unknown DID."""
        keys = generate_identity(domain="unknown-agent.com")
        signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

        verifier = Verifier(
            trusted_roots={},  # No trusted roots
            allow_did_resolution=False,
        )

        token = signer.sign(sample_payload)
        is_valid, passport = verifier.check_vouch(token)

        assert is_valid is False

    def test_add_trusted_root(self, keypair, sample_payload):
        """add_trusted_root() allows adding keys dynamically."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        verifier = Verifier(trusted_roots={}, allow_did_resolution=False)

        token = signer.sign(sample_payload)

        # Should fail before adding
        is_valid, _ = verifier.check_vouch(token)
        assert is_valid is False

        # Add trusted root
        verifier.add_trusted_root(keypair.did, keypair.public_key_jwk)

        # Should succeed after adding
        is_valid, passport = verifier.check_vouch(token)
        assert is_valid is True

    def test_clock_skew_tolerance(self, keypair, sample_payload):
        """Verifier respects clock_skew_seconds setting."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)

        # Small clock skew
        verifier = Verifier(
            trusted_roots={keypair.did: keypair.public_key_jwk}, clock_skew_seconds=5
        )

        token = signer.sign(sample_payload)
        is_valid, _ = verifier.check_vouch(token)
        assert is_valid is True


class TestPassportDataclass:
    """Tests for the Passport dataclass."""

    def test_passport_fields(self, signer, keypair, sample_payload):
        """Passport contains all expected fields."""
        token = signer.sign(sample_payload)
        _, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)

        assert hasattr(passport, "sub")
        assert hasattr(passport, "iss")
        assert hasattr(passport, "iat")
        assert hasattr(passport, "exp")
        assert hasattr(passport, "jti")
        assert hasattr(passport, "payload")
        assert hasattr(passport, "raw_claims")

    def test_passport_raw_claims(self, signer, keypair, sample_payload):
        """Passport.raw_claims contains full JWT claims."""
        token = signer.sign(sample_payload)
        _, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)

        assert "vouch" in passport.raw_claims
        assert "jti" in passport.raw_claims
        assert "iss" in passport.raw_claims


class TestEdgeCases:
    """Edge case tests for Verifier."""

    def test_verify_token_with_unicode_payload(self, signer, keypair):
        """verify() handles unicode in payload."""
        payload = {"message": "Hello 世界 🌍", "emoji": "👨‍💻"}
        token = signer.sign(payload)

        is_valid, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)
        assert is_valid is True
        assert passport.payload["message"] == "Hello 世界 🌍"

    def test_verify_token_with_large_payload(self, signer, keypair):
        """verify() handles large payloads."""
        payload = {"data": "x" * 10000}  # 10KB payload
        token = signer.sign(payload)

        is_valid, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)
        assert is_valid is True

    def test_verify_token_with_special_characters(self, signer, keypair):
        """verify() handles special characters in payload."""
        payload = {
            "sql": "SELECT * FROM users WHERE name = 'O''Brien'",
            "path": "/home/user/../../../etc/passwd",
            "html": "<script>alert('xss')</script>",
        }
        token = signer.sign(payload)

        is_valid, passport = Verifier.verify(token, public_key_jwk=keypair.public_key_jwk)
        assert is_valid is True
        assert passport.payload == payload
