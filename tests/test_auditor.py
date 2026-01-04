"""
Unit tests for the Auditor class.
"""

import pytest
import json

from vouch import Auditor, Verifier
from jwcrypto import jwk


class TestAuditorInitialization:
    """Tests for Auditor initialization."""

    def test_init_with_valid_key(self, auditor_keypair):
        """Auditor initializes with valid Ed25519 key."""
        private_key, _ = auditor_keypair
        auditor = Auditor(private_key_json=private_key)
        assert auditor.get_issuer_did() == "did:web:vouch-authority"

    def test_init_with_custom_issuer_did(self, auditor_keypair):
        """Auditor uses custom issuer DID."""
        private_key, _ = auditor_keypair
        auditor = Auditor(private_key_json=private_key, issuer_did="did:web:custom-authority.com")
        assert auditor.get_issuer_did() == "did:web:custom-authority.com"

    def test_init_missing_key(self):
        """Auditor raises ValueError for missing key."""
        with pytest.raises(ValueError, match="private key"):
            Auditor(private_key_json="")

    def test_init_invalid_key(self):
        """Auditor raises ValueError for invalid key."""
        with pytest.raises(ValueError, match="Invalid"):
            Auditor(private_key_json="not-valid-json")


class TestAuditorIssueVouch:
    """Tests for Auditor.issue_vouch() method."""

    def test_issue_vouch_returns_certificate(self, auditor):
        """issue_vouch() returns dict with certificate."""
        result = auditor.issue_vouch(
            {
                "did": "did:web:test-agent.com",
                "integrity_hash": "sha256:abc123",
                "reputation_score": 75,
            }
        )

        assert "certificate" in result
        assert isinstance(result["certificate"], str)

    def test_issue_vouch_valid_jws(self, auditor):
        """issue_vouch() produces valid JWS token."""
        result = auditor.issue_vouch({"did": "did:web:test-agent.com"})

        parts = result["certificate"].split(".")
        assert len(parts) == 3  # header.payload.signature

    def test_issue_vouch_missing_did(self, auditor):
        """issue_vouch() raises ValueError for missing DID."""
        with pytest.raises(ValueError, match="did"):
            auditor.issue_vouch({})

    def test_issue_vouch_default_reputation(self, auditor, auditor_keypair):
        """issue_vouch() uses default reputation score when not provided."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch({"did": "did:web:test-agent.com"})

        # Verify to check the claims
        is_valid, passport = Verifier.verify(result["certificate"], public_key_jwk=public_key)

        assert is_valid
        # Default reputation is 50
        assert passport.raw_claims["vc"]["reputation_score"] == 50

    def test_issue_vouch_clamps_reputation(self, auditor, auditor_keypair):
        """issue_vouch() clamps reputation to 0-100 range."""
        _, public_key = auditor_keypair

        # Test over 100
        result = auditor.issue_vouch({"did": "did:web:test.com", "reputation_score": 150})
        _, passport = Verifier.verify(result["certificate"], public_key_jwk=public_key)
        assert passport.raw_claims["vc"]["reputation_score"] == 100

        # Test under 0
        result = auditor.issue_vouch({"did": "did:web:test.com", "reputation_score": -50})
        _, passport = Verifier.verify(result["certificate"], public_key_jwk=public_key)
        assert passport.raw_claims["vc"]["reputation_score"] == 0

    def test_issue_vouch_custom_expiry(self, auditor, auditor_keypair):
        """issue_vouch() respects custom expiry."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch(
            {"did": "did:web:test.com"},
            expiry_seconds=3600,  # 1 hour
        )

        _, passport = Verifier.verify(result["certificate"], public_key_jwk=public_key)

        # exp should be iat + 3600
        assert passport.exp == passport.iat + 3600


class TestAuditorVerification:
    """Tests for verifying Auditor certificates."""

    def test_certificate_verifiable(self, auditor, auditor_keypair):
        """Issued certificate can be verified with public key."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch(
            {
                "did": "did:web:test-agent.com",
                "integrity_hash": "sha256:abc123",
                "reputation_score": 85,
            }
        )

        is_valid, passport = Verifier.verify(result["certificate"], public_key_jwk=public_key)

        assert is_valid is True
        assert passport.sub == "did:web:test-agent.com"

    def test_certificate_has_vc_claims(self, auditor, auditor_keypair):
        """Certificate includes Verifiable Credential claims."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch(
            {
                "did": "did:web:test-agent.com",
                "integrity_hash": "sha256:abc123",
                "reputation_score": 85,
            }
        )

        _, passport = Verifier.verify(result["certificate"], public_key_jwk=public_key)

        vc = passport.raw_claims.get("vc", {})
        assert "type" in vc
        assert "VouchIdentityCredential" in vc["type"]
        assert vc["reputation_score"] == 85
        assert vc["integrity_hash"] == "sha256:abc123"


class TestAuditorPublicKey:
    """Tests for Auditor.get_public_key_jwk()."""

    def test_get_public_key(self, auditor):
        """get_public_key_jwk() returns valid public key."""
        pub_key = auditor.get_public_key_jwk()
        parsed = json.loads(pub_key)

        assert parsed["kty"] == "OKP"
        assert "d" not in parsed  # No private component
