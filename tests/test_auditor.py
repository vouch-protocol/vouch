"""
Unit tests for the Auditor class.

The Auditor issues Vouch Credentials (eddsa-jcs-2022 Data Integrity) that bind
an agent's identity to a reputation score and an integrity hash. The agent it
certifies is carried in intent.target; the reputation lands in
credentialSubject.reputationScore.
"""

import base64
import json
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vouch import Auditor, Verifier


def _ed_pub(public_key_jwk: str) -> Ed25519PublicKey:
    """Ed25519PublicKey from a public JWK JSON string."""
    x = json.loads(public_key_jwk)["x"]
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


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
        """issue_vouch() returns a dict holding a Verifiable Credential."""
        result = auditor.issue_vouch(
            {
                "did": "did:web:test-agent.com",
                "integrity_hash": "sha256:abc123",
                "reputation_score": 75,
            }
        )

        assert "certificate" in result
        assert isinstance(result["certificate"], dict)

    def test_issue_vouch_is_data_integrity_vc(self, auditor):
        """issue_vouch() produces a VC with an eddsa-jcs-2022 proof."""
        result = auditor.issue_vouch({"did": "did:web:test-agent.com"})

        cred = result["certificate"]
        assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"
        assert cred["credentialSubject"]["intent"]["target"] == "did:web:test-agent.com"

    def test_issue_vouch_missing_did(self, auditor):
        """issue_vouch() raises ValueError for missing DID."""
        with pytest.raises(ValueError, match="did"):
            auditor.issue_vouch({})

    def test_issue_vouch_default_reputation(self, auditor, auditor_keypair):
        """issue_vouch() uses default reputation score when not provided."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch({"did": "did:web:test-agent.com"})

        is_valid, passport = Verifier.verify(result["certificate"], public_key=_ed_pub(public_key))

        assert is_valid
        assert passport.reputation_score == 50  # Default

    def test_issue_vouch_clamps_reputation(self, auditor, auditor_keypair):
        """issue_vouch() clamps reputation to 0-100 range."""
        _, public_key = auditor_keypair
        pub = _ed_pub(public_key)

        result = auditor.issue_vouch({"did": "did:web:test.com", "reputation_score": 150})
        _, passport = Verifier.verify(result["certificate"], public_key=pub)
        assert passport.reputation_score == 100

        result = auditor.issue_vouch({"did": "did:web:test.com", "reputation_score": -50})
        _, passport = Verifier.verify(result["certificate"], public_key=pub)
        assert passport.reputation_score == 0

    def test_issue_vouch_custom_expiry(self, auditor, auditor_keypair):
        """issue_vouch() respects custom expiry."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch({"did": "did:web:test.com"}, expiry_seconds=3600)

        _, passport = Verifier.verify(result["certificate"], public_key=_ed_pub(public_key))

        vf = datetime.fromisoformat(passport.valid_from.replace("Z", "+00:00"))
        vu = datetime.fromisoformat(passport.valid_until.replace("Z", "+00:00"))
        assert (vu - vf).total_seconds() == 3600


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

        is_valid, passport = Verifier.verify(result["certificate"], public_key=_ed_pub(public_key))

        assert is_valid is True
        assert passport.iss == auditor.get_issuer_did()
        assert passport.intent["target"] == "did:web:test-agent.com"

    def test_certificate_has_vc_claims(self, auditor, auditor_keypair):
        """Certificate binds identity, reputation, and integrity hash."""
        _, public_key = auditor_keypair

        result = auditor.issue_vouch(
            {
                "did": "did:web:test-agent.com",
                "integrity_hash": "sha256:abc123",
                "reputation_score": 85,
            }
        )

        _, passport = Verifier.verify(result["certificate"], public_key=_ed_pub(public_key))

        assert passport.reputation_score == 85
        assert passport.intent["integrity_hash"] == "sha256:abc123"
        assert passport.intent["credential_type"] == "Identity+Reputation"


class TestAuditorPublicKey:
    """Tests for Auditor.get_public_key_jwk()."""

    def test_get_public_key(self, auditor):
        """get_public_key_jwk() returns valid public key."""
        pub_key = auditor.get_public_key_jwk()
        parsed = json.loads(pub_key)

        assert parsed["kty"] == "OKP"
        assert "d" not in parsed  # No private component
