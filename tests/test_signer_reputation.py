"""
Tests for reputation integration in Signer.

Tests the new reputation_score parameter in sign().
"""

import pytest
from vouch.signer import Signer
from vouch.verifier import Verifier
from vouch.keys import generate_identity


class TestSignerReputationManual:
    """Tests for manually specifying reputation_score."""

    @pytest.fixture
    def signer(self):
        """Create a signer with generated keys."""
        identity = generate_identity(domain="test-agent.com")
        return Signer(
            private_key=identity.private_key_jwk, did=identity.did
        ), identity.public_key_jwk

    def test_sign_without_reputation_backward_compatible(self, signer):
        """Tokens without reputation should still work (backward compatible)."""
        signer_obj, public_key = signer
        token = signer_obj.sign({"action": "read"})

        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key)

        assert is_valid
        assert passport.reputation_score is None  # No reputation included

    def test_sign_with_manual_reputation(self, signer):
        """Should include reputation_score when manually specified."""
        signer_obj, public_key = signer
        token = signer_obj.sign({"action": "read"}, reputation_score=85)

        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key)

        assert is_valid
        assert passport.reputation_score == 85

    def test_sign_with_zero_reputation(self, signer):
        """Should handle zero reputation."""
        signer_obj, public_key = signer
        token = signer_obj.sign({"action": "read"}, reputation_score=0)

        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key)

        assert is_valid
        assert passport.reputation_score == 0

    def test_sign_with_max_reputation(self, signer):
        """Should handle 100 reputation."""
        signer_obj, public_key = signer
        token = signer_obj.sign({"action": "read"}, reputation_score=100)

        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key)

        assert is_valid
        assert passport.reputation_score == 100

    def test_sign_clamps_reputation_above_100(self, signer):
        """Should clamp reputation above 100 to 100."""
        signer_obj, public_key = signer
        token = signer_obj.sign({"action": "read"}, reputation_score=150)

        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key)

        assert is_valid
        assert passport.reputation_score == 100  # Clamped

    def test_sign_clamps_reputation_below_0(self, signer):
        """Should clamp reputation below 0 to 0."""
        signer_obj, public_key = signer
        token = signer_obj.sign({"action": "read"}, reputation_score=-10)

        is_valid, passport = Verifier.verify(token, public_key_jwk=public_key)

        assert is_valid
        assert passport.reputation_score == 0  # Clamped


class TestPassportReputation:
    """Tests for Passport reputation field."""

    def test_passport_reputation_in_raw_claims(self):
        """Reputation should be accessible in raw_claims as well."""
        identity = generate_identity(domain="test.com")
        signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

        token = signer.sign({"action": "test"}, reputation_score=75)
        is_valid, passport = Verifier.verify(token, public_key_jwk=identity.public_key_jwk)

        assert is_valid
        assert passport.reputation_score == 75
        assert passport.raw_claims["vouch"]["reputation_score"] == 75

    def test_passport_without_reputation_has_none(self):
        """Passport should have None for reputation if not in token."""
        identity = generate_identity(domain="test.com")
        signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

        token = signer.sign({"action": "test"})  # No reputation
        is_valid, passport = Verifier.verify(token, public_key_jwk=identity.public_key_jwk)

        assert is_valid
        assert passport.reputation_score is None
        assert "reputation_score" not in passport.raw_claims["vouch"]

    def test_passport_reputation_different_values(self):
        """Test various reputation values."""
        identity = generate_identity(domain="test.com")
        signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

        for expected_score in [25, 50, 75, 90, 100]:
            token = signer.sign({"action": "test"}, reputation_score=expected_score)
            is_valid, passport = Verifier.verify(token, public_key_jwk=identity.public_key_jwk)

            assert is_valid
            assert passport.reputation_score == expected_score
