"""
Tests for Vouch Hasura Integration.
"""

import pytest
import json
import time
from unittest.mock import Mock, MagicMock

from vouch import Signer
from vouch.integrations.hasura.webhook import HasuraAuthWebhook, RoleMappingConfig


@pytest.fixture
def test_keys():
    """Generate test keypair."""
    from jwcrypto import jwk

    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    return {
        "private": key.export_private(),
        "public": key.export_public(),
        "did": "did:web:test-agent.example.com",
    }


@pytest.fixture
def signer(test_keys):
    """Create a test signer."""
    return Signer(private_key=test_keys["private"], did=test_keys["did"])


@pytest.fixture
def webhook(test_keys):
    """Create a webhook with the test key trusted."""
    return HasuraAuthWebhook(
        trusted_dids={test_keys["did"]: test_keys["public"]},
        allow_did_resolution=False,
    )


class TestHasuraAuthWebhook:
    """Test cases for HasuraAuthWebhook."""

    def test_missing_token_returns_401(self, webhook):
        """Missing Vouch-Token should fail."""
        success, result = webhook.authenticate({})
        assert success is False
        assert "Missing Vouch-Token" in result["error"]

    def test_valid_token_returns_session_vars(self, webhook, signer):
        """Valid token should return session variables."""
        token = signer.sign({"action": "read_users"})
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is True
        assert "X-Hasura-Role" in result
        assert result["X-Hasura-User-Id"] == signer.get_did()

    def test_authorization_header_format(self, webhook, signer):
        """Authorization: Vouch <token> format should work."""
        token = signer.sign({"action": "read_users"})
        headers = {"Authorization": f"Vouch {token}"}

        success, result = webhook.authenticate(headers)

        assert success is True

    def test_expired_token_fails(self, webhook, signer):
        """Expired token should fail verification."""
        token = signer.sign({"action": "read"}, expiry_seconds=-10)  # Already expired
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is False

    def test_invalid_signature_fails(self, webhook):
        """Token with invalid signature should fail."""
        headers = {"Vouch-Token": "eyJ.invalid.token"}

        success, result = webhook.authenticate(headers)

        assert success is False

    def test_reputation_score_in_session_vars(self, webhook, signer):
        """Reputation score should be included in session vars."""
        token = signer.sign({"action": "read"}, reputation_score=85)
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is True
        assert result.get("X-Hasura-Vouch-Reputation") == "85"

    def test_high_reputation_gets_admin_role(self, webhook, signer):
        """High reputation should get agent_admin role."""
        token = signer.sign({"action": "admin_task"}, reputation_score=90)
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is True
        assert result["X-Hasura-Role"] == "agent_admin"

    def test_low_reputation_gets_reader_role(self, webhook, signer):
        """Low reputation should get agent_reader role."""
        token = signer.sign({"action": "read"}, reputation_score=35)
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is True
        assert result["X-Hasura-Role"] == "agent_reader"

    def test_did_role_mapping(self, test_keys):
        """Explicit DID role mapping should work."""
        config = RoleMappingConfig(did_roles={test_keys["did"]: "special_agent"})

        webhook = HasuraAuthWebhook(
            trusted_dids={test_keys["did"]: test_keys["public"]},
            role_config=config,
        )

        signer = Signer(private_key=test_keys["private"], did=test_keys["did"])
        token = signer.sign({"action": "test"})
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is True
        assert result["X-Hasura-Role"] == "special_agent"

    def test_intent_hash_included(self, webhook, signer):
        """Intent hash should be included in session vars."""
        token = signer.sign({"action": "query_users", "table": "users"})
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is True
        assert "X-Hasura-Vouch-Intent" in result
        assert len(result["X-Hasura-Vouch-Intent"]) == 16  # First 16 chars of hash

    def test_revocation_check(self, test_keys):
        """Revoked DIDs should be rejected."""
        # Mock Redis that says DID is revoked
        mock_redis = MagicMock()
        mock_redis.get.return_value = "1"

        webhook = HasuraAuthWebhook(
            trusted_dids={test_keys["did"]: test_keys["public"]},
            revocation_store=mock_redis,
        )

        signer = Signer(private_key=test_keys["private"], did=test_keys["did"])
        token = signer.sign({"action": "test"})
        headers = {"Vouch-Token": token}

        success, result = webhook.authenticate(headers)

        assert success is False
        assert "revoked" in result["error"].lower()

    def test_replay_prevention(self, test_keys):
        """Same token used twice should be rejected."""
        mock_redis = MagicMock()
        mock_redis.exists.side_effect = [False, True]  # First call: not used, second: used

        webhook = HasuraAuthWebhook(
            trusted_dids={test_keys["did"]: test_keys["public"]},
            nonce_store=mock_redis,
        )

        signer = Signer(private_key=test_keys["private"], did=test_keys["did"])
        token = signer.sign({"action": "test"})
        headers = {"Vouch-Token": token}

        # First request should succeed
        success1, _ = webhook.authenticate(headers)
        assert success1 is True

        # Second request (replay) should fail
        success2, result2 = webhook.authenticate(headers)
        assert success2 is False
        assert "replay" in result2["error"].lower()
