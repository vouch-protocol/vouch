"""
Tests for Vouch Hasura Integration.
"""

import json

import pytest
from unittest.mock import MagicMock

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


def _headers(signer, action, *, resource=None, extra=None, header="Vouch-Credential", **sign_kw):
    """Sign a credential for `action` and wrap it as a request header."""
    intent = {"action": action, "target": "hasura", "resource": resource or action}
    if extra:
        intent.update(extra)
    credential = signer.sign(intent=intent, **sign_kw)
    return {header: json.dumps(credential)}


class TestHasuraAuthWebhook:
    """Test cases for HasuraAuthWebhook."""

    def test_missing_credential_returns_401(self, webhook):
        """Missing credential should fail."""
        success, result = webhook.authenticate({})
        assert success is False
        assert "Missing Vouch-Credential" in result["error"]

    def test_valid_credential_returns_session_vars(self, webhook, signer):
        """Valid credential should return session variables."""
        success, result = webhook.authenticate(_headers(signer, "read_users"))

        assert success is True
        assert "X-Hasura-Role" in result
        assert result["X-Hasura-User-Id"] == signer.did

    def test_authorization_header_format(self, webhook, signer):
        """Authorization: Vouch <credential> format should work."""
        headers = _headers(signer, "read_users")
        auth = {"Authorization": f"Vouch {headers['Vouch-Credential']}"}

        success, result = webhook.authenticate(auth)

        assert success is True

    def test_expired_credential_fails(self, webhook, signer):
        """Expired credential should fail verification."""
        success, result = webhook.authenticate(_headers(signer, "read", valid_seconds=-60))

        assert success is False

    def test_invalid_signature_fails(self, webhook):
        """A malformed credential should fail."""
        success, result = webhook.authenticate({"Vouch-Credential": "eyJ.invalid.token"})

        assert success is False

    def test_reputation_score_in_session_vars(self, webhook, signer):
        """Reputation score should be included in session vars."""
        success, result = webhook.authenticate(_headers(signer, "read", reputation_score=85))

        assert success is True
        assert result.get("X-Hasura-Vouch-Reputation") == "85"

    def test_high_reputation_gets_admin_role(self, webhook, signer):
        """High reputation should get agent_admin role."""
        success, result = webhook.authenticate(_headers(signer, "admin_task", reputation_score=90))

        assert success is True
        assert result["X-Hasura-Role"] == "agent_admin"

    def test_low_reputation_gets_reader_role(self, webhook, signer):
        """Low reputation should get agent_reader role."""
        success, result = webhook.authenticate(_headers(signer, "read", reputation_score=35))

        assert success is True
        assert result["X-Hasura-Role"] == "agent_reader"

    def test_did_role_mapping(self, test_keys):
        """Explicit DID role mapping should work."""
        config = RoleMappingConfig(did_roles={test_keys["did"]: "special_agent"})

        webhook = HasuraAuthWebhook(
            trusted_dids={test_keys["did"]: test_keys["public"]},
            role_config=config,
            allow_did_resolution=False,
        )

        signer = Signer(private_key=test_keys["private"], did=test_keys["did"])
        success, result = webhook.authenticate(_headers(signer, "test"))

        assert success is True
        assert result["X-Hasura-Role"] == "special_agent"

    def test_intent_hash_included(self, webhook, signer):
        """Intent hash should be included in session vars."""
        success, result = webhook.authenticate(
            _headers(signer, "query_users", extra={"table": "users"})
        )

        assert success is True
        assert "X-Hasura-Vouch-Intent" in result
        assert len(result["X-Hasura-Vouch-Intent"]) == 16  # First 16 chars of hash

    def test_revocation_check(self, test_keys):
        """Revoked DIDs should be rejected."""
        mock_redis = MagicMock()
        mock_redis.get.return_value = "1"

        webhook = HasuraAuthWebhook(
            trusted_dids={test_keys["did"]: test_keys["public"]},
            revocation_store=mock_redis,
            allow_did_resolution=False,
        )

        signer = Signer(private_key=test_keys["private"], did=test_keys["did"])
        success, result = webhook.authenticate(_headers(signer, "test"))

        assert success is False
        assert "revoked" in result["error"].lower()

    def test_replay_prevention(self, test_keys):
        """Same credential used twice should be rejected."""
        mock_redis = MagicMock()
        mock_redis.exists.side_effect = [False, True]  # First: not used, second: used

        webhook = HasuraAuthWebhook(
            trusted_dids={test_keys["did"]: test_keys["public"]},
            nonce_store=mock_redis,
            allow_did_resolution=False,
        )

        signer = Signer(private_key=test_keys["private"], did=test_keys["did"])
        headers = _headers(signer, "test")

        success1, _ = webhook.authenticate(headers)
        assert success1 is True

        success2, result2 = webhook.authenticate(headers)
        assert success2 is False
        assert "replay" in result2["error"].lower()
