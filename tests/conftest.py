"""
Shared pytest fixtures for Vouch Protocol tests.
"""

import pytest
from jwcrypto import jwk

from vouch import Signer, Verifier, Auditor, generate_identity, KeyPair
from vouch.cache import MemoryCache
from vouch.nonce import MemoryNonceTracker


@pytest.fixture
def keypair() -> KeyPair:
    """Generate a fresh keypair for testing."""
    return generate_identity(domain="test-agent.example.com")


@pytest.fixture
def signer(keypair: KeyPair) -> Signer:
    """Create a Signer instance with test keys."""
    return Signer(private_key=keypair.private_key_jwk, did=keypair.did)


@pytest.fixture
def auditor_keypair() -> tuple:
    """Generate keypair for auditor testing."""
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    return key.export_private(), key.export_public()


@pytest.fixture
def auditor(auditor_keypair: tuple) -> Auditor:
    """Create an Auditor instance for testing."""
    private_key, _ = auditor_keypair
    return Auditor(
        private_key_json=private_key,
        issuer_did="did:web:test-authority.example.com"
    )


@pytest.fixture
def memory_cache() -> MemoryCache:
    """Create a memory cache for testing."""
    return MemoryCache(max_size=100, default_ttl=60)


@pytest.fixture
def nonce_tracker() -> MemoryNonceTracker:
    """Create a nonce tracker for testing."""
    return MemoryNonceTracker(max_size=1000)


@pytest.fixture
def sample_payload() -> dict:
    """Sample payload for signing tests."""
    return {
        "action": "read_database",
        "target": "users_table",
        "scope": ["read", "list"]
    }


@pytest.fixture
def expired_signer(keypair: KeyPair) -> Signer:
    """Create a Signer that produces expired tokens."""
    return Signer(
        private_key=keypair.private_key_jwk,
        did=keypair.did,
        default_expiry_seconds=-60  # Already expired
    )
