"""
Unit tests for the AsyncVerifier class.
"""

import pytest
import asyncio

from vouch import Signer, generate_identity
from vouch.async_verifier import AsyncVerifier, VerificationResult
from vouch.cache import MemoryCache
from vouch.nonce import MemoryNonceTracker


class TestAsyncVerifierBasic:
    """Basic async verification tests."""

    @pytest.mark.asyncio
    async def test_verify_valid_token(self, keypair, sample_payload):
        """verify() returns True for valid token."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        token = signer.sign(sample_payload)

        async with AsyncVerifier() as verifier:
            is_valid, passport = await verifier.verify(token, public_key_jwk=keypair.public_key_jwk)

        assert is_valid is True
        assert passport.sub == keypair.did

    @pytest.mark.asyncio
    async def test_verify_invalid_token(self, keypair):
        """verify() returns False for invalid token."""
        async with AsyncVerifier() as verifier:
            is_valid, passport = await verifier.verify(
                "invalid.token.here", public_key_jwk=keypair.public_key_jwk
            )

        assert is_valid is False
        assert passport is None

    @pytest.mark.asyncio
    async def test_verify_empty_token(self):
        """verify() returns False for empty token."""
        async with AsyncVerifier() as verifier:
            is_valid, passport = await verifier.verify("")

        assert is_valid is False


class TestAsyncVerifierWithNonceTracking:
    """Tests for nonce tracking (replay prevention)."""

    @pytest.mark.asyncio
    async def test_nonce_tracking_blocks_replay(self, keypair, sample_payload):
        """Same token cannot be used twice with nonce tracking."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        token = signer.sign(sample_payload)

        nonce_tracker = MemoryNonceTracker()

        async with AsyncVerifier(nonce_tracker=nonce_tracker) as verifier:
            # First verification should succeed
            is_valid1, _ = await verifier.verify(
                token, public_key_jwk=keypair.public_key_jwk, check_nonce=True
            )
            assert is_valid1 is True

            # Second verification should fail (replay)
            is_valid2, _ = await verifier.verify(
                token, public_key_jwk=keypair.public_key_jwk, check_nonce=True
            )
            assert is_valid2 is False

    @pytest.mark.asyncio
    async def test_nonce_tracking_disabled(self, keypair, sample_payload):
        """Token can be reused when nonce tracking is disabled."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        token = signer.sign(sample_payload)

        nonce_tracker = MemoryNonceTracker()

        async with AsyncVerifier(nonce_tracker=nonce_tracker) as verifier:
            # Both should succeed with check_nonce=False
            is_valid1, _ = await verifier.verify(
                token, public_key_jwk=keypair.public_key_jwk, check_nonce=False
            )
            is_valid2, _ = await verifier.verify(
                token, public_key_jwk=keypair.public_key_jwk, check_nonce=False
            )

            assert is_valid1 is True
            assert is_valid2 is True


class TestAsyncVerifierBatch:
    """Tests for batch verification."""

    @pytest.mark.asyncio
    async def test_verify_batch_all_valid(self, keypair, sample_payload):
        """verify_batch() returns all valid for valid tokens."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        tokens = [signer.sign(sample_payload) for _ in range(5)]

        async with AsyncVerifier() as verifier:
            results = await verifier.verify_batch(
                tokens, public_key_jwk=keypair.public_key_jwk, check_nonce=False
            )

        assert len(results) == 5
        assert all(r.is_valid for r in results)

    @pytest.mark.asyncio
    async def test_verify_batch_mixed(self, keypair, sample_payload):
        """verify_batch() handles mix of valid and invalid tokens."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)

        tokens = [
            signer.sign(sample_payload),  # Valid
            "invalid.token.1",  # Invalid
            signer.sign(sample_payload),  # Valid
            "invalid.token.2",  # Invalid
        ]

        async with AsyncVerifier() as verifier:
            results = await verifier.verify_batch(
                tokens, public_key_jwk=keypair.public_key_jwk, check_nonce=False
            )

        assert len(results) == 4
        assert results[0].is_valid is True
        assert results[1].is_valid is False
        assert results[2].is_valid is True
        assert results[3].is_valid is False

    @pytest.mark.asyncio
    async def test_verify_batch_empty(self):
        """verify_batch() handles empty list."""
        async with AsyncVerifier() as verifier:
            results = await verifier.verify_batch([])

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_verify_batch_preserves_order(self, keypair):
        """verify_batch() results maintain token order."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)

        payloads = [{"index": i} for i in range(10)]
        tokens = [signer.sign(p) for p in payloads]

        async with AsyncVerifier() as verifier:
            results = await verifier.verify_batch(
                tokens, public_key_jwk=keypair.public_key_jwk, check_nonce=False
            )

        for i, result in enumerate(results):
            assert result.token_index == i
            assert result.passport.payload == {"index": i}


class TestAsyncVerifierWithCache:
    """Tests for caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_integration(self, keypair, sample_payload):
        """AsyncVerifier uses cache for trusted roots."""
        cache = MemoryCache()

        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        token = signer.sign(sample_payload)

        async with AsyncVerifier(
            trusted_roots={keypair.did: keypair.public_key_jwk}, cache=cache
        ) as verifier:
            is_valid, _ = await verifier.check_vouch(token)

        assert is_valid is True


class TestAsyncVerifierStats:
    """Tests for statistics tracking."""

    @pytest.mark.asyncio
    async def test_stats_tracking(self, keypair, sample_payload):
        """AsyncVerifier tracks verification statistics."""
        signer = Signer(private_key=keypair.private_key_jwk, did=keypair.did)
        token = signer.sign(sample_payload)

        async with AsyncVerifier() as verifier:
            await verifier.verify(token, public_key_jwk=keypair.public_key_jwk)
            await verifier.verify("invalid", public_key_jwk=keypair.public_key_jwk)

            stats = verifier.stats

        assert stats["verifications"] == 2
        assert stats["successes"] == 1
        assert stats["failures"] == 1
