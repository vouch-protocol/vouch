"""
Unit tests for the revocation registry.
"""

import pytest
import time

from vouch.revocation import RevocationRecord, MemoryRevocationStore, RevocationRegistry


class TestRevocationRecord:
    """Tests for RevocationRecord dataclass."""

    def test_create_record(self):
        """Create a basic revocation record."""
        record = RevocationRecord(
            did="did:web:test.com", revoked_at=int(time.time()), reason="Key compromised"
        )
        assert record.did == "did:web:test.com"
        assert record.reason == "Key compromised"

    def test_to_dict(self):
        """Convert record to dictionary."""
        record = RevocationRecord(did="did:web:test.com", revoked_at=12345, reason="Test")
        d = record.to_dict()
        assert d["did"] == "did:web:test.com"
        assert d["revoked_at"] == 12345

    def test_from_dict(self):
        """Create record from dictionary."""
        data = {"did": "did:web:test.com", "revoked_at": 12345, "reason": "Test"}
        record = RevocationRecord.from_dict(data)
        assert record.did == "did:web:test.com"


class TestMemoryRevocationStore:
    """Tests for MemoryRevocationStore."""

    @pytest.mark.asyncio
    async def test_add_revocation(self):
        """Add a revocation."""
        store = MemoryRevocationStore()
        record = RevocationRecord(
            did="did:web:bad-agent.com", revoked_at=int(time.time()), reason="Malicious behavior"
        )
        await store.add_revocation(record)

        is_revoked = await store.is_revoked("did:web:bad-agent.com")
        assert is_revoked is True

    @pytest.mark.asyncio
    async def test_not_revoked(self):
        """Non-revoked DID returns False."""
        store = MemoryRevocationStore()
        is_revoked = await store.is_revoked("did:web:good-agent.com")
        assert is_revoked is False

    @pytest.mark.asyncio
    async def test_remove_revocation(self):
        """Remove revocation reinstates key."""
        store = MemoryRevocationStore()
        record = RevocationRecord(
            did="did:web:test.com", revoked_at=int(time.time()), reason="Test"
        )
        await store.add_revocation(record)

        removed = await store.remove_revocation("did:web:test.com")
        assert removed is True

        is_revoked = await store.is_revoked("did:web:test.com")
        assert is_revoked is False

    @pytest.mark.asyncio
    async def test_list_revocations(self):
        """List all revocations."""
        store = MemoryRevocationStore()

        await store.add_revocation(
            RevocationRecord(did="did:web:agent1.com", revoked_at=int(time.time()), reason="Test 1")
        )
        await store.add_revocation(
            RevocationRecord(did="did:web:agent2.com", revoked_at=int(time.time()), reason="Test 2")
        )

        revocations = await store.list_revocations()
        assert len(revocations) == 2


class TestRevocationRegistry:
    """Tests for RevocationRegistry."""

    @pytest.mark.asyncio
    async def test_revoke(self):
        """Revoke a DID."""
        registry = RevocationRegistry(check_remote=False)

        record = await registry.revoke(
            did="did:web:compromised.com", reason="Key leaked", revoked_by="did:web:authority.com"
        )

        assert record.did == "did:web:compromised.com"
        assert await registry.is_revoked("did:web:compromised.com") is True

    @pytest.mark.asyncio
    async def test_reinstate(self):
        """Reinstate a revoked DID."""
        registry = RevocationRegistry(check_remote=False)

        await registry.revoke(did="did:web:test.com", reason="Test")
        await registry.reinstate("did:web:test.com")

        assert await registry.is_revoked("did:web:test.com") is False

    @pytest.mark.asyncio
    async def test_effective_from(self):
        """Delayed revocation respects effective_from."""
        registry = RevocationRegistry(check_remote=False)

        future_time = int(time.time()) + 3600  # 1 hour from now
        await registry.revoke(
            did="did:web:delayed.com", reason="Scheduled revocation", effective_from=future_time
        )

        # Should not be revoked yet
        assert await registry.is_revoked("did:web:delayed.com") is False
