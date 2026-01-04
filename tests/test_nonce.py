"""
Unit tests for nonce tracking (replay prevention).
"""

import pytest
import asyncio
import time

from vouch.nonce import MemoryNonceTracker


class TestMemoryNonceTrackerBasic:
    """Basic nonce tracker tests."""

    @pytest.mark.asyncio
    async def test_new_nonce_not_used(self, nonce_tracker):
        """New nonce is not marked as used."""
        is_used = await nonce_tracker.is_used("new-jti-123")
        assert is_used is False

    @pytest.mark.asyncio
    async def test_mark_used(self, nonce_tracker):
        """mark_used() marks nonce as used."""
        await nonce_tracker.mark_used("jti-123", int(time.time()) + 300)
        is_used = await nonce_tracker.is_used("jti-123")
        assert is_used is True

    @pytest.mark.asyncio
    async def test_expired_nonce_not_used(self):
        """Expired nonce returns False."""
        tracker = MemoryNonceTracker()

        # Mark as used with expiry in the past
        await tracker.mark_used("jti-expired", int(time.time()) - 10)

        is_used = await tracker.is_used("jti-expired")
        assert is_used is False


class TestMemoryNonceTrackerCapacity:
    """Capacity and eviction tests."""

    @pytest.mark.asyncio
    async def test_max_size_eviction(self):
        """Oldest nonces evicted when at capacity."""
        tracker = MemoryNonceTracker(max_size=3)
        future = int(time.time()) + 300

        await tracker.mark_used("jti-1", future)
        await tracker.mark_used("jti-2", future)
        await tracker.mark_used("jti-3", future)

        # Adding 4th should evict jti-1
        await tracker.mark_used("jti-4", future)

        assert await tracker.is_used("jti-1") is False  # Evicted
        assert await tracker.is_used("jti-4") is True


class TestMemoryNonceTrackerCleanup:
    """Cleanup tests."""

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        """cleanup_expired() removes expired entries."""
        tracker = MemoryNonceTracker()
        now = int(time.time())

        await tracker.mark_used("jti-expired", now - 10)  # Already expired
        await tracker.mark_used("jti-valid", now + 300)  # Still valid

        removed = await tracker.cleanup_expired()

        assert removed >= 1
        assert await tracker.is_used("jti-valid") is True


class TestMemoryNonceTrackerStats:
    """Statistics tracking tests."""

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Tracker maintains statistics."""
        tracker = MemoryNonceTracker()
        future = int(time.time()) + 300

        await tracker.mark_used("jti-1", future)
        await tracker.is_used("jti-1")  # Replay blocked
        await tracker.is_used("jti-2")  # Not found

        stats = tracker.stats
        assert stats["tracked"] >= 1
        assert stats["replays_blocked"] >= 1


class TestNonceTrackerConcurrency:
    """Concurrency tests."""

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Tracker handles concurrent access safely."""
        tracker = MemoryNonceTracker()
        future = int(time.time()) + 300

        async def mark_and_check(jti: str):
            await tracker.mark_used(jti, future)
            return await tracker.is_used(jti)

        # Run 100 concurrent operations
        tasks = [mark_and_check(f"jti-{i}") for i in range(100)]
        results = await asyncio.gather(*tasks)

        assert all(r is True for r in results)
