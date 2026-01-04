"""
Unit tests for the caching layer.
"""

import pytest
import asyncio

from vouch.cache import MemoryCache, CacheInterface


class TestMemoryCacheBasic:
    """Basic MemoryCache tests."""

    @pytest.mark.asyncio
    async def test_set_and_get(self, memory_cache):
        """set() stores value, get() retrieves it."""
        await memory_cache.set("key1", "value1")
        result = await memory_cache.get("key1")
        assert result == "value1"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, memory_cache):
        """get() returns None for nonexistent key."""
        result = await memory_cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, memory_cache):
        """delete() removes key."""
        await memory_cache.set("key1", "value1")
        deleted = await memory_cache.delete("key1")
        assert deleted is True

        result = await memory_cache.get("key1")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, memory_cache):
        """delete() returns False for nonexistent key."""
        deleted = await memory_cache.delete("nonexistent")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_exists(self, memory_cache):
        """exists() returns correct status."""
        await memory_cache.set("key1", "value1")

        assert await memory_cache.exists("key1") is True
        assert await memory_cache.exists("nonexistent") is False

    @pytest.mark.asyncio
    async def test_clear(self, memory_cache):
        """clear() removes all entries."""
        await memory_cache.set("key1", "value1")
        await memory_cache.set("key2", "value2")

        await memory_cache.clear()

        assert await memory_cache.get("key1") is None
        assert await memory_cache.get("key2") is None


class TestMemoryCacheTTL:
    """TTL (Time-To-Live) tests."""

    @pytest.mark.asyncio
    async def test_ttl_expiration(self):
        """Entries expire after TTL."""
        cache = MemoryCache(default_ttl=1)  # 1 second TTL

        await cache.set("key1", "value1")

        # Should exist immediately
        assert await cache.get("key1") == "value1"

        # Wait for expiration
        await asyncio.sleep(1.5)

        # Should be expired
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_custom_ttl_override(self):
        """Custom TTL overrides default."""
        cache = MemoryCache(default_ttl=60)

        await cache.set("key1", "value1", ttl=1)  # 1 second

        await asyncio.sleep(1.5)

        assert await cache.get("key1") is None


class TestMemoryCacheLRU:
    """LRU eviction tests."""

    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        """Oldest entries evicted when at capacity."""
        cache = MemoryCache(max_size=3)

        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")

        # Adding 4th should evict key1
        await cache.set("key4", "value4")

        assert await cache.get("key1") is None  # Evicted
        assert await cache.get("key2") == "value2"
        assert await cache.get("key4") == "value4"

    @pytest.mark.asyncio
    async def test_lru_access_updates_order(self):
        """Accessing a key moves it to end (prevents eviction)."""
        cache = MemoryCache(max_size=3)

        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")

        # Access key1 to move it to end
        await cache.get("key1")

        # Adding 4th should now evict key2 (oldest not accessed)
        await cache.set("key4", "value4")

        assert await cache.get("key1") == "value1"  # Still exists
        assert await cache.get("key2") is None  # Evicted


class TestMemoryCacheStats:
    """Cache statistics tests."""

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Cache tracks hits and misses."""
        cache = MemoryCache()

        await cache.set("key1", "value1")

        await cache.get("key1")  # Hit
        await cache.get("key1")  # Hit
        await cache.get("missing")  # Miss

        stats = cache.stats
        assert stats["hits"] == 2
        assert stats["misses"] == 1

    @pytest.mark.asyncio
    async def test_hit_ratio(self):
        """hit_ratio property calculates correctly."""
        cache = MemoryCache()

        await cache.set("key1", "value1")

        await cache.get("key1")  # Hit
        await cache.get("key1")  # Hit
        await cache.get("missing")  # Miss
        await cache.get("missing2")  # Miss

        # 2 hits, 2 misses = 50% hit ratio
        assert cache.hit_ratio == 0.5
