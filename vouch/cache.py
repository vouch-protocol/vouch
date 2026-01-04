"""
Vouch Protocol Caching Layer.

Provides pluggable cache backends for DID public key caching,
supporting both in-memory and Redis-backed distributed caching.
"""

import time
import logging
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from collections import OrderedDict
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached value with metadata."""

    value: str
    cached_at: float
    ttl: int
    hits: int = 0


class CacheInterface(ABC):
    """Abstract interface for cache implementations."""

    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Get a value from cache. Returns None if not found or expired."""
        pass

    @abstractmethod
    async def set(self, key: str, value: str, ttl: int = 300) -> None:
        """Set a value in cache with TTL in seconds."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key from cache. Returns True if key existed."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all entries from cache."""
        pass


class MemoryCache(CacheInterface):
    """
    Thread-safe in-memory LRU cache with TTL support.

    Suitable for single-instance deployments or development.
    For production multi-instance deployments, use RedisCache.

    Example:
        >>> cache = MemoryCache(max_size=1000, default_ttl=300)
        >>> await cache.set('did:web:agent.com', '{"kty":"OKP",...}')
        >>> key = await cache.get('did:web:agent.com')
    """

    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        """
        Initialize the memory cache.

        Args:
            max_size: Maximum number of entries before LRU eviction.
            default_ttl: Default TTL in seconds.
        """
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._lock = asyncio.Lock()
        self._stats = {"hits": 0, "misses": 0, "evictions": 0}

    async def get(self, key: str) -> Optional[str]:
        """Get a value, returning None if not found or expired."""
        async with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None

            entry = self._cache[key]

            # Check expiration
            if time.time() > entry.cached_at + entry.ttl:
                del self._cache[key]
                self._stats["misses"] += 1
                return None

            # Move to end (LRU)
            self._cache.move_to_end(key)
            entry.hits += 1
            self._stats["hits"] += 1

            return entry.value

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> None:
        """Set a value with optional TTL override."""
        async with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self._max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self._stats["evictions"] += 1

            self._cache[key] = CacheEntry(
                value=value,
                cached_at=time.time(),
                ttl=ttl if ttl is not None else self._default_ttl,
            )
            self._cache.move_to_end(key)

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        return await self.get(key) is not None

    async def clear(self) -> None:
        """Clear all entries."""
        async with self._lock:
            self._cache.clear()

    @property
    def stats(self) -> Dict[str, int]:
        """Return cache statistics."""
        return {**self._stats, "size": len(self._cache), "max_size": self._max_size}

    @property
    def hit_ratio(self) -> float:
        """Return cache hit ratio."""
        total = self._stats["hits"] + self._stats["misses"]
        return self._stats["hits"] / total if total > 0 else 0.0


class RedisCache(CacheInterface):
    """
    Redis-backed distributed cache for multi-instance deployments.

    Provides shared caching across all verifier instances for
    horizontal scaling.

    Example:
        >>> import redis.asyncio as redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> cache = RedisCache(client, key_prefix='vouch:keys:')
        >>> await cache.set('did:web:agent.com', '{"kty":"OKP",...}')
    """

    def __init__(self, redis_client, key_prefix: str = "vouch:pubkeys:", default_ttl: int = 300):
        """
        Initialize Redis cache.

        Args:
            redis_client: An async Redis client (redis.asyncio.Redis).
            key_prefix: Prefix for all cache keys.
            default_ttl: Default TTL in seconds.
        """
        self._redis = redis_client
        self._prefix = key_prefix
        self._default_ttl = default_ttl

    def _key(self, key: str) -> str:
        """Generate prefixed key."""
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> Optional[str]:
        """Get a value from Redis."""
        try:
            value = await self._redis.get(self._key(key))
            if value:
                return value.decode("utf-8") if isinstance(value, bytes) else value
            return None
        except Exception as e:
            logger.warning(f"Redis get error: {e}")
            return None

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> None:
        """Set a value in Redis with TTL."""
        try:
            await self._redis.setex(
                self._key(key), ttl if ttl is not None else self._default_ttl, value
            )
        except Exception as e:
            logger.warning(f"Redis set error: {e}")

    async def delete(self, key: str) -> bool:
        """Delete a key from Redis."""
        try:
            result = await self._redis.delete(self._key(key))
            return result > 0
        except Exception as e:
            logger.warning(f"Redis delete error: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis."""
        try:
            return await self._redis.exists(self._key(key)) > 0
        except Exception as e:
            logger.warning(f"Redis exists error: {e}")
            return False

    async def clear(self) -> None:
        """Clear all keys with our prefix."""
        try:
            cursor = 0
            while True:
                cursor, keys = await self._redis.scan(cursor, match=f"{self._prefix}*", count=100)
                if keys:
                    await self._redis.delete(*keys)
                if cursor == 0:
                    break
        except Exception as e:
            logger.warning(f"Redis clear error: {e}")

    async def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            return await self._redis.ping()
        except Exception:
            return False


class TieredCache(CacheInterface):
    """
    Two-tier cache: fast in-memory L1 + distributed Redis L2.

    Provides the speed of local memory cache with the consistency
    of a distributed cache for optimal performance.

    Example:
        >>> l1 = MemoryCache(max_size=1000)
        >>> l2 = RedisCache(redis_client)
        >>> cache = TieredCache(l1, l2)
    """

    def __init__(self, l1_cache: MemoryCache, l2_cache: RedisCache):
        """
        Initialize tiered cache.

        Args:
            l1_cache: Fast local cache (MemoryCache).
            l2_cache: Distributed cache (RedisCache).
        """
        self._l1 = l1_cache
        self._l2 = l2_cache

    async def get(self, key: str) -> Optional[str]:
        """Try L1 first, then L2, populating L1 on L2 hit."""
        # Try L1
        value = await self._l1.get(key)
        if value is not None:
            return value

        # Try L2
        value = await self._l2.get(key)
        if value is not None:
            # Populate L1
            await self._l1.set(key, value)
            return value

        return None

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> None:
        """Set in both L1 and L2."""
        await asyncio.gather(self._l1.set(key, value, ttl), self._l2.set(key, value, ttl))

    async def delete(self, key: str) -> bool:
        """Delete from both tiers."""
        results = await asyncio.gather(self._l1.delete(key), self._l2.delete(key))
        return any(results)

    async def exists(self, key: str) -> bool:
        """Check if exists in either tier."""
        if await self._l1.exists(key):
            return True
        return await self._l2.exists(key)

    async def clear(self) -> None:
        """Clear both tiers."""
        await asyncio.gather(self._l1.clear(), self._l2.clear())
