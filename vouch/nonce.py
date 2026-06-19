"""
Vouch Protocol Nonce Tracking.

Provides nonce (JTI) tracking to prevent token replay attacks.
Supports both in-memory and Redis-backed storage.
"""

import time
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Optional, Set
from collections import OrderedDict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NonceEntry:
    """Represents a tracked nonce with expiration."""

    jti: str
    expires_at: float


class NonceTrackerInterface(ABC):
    """Abstract interface for nonce tracking implementations."""

    @abstractmethod
    async def is_used(self, jti: str) -> bool:
        """Check if a nonce has already been used."""
        pass

    @abstractmethod
    async def mark_used(self, jti: str, expires_at: int) -> None:
        """Mark a nonce as used, with expiration timestamp."""
        pass

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove expired nonces. Returns count removed."""
        pass


class MemoryNonceTracker(NonceTrackerInterface):
    """
    In-memory nonce tracker with automatic expiration.

    Suitable for single-instance deployments. For multi-instance
    deployments, use RedisNonceTracker.

    Example:
        >>> tracker = MemoryNonceTracker(max_size=100000)
        >>>
        >>> # During verification:
        >>> if await tracker.is_used(passport.jti):
        ...     raise ValueError("Token replay detected")
        >>> await tracker.mark_used(passport.jti, passport.exp)
    """

    def __init__(self, max_size: int = 100000, cleanup_interval: int = 60):
        """
        Initialize the memory nonce tracker.

        Args:
            max_size: Maximum nonces to track before forced eviction.
            cleanup_interval: Seconds between automatic cleanup runs.
        """
        self._nonces: OrderedDict[str, float] = OrderedDict()  # jti -> expires_at
        self._max_size = max_size
        self._cleanup_interval = cleanup_interval
        self._lock = asyncio.Lock()
        self._last_cleanup = time.time()
        self._stats = {"tracked": 0, "replays_blocked": 0, "evicted": 0}

    async def is_used(self, jti: str) -> bool:
        """Check if nonce was already used (replay attack)."""
        async with self._lock:
            # Periodic cleanup
            await self._maybe_cleanup()

            if jti in self._nonces:
                expires_at = self._nonces[jti]
                if time.time() < expires_at:
                    self._stats["replays_blocked"] += 1
                    return True
                else:
                    # Expired, remove it
                    del self._nonces[jti]

            return False

    async def mark_used(self, jti: str, expires_at: int) -> None:
        """Mark a nonce as used."""
        async with self._lock:
            # Evict oldest if at capacity
            while len(self._nonces) >= self._max_size:
                oldest = next(iter(self._nonces))
                del self._nonces[oldest]
                self._stats["evicted"] += 1

            self._nonces[jti] = float(expires_at)
            self._stats["tracked"] += 1

    async def cleanup_expired(self) -> int:
        """Remove all expired nonces."""
        async with self._lock:
            return await self._cleanup_internal()

    async def _cleanup_internal(self) -> int:
        """Internal cleanup without lock."""
        now = time.time()
        expired = [jti for jti, exp in self._nonces.items() if now >= exp]

        for jti in expired:
            del self._nonces[jti]

        return len(expired)

    async def _maybe_cleanup(self) -> None:
        """Run cleanup if interval has passed."""
        now = time.time()
        if now - self._last_cleanup >= self._cleanup_interval:
            await self._cleanup_internal()
            self._last_cleanup = now

    @property
    def stats(self) -> dict:
        """Return tracking statistics."""
        return {**self._stats, "active": len(self._nonces), "max_size": self._max_size}


class RedisNonceTracker(NonceTrackerInterface):
    """
    Redis-backed nonce tracker for distributed deployments.

    Uses Redis SET with TTL for automatic expiration. Provides
    consistent nonce tracking across all verifier instances.

    Example:
        >>> import redis.asyncio as redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> tracker = RedisNonceTracker(client)
        >>>
        >>> if await tracker.is_used(passport.jti):
        ...     raise ValueError("Token replay detected")
        >>> await tracker.mark_used(passport.jti, passport.exp)
    """

    def __init__(self, redis_client, key_prefix: str = "vouch:nonce:", grace_period: int = 60):
        """
        Initialize Redis nonce tracker.

        Args:
            redis_client: An async Redis client (redis.asyncio.Redis).
            key_prefix: Prefix for nonce keys.
            grace_period: Extra seconds to keep nonce after token expiry.
        """
        self._redis = redis_client
        self._prefix = key_prefix
        self._grace_period = grace_period

    def _key(self, jti: str) -> str:
        """Generate prefixed key."""
        return f"{self._prefix}{jti}"

    async def is_used(self, jti: str) -> bool:
        """Check if nonce exists in Redis."""
        try:
            exists = await self._redis.exists(self._key(jti))
            return exists > 0
        except Exception as e:
            logger.warning(f"Redis nonce check error: {e}")
            # Fail open vs fail closed - configurable in production
            return False

    async def mark_used(self, jti: str, expires_at: int) -> None:
        """Mark nonce as used with TTL matching token expiry."""
        try:
            # Calculate TTL: time until expiry + grace period
            now = int(time.time())
            ttl = max(expires_at - now + self._grace_period, 60)

            await self._redis.setex(
                self._key(jti),
                ttl,
                "1",  # Value doesn't matter, just existence
            )
        except Exception as e:
            logger.warning(f"Redis nonce mark error: {e}")

    async def cleanup_expired(self) -> int:
        """Redis handles expiration automatically via TTL."""
        return 0  # No manual cleanup needed

    async def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            return await self._redis.ping()
        except Exception:
            return False


class NonceTrackerFactory:
    """Factory for creating appropriate nonce tracker."""

    @staticmethod
    def create_memory(max_size: int = 100000) -> MemoryNonceTracker:
        """Create an in-memory nonce tracker."""
        return MemoryNonceTracker(max_size=max_size)

    @staticmethod
    def create_redis(redis_client, key_prefix: str = "vouch:nonce:") -> RedisNonceTracker:
        """Create a Redis-backed nonce tracker."""
        return RedisNonceTracker(redis_client, key_prefix=key_prefix)
