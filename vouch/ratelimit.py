"""
Vouch Protocol Rate Limiting.

Provides rate limiting for verification endpoints to prevent
abuse and ensure fair resource usage.
"""

import time
import logging
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    reset_at: float
    retry_after: Optional[float] = None


class RateLimiterInterface(ABC):
    """Abstract interface for rate limiter implementations."""

    @abstractmethod
    async def check_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> RateLimitResult:
        """
        Check if a request is allowed under rate limits.

        Args:
            key: Identifier for rate limiting (e.g., DID, IP).
            max_requests: Maximum requests allowed in window.
            window_seconds: Time window in seconds.

        Returns:
            RateLimitResult with allowed status and metadata.
        """
        pass

    @abstractmethod
    async def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        pass


class MemoryRateLimiter(RateLimiterInterface):
    """
    In-memory token bucket rate limiter.

    Suitable for single-instance deployments. For multi-instance
    deployments, use RedisRateLimiter.

    Example:
        >>> limiter = MemoryRateLimiter()
        >>> result = await limiter.check_limit(
        ...     key="did:web:agent.com",
        ...     max_requests=100,
        ...     window_seconds=60
        ... )
        >>> if not result.allowed:
        ...     raise HTTPException(429, f"Retry after {result.retry_after}s")
    """

    def __init__(self, cleanup_interval: int = 300):
        """
        Initialize the rate limiter.

        Args:
            cleanup_interval: Seconds between cleanup runs.
        """
        # key -> (tokens, last_update, window_start)
        self._buckets: Dict[str, Tuple[float, float, float]] = {}
        self._lock = asyncio.Lock()
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()

    async def check_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> RateLimitResult:
        """Check rate limit using token bucket algorithm."""
        async with self._lock:
            await self._maybe_cleanup()

            now = time.time()

            if key in self._buckets:
                tokens, last_update, window_start = self._buckets[key]

                # Refill tokens based on time passed
                time_passed = now - last_update
                refill_rate = max_requests / window_seconds
                tokens = min(max_requests, tokens + time_passed * refill_rate)
            else:
                tokens = float(max_requests)
                window_start = now

            if tokens >= 1:
                # Allow request
                tokens -= 1
                self._buckets[key] = (tokens, now, window_start)

                return RateLimitResult(
                    allowed=True, remaining=int(tokens), reset_at=now + window_seconds
                )
            else:
                # Deny request
                retry_after = (1 - tokens) * (window_seconds / max_requests)
                self._buckets[key] = (tokens, now, window_start)

                return RateLimitResult(
                    allowed=False, remaining=0, reset_at=now + retry_after, retry_after=retry_after
                )

    async def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        async with self._lock:
            if key in self._buckets:
                del self._buckets[key]

    async def _maybe_cleanup(self) -> None:
        """Cleanup old entries."""
        now = time.time()
        if now - self._last_cleanup >= self._cleanup_interval:
            # Remove entries not updated in 2x cleanup interval
            cutoff = now - (self._cleanup_interval * 2)
            expired = [
                k for k, (_, last_update, _) in self._buckets.items() if last_update < cutoff
            ]
            for key in expired:
                del self._buckets[key]
            self._last_cleanup = now


class RedisRateLimiter(RateLimiterInterface):
    """
    Redis-backed sliding window rate limiter.

    Provides consistent rate limiting across all instances using
    Redis sorted sets for sliding window implementation.

    Example:
        >>> import redis.asyncio as redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> limiter = RedisRateLimiter(client)
        >>> result = await limiter.check_limit(
        ...     key="did:web:agent.com",
        ...     max_requests=1000,
        ...     window_seconds=60
        ... )
    """

    def __init__(self, redis_client, key_prefix: str = "vouch:ratelimit:"):
        """
        Initialize Redis rate limiter.

        Args:
            redis_client: An async Redis client.
            key_prefix: Prefix for rate limit keys.
        """
        self._redis = redis_client
        self._prefix = key_prefix

    def _key(self, key: str) -> str:
        """Generate prefixed key."""
        return f"{self._prefix}{key}"

    async def check_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> RateLimitResult:
        """Check rate limit using sliding window."""
        try:
            redis_key = self._key(key)
            now = time.time()
            window_start = now - window_seconds

            # Use pipeline for atomic operations
            pipe = self._redis.pipeline()

            # Remove old entries
            pipe.zremrangebyscore(redis_key, 0, window_start)

            # Count current entries
            pipe.zcard(redis_key)

            results = await pipe.execute()
            current_count = results[1]

            if current_count < max_requests:
                # Allow request - add timestamp
                await self._redis.zadd(redis_key, {str(now): now})
                await self._redis.expire(redis_key, window_seconds + 1)

                return RateLimitResult(
                    allowed=True,
                    remaining=max_requests - current_count - 1,
                    reset_at=now + window_seconds,
                )
            else:
                # Deny request
                # Get oldest entry to calculate retry_after
                oldest = await self._redis.zrange(redis_key, 0, 0, withscores=True)
                if oldest:
                    oldest_time = oldest[0][1]
                    retry_after = oldest_time + window_seconds - now
                else:
                    retry_after = window_seconds

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=now + retry_after,
                    retry_after=max(0, retry_after),
                )

        except Exception as e:
            logger.warning(f"Redis rate limit error: {e}")
            # Fail open - allow request if Redis fails
            return RateLimitResult(
                allowed=True, remaining=max_requests, reset_at=time.time() + window_seconds
            )

    async def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        try:
            await self._redis.delete(self._key(key))
        except Exception as e:
            logger.warning(f"Redis reset error: {e}")


class CompositeRateLimiter:
    """
    Composite rate limiter combining multiple limits.

    Useful for applying different limits per DID and per IP.

    Example:
        >>> limiter = CompositeRateLimiter(base_limiter)
        >>> limiter.add_limit("per_did", max_requests=1000, window_seconds=60)
        >>> limiter.add_limit("per_ip", max_requests=10000, window_seconds=60)
        >>>
        >>> result = await limiter.check_all({
        ...     "per_did": "did:web:agent.com",
        ...     "per_ip": "192.168.1.1"
        ... })
    """

    def __init__(self, base_limiter: RateLimiterInterface):
        """
        Initialize composite rate limiter.

        Args:
            base_limiter: The underlying rate limiter to use.
        """
        self._limiter = base_limiter
        self._limits: Dict[str, Tuple[int, int]] = {}  # name -> (max, window)

    def add_limit(self, name: str, max_requests: int, window_seconds: int) -> None:
        """Add a named rate limit."""
        self._limits[name] = (max_requests, window_seconds)

    async def check_all(self, keys: Dict[str, str]) -> RateLimitResult:
        """
        Check all configured limits.

        Args:
            keys: Dict mapping limit name to the key to check.

        Returns:
            RateLimitResult - denied if ANY limit is exceeded.
        """
        for limit_name, key in keys.items():
            if limit_name not in self._limits:
                continue

            max_req, window = self._limits[limit_name]
            result = await self._limiter.check_limit(f"{limit_name}:{key}", max_req, window)

            if not result.allowed:
                return result

        # All limits passed
        return RateLimitResult(
            allowed=True,
            remaining=-1,  # Unknown in composite
            reset_at=time.time() + 60,
        )
