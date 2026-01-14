#!/usr/bin/env python3
"""
05_caching.py - Cache Verification Results

Speed up verification with caching.

Run: python 05_caching.py
"""

from vouch import (
    Signer,
    Verifier,
    MemoryCache,
    TieredCache,
)
import time

print("💾 Verification Caching")
print("=" * 50)

# =============================================================================
# Setup Cache
# =============================================================================

# Create memory cache (use RedisCache in production)
cache = MemoryCache(
    ttl_seconds=300,  # Cache for 5 minutes
    max_entries=1000,
)

# Create verifier with cache
verifier = Verifier(cache=cache)

print("Cache TTL: 300 seconds")
print("Max entries: 1000")

# =============================================================================
# Cached Verification
# =============================================================================

agent = Signer(name="Test Agent")
token = agent.sign("Some action")

print("\n⏱️ Verification Timing:")

# First verification (cache miss)
start = time.time()
result1 = verifier.verify(token)
time1 = time.time() - start
print(f"  First verification: {time1 * 1000:.2f}ms (cache miss)")

# Second verification (cache hit)
start = time.time()
result2 = verifier.verify(token)
time2 = time.time() - start
print(f"  Second verification: {time2 * 1000:.2f}ms (cache hit)")

print(f"  Speedup: {time1 / time2:.1f}x faster")

# =============================================================================
# Cache Stats
# =============================================================================

print("\n📊 Cache Statistics:")

stats = cache.get_stats()
print(f"  Hits: {stats.hits}")
print(f"  Misses: {stats.misses}")
print(f"  Hit rate: {stats.hit_rate:.1%}")
print(f"  Entries: {stats.size}")

# =============================================================================
# Tiered Cache
# =============================================================================

print("\n🏗️ Tiered Cache (Memory + Redis):")

print("""
from vouch import MemoryCache, RedisCache, TieredCache

# L1: Fast memory cache
l1_cache = MemoryCache(ttl_seconds=60, max_entries=100)

# L2: Larger Redis cache
l2_cache = RedisCache(
    redis_url="redis://localhost:6379",
    ttl_seconds=300,
)

# Combined: Check L1 first, then L2
tiered = TieredCache([l1_cache, l2_cache])

verifier = Verifier(cache=tiered)
""")

print("  L1 (Memory): Fast, small (100 entries, 60s TTL)")
print("  L2 (Redis): Slower, larger (unlimited, 300s TTL)")
print("  Lookup: L1 → miss → L2 → miss → verify → populate both")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 CACHING BENEFITS:

Performance:
  • 10-100x faster for cached verifications
  • Reduces CPU load
  • Scales better

Cache Types:
  • MemoryCache - Single instance, fast
  • RedisCache - Distributed, persistent
  • TieredCache - Multiple levels (L1 + L2)

Configuration:
  • ttl_seconds: How long to cache
  • max_entries: Cache size limit
  • Auto-eviction of old entries

Best Practices:
  • Short TTL for security-sensitive operations
  • Tiered cache for production
  • Monitor hit rate for tuning
""")
