#!/usr/bin/env python3
"""
04_rate_limiting.py - Protect APIs with Rate Limiting

Limit how fast agents can make requests.

Run: python 04_rate_limiting.py
"""

from vouch import (
    Signer,
    MemoryRateLimiter,
    RateLimitResult,
)
import time

print("⏱️ Rate Limiting")
print("=" * 50)

# =============================================================================
# Create Rate Limiter
# =============================================================================

# Allow 5 requests per minute per agent
limiter = MemoryRateLimiter(
    max_requests=5,
    window_seconds=60,
)

agent = Signer(name="Fast Agent")

print(f"Rate limit: 5 requests per minute")
print(f"Agent: {agent.name}")

# =============================================================================
# Check Rate Limits
# =============================================================================

print("\n📊 Making requests...")

for i in range(7):
    result = limiter.check(agent.public_key)
    
    if result.allowed:
        print(f"  Request {i+1}: ✅ Allowed ({result.remaining} remaining)")
    else:
        print(f"  Request {i+1}: ❌ Blocked (retry in {result.retry_after:.0f}s)")

# =============================================================================
# Different Limits for Different Operations
# =============================================================================

print("\n🔧 Tiered Rate Limits:")

# Critical operations: stricter limits
critical_limiter = MemoryRateLimiter(max_requests=2, window_seconds=60)

# Normal operations: more generous
normal_limiter = MemoryRateLimiter(max_requests=100, window_seconds=60)

print("  Critical operations: 2/min (transfers, deletions)")
print("  Normal operations: 100/min (reads, queries)")

# Check critical operation
result = critical_limiter.check(agent.public_key)
print(f"\n  Critical op: {'✅ Allowed' if result.allowed else '❌ Blocked'}")

# =============================================================================
# Composite Limiter
# =============================================================================

print("\n📦 Composite Rate Limiter:")

from vouch import CompositeRateLimiter

# Multiple limits applied together
composite = CompositeRateLimiter([
    MemoryRateLimiter(max_requests=10, window_seconds=1),    # Burst: 10/sec
    MemoryRateLimiter(max_requests=100, window_seconds=60),  # Sustained: 100/min
    MemoryRateLimiter(max_requests=1000, window_seconds=3600), # Daily: 1000/hr
])

print("  Burst: 10/second")
print("  Sustained: 100/minute")
print("  Daily: 1000/hour")

result = composite.check(agent.public_key)
print(f"\n  Composite check: {'✅ Allowed' if result.allowed else '❌ Blocked'}")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 RATE LIMITING FEATURES:

Limiters:
  • MemoryRateLimiter - Single instance
  • RedisRateLimiter - Distributed
  • CompositeRateLimiter - Multiple limits

Configuration:
  • max_requests: Requests allowed
  • window_seconds: Time window
  • Per agent (by public_key)

Response:
  • allowed: Can proceed?
  • remaining: Requests left
  • retry_after: Seconds to wait

Use Cases:
  • Prevent API abuse
  • Protect expensive operations
  • Fair resource allocation
""")
