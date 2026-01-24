#!/usr/bin/env python3
"""
04_rate_limiting.py - Rate Limiting for Verification

Prevent abuse of verification endpoints.

Run: python 04_rate_limiting.py
"""

from vouch import Signer, Verifier, generate_identity, MemoryRateLimiter, CompositeRateLimiter
import asyncio

print("⏱️ Rate Limiting")
print("=" * 50)


async def main():
    # =============================================================================
    # Setup Rate Limiter
    # =============================================================================
    
    print("\n📊 Setting up rate limiter...")
    
    # Create memory-based rate limiter
    limiter = MemoryRateLimiter()
    
    # Create an agent
    agent_id = generate_identity(domain="api-client.example.com")
    agent = Signer(private_key=agent_id.private_key_jwk, did=agent_id.did)
    
    print(f"Agent DID: {agent.get_did()}")
    
    # =============================================================================
    # Basic Rate Limiting
    # =============================================================================
    
    print("\n🚦 Testing rate limits (5 requests per 60 seconds):")
    
    # Simulate multiple requests
    for i in range(7):
        # Check rate limit: 5 requests per 60 seconds
        result = await limiter.check_limit(
            key=agent.get_did(),
            max_requests=5,
            window_seconds=60
        )
        
        if result.allowed:
            print(f"   Request {i+1}: ✅ Allowed (remaining: {result.remaining})")
        else:
            print(f"   Request {i+1}: ❌ Denied (retry after: {result.retry_after:.1f}s)")
    
    # =============================================================================
    # Composite Rate Limiting
    # =============================================================================
    
    print("\n🔀 Composite rate limiting (multiple limits):")
    
    # Reset the base limiter
    await limiter.reset(agent.get_did())
    
    # Create composite limiter with multiple rules
    composite = CompositeRateLimiter(base_limiter=limiter)
    composite.add_limit("per_agent", max_requests=10, window_seconds=60)
    composite.add_limit("per_ip", max_requests=100, window_seconds=60)
    composite.add_limit("burst", max_requests=5, window_seconds=1)
    
    # Check against all limits
    keys = {
        "per_agent": agent.get_did(),
        "per_ip": "10.0.0.1",
        "burst": f"{agent.get_did()}:burst",
    }
    
    for i in range(8):
        result = await composite.check_all(keys)
        
        if result.allowed:
            print(f"   Request {i+1}: ✅ Allowed")
        else:
            print(f"   Request {i+1}: ❌ Denied (limit exceeded)")
    
    # =============================================================================
    # Rate Limit Integration Pattern
    # =============================================================================
    
    print("\n🔒 Integration pattern:")
    
    print("""
async def verify_with_rate_limit(token: str, client_did: str, client_ip: str):
    \"\"\"Verify token with rate limiting.\"\"\"
    
    # Check rate limits first
    result = await composite.check_all({
        "per_agent": client_did,
        "per_ip": client_ip,
        "burst": f"{client_did}:burst",
    })
    
    if not result.allowed:
        return {
            "error": "rate_limited",
            "retry_after": result.retry_after
        }
    
    # Proceed with verification
    is_valid, passport = Verifier.verify(token, public_key_jwk)
    
    return {"valid": is_valid, "passport": passport}
""")
    
    print("""
📝 RATE LIMITING BENEFITS:

Protection:
   • Prevent DDoS attacks on verifiers
   • Fair resource allocation
   • Cost control for cloud deployments

Rate Limit Types:
   • Per-agent (DID-based)
   • Per-IP address
   • Burst protection

Storage Options:
   • MemoryRateLimiter - Single instance
   • RedisRateLimiter - Distributed (multi-instance)
   • CompositeRateLimiter - Multiple limits combined
""")


if __name__ == "__main__":
    asyncio.run(main())
