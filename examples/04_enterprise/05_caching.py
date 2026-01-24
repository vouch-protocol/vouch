#!/usr/bin/env python3
"""
05_caching.py - Verification Caching

Cache public keys and verification results for performance.

Run: python 05_caching.py
"""

from vouch import Signer, Verifier, generate_identity, MemoryCache
import asyncio
import time

print("💾 Verification Caching")
print("=" * 50)


async def main():
    # =============================================================================
    # Setup Cache
    # =============================================================================
    
    print("\n📦 Setting up cache...")
    
    # Create memory cache (max 1000 entries, 5 minute TTL)
    cache = MemoryCache(max_size=1000, default_ttl=300)
    
    # Create an agent
    agent_id = generate_identity(domain="api-client.example.com")
    agent = Signer(private_key=agent_id.private_key_jwk, did=agent_id.did)
    
    print(f"Agent DID: {agent.get_did()}")
    print("Cache config: max_size=1000, default_ttl=300s")
    
    # =============================================================================
    # Cache Public Keys
    # =============================================================================
    
    print("\n🔑 Caching public keys:")
    
    # Store public key in cache
    await cache.set(
        key=f"pubkey:{agent.get_did()}",
        value=agent.get_public_key_jwk(),
        ttl=3600  # 1 hour
    )
    print(f"   ✅ Cached public key for {agent.get_did()}")
    
    # Retrieve from cache
    cached_key = await cache.get(f"pubkey:{agent.get_did()}")
    if cached_key:
        print(f"   📤 Retrieved from cache: {cached_key[:40]}...")
    
    # =============================================================================
    # Verify with Cached Keys
    # =============================================================================
    
    print("\n🔍 Verification with cache:")
    
    async def verify_with_cache(token: str, did: str, cache: MemoryCache):
        """Verify token using cached public key."""
        
        # Try to get public key from cache
        cache_key = f"pubkey:{did}"
        public_key = await cache.get(cache_key)
        
        if public_key:
            print(f"   Cache HIT for {did}")
        else:
            print(f"   Cache MISS for {did} - would fetch from DID document")
            # In real implementation, resolve DID and cache the key
            return {"valid": False, "error": "Key not in cache"}
        
        # Verify with cached key
        is_valid, passport = Verifier.verify(token, public_key)
        
        return {"valid": is_valid, "passport": passport}
    
    # Sign and verify with cache
    token = agent.sign({"action": "test"})
    result = await verify_with_cache(token, agent.get_did(), cache)
    print(f"   Result: valid={result.get('valid')}")
    
    # =============================================================================
    # Cache Statistics
    # =============================================================================
    
    print("\n📊 Cache statistics:")
    
    stats = cache.stats
    print(f"   Entries: {stats.get('size', 0)}")
    print(f"   Hits: {stats.get('hits', 0)}")
    print(f"   Misses: {stats.get('misses', 0)}")
    print(f"   Hit ratio: {cache.hit_ratio:.1%}")
    
    # =============================================================================
    # Cache Operations
    # =============================================================================
    
    print("\n🔧 Cache operations:")
    
    # Check existence
    exists = await cache.exists(f"pubkey:{agent.get_did()}")
    print(f"   Key exists: {exists}")
    
    # Delete
    deleted = await cache.delete(f"pubkey:{agent.get_did()}")
    print(f"   Key deleted: {deleted}")
    
    # Clear all
    await cache.clear()
    print("   Cache cleared")
    
    stats = cache.stats
    print(f"   Entries after clear: {stats.get('size', 0)}")
    
    print("""
📝 CACHING BENEFITS:

Performance:
   • Avoid repeated DID resolution
   • Sub-millisecond key lookups
   • Reduce external API calls

Cache Options:
   • MemoryCache - Single instance, LRU eviction
   • RedisCache - Distributed across instances
   • TieredCache - L1 memory + L2 Redis

Best Practices:
   • Cache public keys (they don't change often)
   • Use appropriate TTL (e.g., 1 hour)
   • Invalidate on key rotation
""")


if __name__ == "__main__":
    asyncio.run(main())
