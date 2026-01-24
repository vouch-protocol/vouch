#!/usr/bin/env python3
"""
01_reputation.py - Reputation System

Track agent reputation based on behavior.

Run: python 01_reputation.py
"""

from vouch import Signer, Verifier, generate_identity, ReputationEngine, MemoryReputationStore
import asyncio

print("⭐ Reputation Engine")
print("=" * 50)


async def main():
    # =============================================================================
    # Setup
    # =============================================================================
    
    # Create identity and signer
    identity = generate_identity(domain="trading-bot.example.com")
    agent = Signer(private_key=identity.private_key_jwk, did=identity.did)
    
    # Create reputation engine with memory store
    store = MemoryReputationStore()
    engine = ReputationEngine(store=store)
    
    print(f"Agent DID: {agent.get_did()}")
    
    # =============================================================================
    # Check Initial Reputation
    # =============================================================================
    
    print("\n📊 Initial Reputation:")
    score = await engine.get_score(agent.get_did())
    print(f"   Score: {score.score}")
    print(f"   Tier: {score.tier}")
    
    # =============================================================================
    # Record Positive Events
    # =============================================================================
    
    print("\n📈 Recording positive events...")
    
    # Successful transaction
    new_score = await engine.record_success(
        did=agent.get_did(),
        reason="Transaction completed successfully",
        metadata={"tx_id": "tx123"}
    )
    print(f"   ✅ record_success: Score now {new_score}")
    
    # Another success
    new_score = await engine.record_success(
        did=agent.get_did(),
        reason="Task completed",
    )
    print(f"   ✅ record_success: Score now {new_score}")
    
    # Boost for verified identity
    new_score = await engine.boost(
        did=agent.get_did(),
        amount=5,
        reason="Verified email identity"
    )
    print(f"   🚀 boost (+5): Score now {new_score}")
    
    # =============================================================================
    # Check Updated Score
    # =============================================================================
    
    print("\n📊 Updated Reputation:")
    score = await engine.get_score(agent.get_did())
    print(f"   Score: {score.score}")
    print(f"   Tier: {score.tier}")
    print(f"   Total actions: {score.total_actions}")
    print(f"   Success rate: {score.success_rate:.1%}")
    
    # =============================================================================
    # Record Negative Event
    # =============================================================================
    
    print("\n📉 Recording negative events...")
    
    new_score = await engine.record_failure(
        did=agent.get_did(),
        reason="Failed to respond to request",
    )
    print(f"   ❌ record_failure: Score now {new_score}")
    
    # =============================================================================
    # Slashing for Violation
    # =============================================================================
    
    print("\n🔥 Slashing for policy violation...")
    
    new_score = await engine.slash(
        did=agent.get_did(),
        amount=10,
        reason="Policy violation - unauthorized data access"
    )
    print(f"   ⚠️ slash (-10): Score now {new_score}")
    
    # =============================================================================
    # Get History
    # =============================================================================
    
    print("\n📜 Reputation History:")
    history = await engine.get_history(agent.get_did(), limit=5)
    for event in history:
        print(f"   [{event.action_type}] {event.reason} ({event.delta:+d})")
    
    # =============================================================================
    # Final Score
    # =============================================================================
    
    print("\n📊 Final Reputation:")
    final_score = await engine.get_score(agent.get_did())
    print(f"   Score: {final_score.score}")
    print(f"   Tier: {final_score.tier}") 
    
    print("""
📝 REPUTATION ENGINE FEATURES:

Actions:
   • record_success() - Positive action (+1)
   • record_failure() - Failed action (-2)
   • boost() - Manual reputation boost
   • slash() - Penalty for violations

Tiers:
   • exceptional (90-100)
   • trusted (75-89)
   • neutral (50-74)
   • cautionary (25-49)
   • untrusted (0-24)

Decay:
   • Score trends toward 50 after 7 days inactivity
   • Encourages consistent positive behavior
""")


if __name__ == "__main__":
    asyncio.run(main())
