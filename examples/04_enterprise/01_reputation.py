#!/usr/bin/env python3
"""
01_reputation.py - Agent Reputation & Trust Scoring

Track agent behavior and compute trust scores.

Run: python 01_reputation.py
"""

from vouch import Signer, ReputationEngine, ReputationEvent, MemoryReputationStore

print("⭐ Reputation Engine")
print("=" * 50)

# =============================================================================
# Create Reputation Engine
# =============================================================================

# Create an agent
agent = Signer(name="Trading Bot")

# Create reputation engine
store = MemoryReputationStore()  # Use RedisReputationStore in production
engine = ReputationEngine(store=store)

print(f"Agent: {agent.name}")
print(f"Public Key: {agent.public_key[:20]}...")

# =============================================================================
# Log Events
# =============================================================================

print("\n📊 Logging Events:")

# Successful actions improve reputation
engine.log_event(ReputationEvent(
    agent_id=agent.public_key,
    event_type="action_success",
    details={"action": "trade_executed", "value": 1000},
))
print("  ✅ Logged: trade executed successfully")

engine.log_event(ReputationEvent(
    agent_id=agent.public_key,
    event_type="action_success",
    details={"action": "risk_check_passed"},
))
print("  ✅ Logged: risk check passed")

# Failed actions decrease reputation
engine.log_event(ReputationEvent(
    agent_id=agent.public_key,
    event_type="action_failed",
    details={"action": "api_timeout", "severity": "low"},
))
print("  ⚠️  Logged: API timeout (low severity)")

# =============================================================================
# Get Reputation Score
# =============================================================================

print("\n📈 Reputation Score:")

score = engine.get_score(agent.public_key)
print(f"   Score: {score.score:.2f}/100")
print(f"   Level: {score.level}")  # trusted, neutral, suspicious
print(f"   Events: {score.event_count}")

# =============================================================================
# Use in Decisions
# =============================================================================

print("\n🔒 Using Reputation for Access Control:")

if score.score >= 80:
    print("  ✅ Agent is trusted - allow high-value operations")
elif score.score >= 50:
    print("  ⚠️  Agent is neutral - require extra verification")
else:
    print("  ❌ Agent is suspicious - deny sensitive operations")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 REPUTATION ENGINE FEATURES:

Event Types:
  • action_success - Positive actions
  • action_failed - Failed operations
  • verification_success - Valid signatures
  • verification_failed - Invalid signatures
  • rate_limit_hit - Too many requests
  
Score Levels:
  • 80-100: Trusted
  • 50-79: Neutral  
  • 0-49: Suspicious

Storage Options:
  • MemoryReputationStore - Dev/testing
  • RedisReputationStore - Production
  • KafkaReputationStore - Distributed events
""")
