#!/usr/bin/env python3
"""
03_revocation.py - Key and Token Revocation

Revoke compromised keys or specific tokens.

Run: python 03_revocation.py
"""

from vouch import (
    Signer,
    Verifier,
    RevocationRegistry,
    RevocationRecord,
    MemoryRevocationStore,
)

print("🚫 Revocation")
print("=" * 50)

# =============================================================================
# Setup
# =============================================================================

# Create registry
store = MemoryRevocationStore()  # Use RedisRevocationStore in production
registry = RevocationRegistry(store=store)

# Create an agent
agent = Signer(name="Compromised Agent")
verifier = Verifier(revocation_registry=registry)

print(f"Agent: {agent.name}")
print(f"Public Key: {agent.public_key[:30]}...")

# =============================================================================
# Sign Some Tokens
# =============================================================================

print("\n📝 Signing tokens...")

token1 = agent.sign("Action 1")
token2 = agent.sign("Action 2")
token3 = agent.sign("Action 3")

print(f"  Token 1: {token1[:40]}...")
print(f"  Token 2: {token2[:40]}...")
print(f"  Token 3: {token3[:40]}...")

# Verify they work
result = verifier.verify(token1)
print(f"\n  Token 1 valid: {result.valid}")

# =============================================================================
# Revoke a Specific Token
# =============================================================================

print("\n🚫 Revoking Token 2...")

registry.revoke_token(
    token=token2,
    reason="Fraudulent action detected",
)

# Try to verify
result1 = verifier.verify(token1)
result2 = verifier.verify(token2)
result3 = verifier.verify(token3)

print(f"  Token 1 valid: {result1.valid}")
print(f"  Token 2 valid: {result2.valid}  ← Revoked!")
print(f"  Token 3 valid: {result3.valid}")

# =============================================================================
# Revoke an Entire Key
# =============================================================================

print("\n🚫 Revoking entire key (agent compromised)...")

registry.revoke_key(
    public_key=agent.public_key,
    reason="Key compromised - employee terminated",
)

# All tokens from this agent are now invalid
result1 = verifier.verify(token1)
result3 = verifier.verify(token3)

print(f"  Token 1 valid: {result1.valid}  ← All revoked!")
print(f"  Token 3 valid: {result3.valid}  ← All revoked!")

# =============================================================================
# Check Revocation Status
# =============================================================================

print("\n📋 Revocation List:")

for record in registry.list_revocations(limit=10):
    print(f"  {record.type}: {record.id[:20]}...")
    print(f"     Reason: {record.reason}")
    print(f"     Time: {record.revoked_at}")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 REVOCATION TYPES:

Token Revocation:
  • Revoke specific signed actions
  • Use case: Fraudulent transaction detected

Key Revocation:
  • Revoke all tokens from a key
  • Use case: Employee terminated, key compromised

Storage Options:
  • MemoryRevocationStore - Dev/testing
  • RedisRevocationStore - Production (fast lookups)
  • Custom store - Implement RevocationStore interface

Best Practices:
  • Always check revocation on verify
  • Include reason for audit trail
  • Use short token expiry + revocation together
""")
