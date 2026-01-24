#!/usr/bin/env python3
"""
03_revocation.py - Key and Token Revocation

Revoke compromised keys or specific tokens.

Run: python 03_revocation.py
"""

from vouch import (
    Signer,
    Verifier,
    generate_identity,
    RevocationRecord,
    MemoryRevocationStore,
)
import asyncio
import time

print("🚫 Revocation")
print("=" * 50)


async def main():
    # =============================================================================
    # Setup
    # =============================================================================
    
    # Create revocation store
    store = MemoryRevocationStore()
    
    # Create an agent
    agent_id = generate_identity(domain="compromised-agent.example.com")
    agent = Signer(private_key=agent_id.private_key_jwk, did=agent_id.did)
    
    print(f"Agent DID: {agent.get_did()}")
    
    # =============================================================================
    # Sign Some Tokens
    # =============================================================================
    
    print("\n📝 Signing tokens...")
    
    token1 = agent.sign({"action": "Action 1"})
    token2 = agent.sign({"action": "Action 2"})
    token3 = agent.sign({"action": "Action 3"})
    
    print(f"  Token 1: {token1[:40]}...")
    print(f"  Token 2: {token2[:40]}...")
    print(f"  Token 3: {token3[:40]}...")
    
    # Verify they work
    is_valid, passport = Verifier.verify(token1, agent.get_public_key_jwk())
    print(f"\n  Token 1 valid: {is_valid}")
    
    # =============================================================================
    # Revoke the Agent's Key
    # =============================================================================
    
    print("\n🚫 Revoking agent's key...")
    
    # Create revocation record
    record = RevocationRecord(
        did=agent.get_did(),
        revoked_at=int(time.time()),
        reason="Key compromised - security incident"
    )
    
    await store.add_revocation(record)
    print(f"   Revoked: {agent.get_did()}")
    print(f"   Reason: {record.reason}")
    
    # =============================================================================
    # Check Revocation Status
    # =============================================================================
    
    print("\n🔍 Checking revocation status:")
    
    is_revoked = await store.is_revoked(agent.get_did())
    print(f"   Is {agent.get_did()} revoked? {is_revoked}")
    
    # Get revocation details
    revocation = await store.get_revocation(agent.get_did())
    if revocation:
        print(f"   Revoked at: {revocation.revoked_at}")
        print(f"   Reason: {revocation.reason}")
    
    # =============================================================================
    # Verification with Revocation Check
    # =============================================================================
    
    print("\n🔒 Verification with revocation check:")
    
    async def verify_with_revocation(token: str, public_key: str, store: MemoryRevocationStore):
        """Verify token and check if the signer is revoked."""
        # First verify the signature
        is_valid, passport = Verifier.verify(token, public_key)
        
        if not is_valid or not passport:
            return {"valid": False, "reason": "Invalid signature"}
        
        # Then check if the signer is revoked
        is_revoked = await store.is_revoked(passport.iss)
        
        if is_revoked:
            return {"valid": False, "reason": "Signer key has been revoked"}
        
        return {"valid": True, "payload": passport.payload}
    
    # Try to verify tokens from revoked agent
    result = await verify_with_revocation(token1, agent.get_public_key_jwk(), store)
    print(f"   Token 1: {result}")
    
    result = await verify_with_revocation(token3, agent.get_public_key_jwk(), store)
    print(f"   Token 3: {result}")
    
    # =============================================================================
    # Remove Revocation (Reinstate)
    # =============================================================================
    
    print("\n♻️ Reinstating key:")
    
    removed = await store.remove_revocation(agent.get_did())
    print(f"   Removed revocation: {removed}")
    
    is_revoked = await store.is_revoked(agent.get_did())
    print(f"   Is revoked after reinstatement? {is_revoked}")
    
    # =============================================================================
    # List All Revocations
    # =============================================================================
    
    print("\n📋 All Revocations:")
    
    # Add some more revocations for demo
    await store.add_revocation(RevocationRecord(
        did="did:web:bad-actor.com",
        revoked_at=int(time.time()),
        reason="Malicious behavior"
    ))
    
    revocations = await store.list_revocations()
    for rev in revocations:
        print(f"   {rev.did}: {rev.reason}")
    
    print("""
📝 REVOCATION TYPES:

Key Revocation:
  • Revoke all tokens from a DID
  • Use case: Key compromised, employee terminated

Storage Options:
  • MemoryRevocationStore - Dev/testing
  • RedisRevocationStore - Production (fast lookups)

Best Practices:
  • Always check revocation on verify
  • Include reason for audit trail
  • Use short token expiry + revocation together
""")


if __name__ == "__main__":
    asyncio.run(main())
