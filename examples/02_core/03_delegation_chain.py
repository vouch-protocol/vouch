#!/usr/bin/env python3
"""
03_delegation_chain.py - Agent-to-Agent Delegation

Allow agents to delegate authority to sub-agents using parent tokens.

Run: python 03_delegation_chain.py
"""

from vouch import Signer, Verifier, generate_identity
import json

print("🔗 Delegation Chain")
print("=" * 50)

# =============================================================================
# Scenario: Human -> Orchestrator -> Worker
# =============================================================================

# Generate identities for each actor
human_id = generate_identity(domain="alice.example.com")
orchestrator_id = generate_identity(domain="orchestrator.example.com")
worker_id = generate_identity(domain="worker.example.com")

# Create signers
human = Signer(private_key=human_id.private_key_jwk, did=human_id.did)
orchestrator = Signer(private_key=orchestrator_id.private_key_jwk, did=orchestrator_id.did)
worker = Signer(private_key=worker_id.private_key_jwk, did=worker_id.did)

print("👥 Chain Participants:")
print(f"   Human: {human.get_did()}")
print(f"   Orchestrator: {orchestrator.get_did()}")
print(f"   Worker: {worker.get_did()}")

# =============================================================================
# Create Delegation Chain
# =============================================================================

print("\n📝 Creating Delegation Chain:")

# Step 1: Human authorizes orchestrator
human_auth = {
    "action": "delegate",
    "delegatee": orchestrator.get_did(),
    "scope": ["database:read", "database:write"],
    "valid_for_hours": 24,
}
human_token = human.sign(human_auth)
print(f"   1. Human → Orchestrator: {human_token[:40]}...")

# Step 2: Orchestrator sub-delegates to worker (with reduced scope)
# Pass human's token as the parent_token for chain building
orchestrator_auth = {
    "action": "sub_delegate",
    "delegatee": worker.get_did(),
    "scope": ["database:read"],  # Worker can only read, not write
    "valid_for_hours": 1,
    "parent_authority": human.get_did(),
}
orchestrator_token = orchestrator.sign(orchestrator_auth, parent_token=human_token)
print(f"   2. Orchestrator → Worker: {orchestrator_token[:40]}...")

# =============================================================================
# Worker Acts with Delegation Chain
# =============================================================================

print("\n⚡ Worker performs action with delegation:")

action = {
    "action": "database:read",
    "query": "SELECT * FROM users WHERE active=true",
    "authorized_by": [human.get_did(), orchestrator.get_did()],
}

# Worker signs their action with the delegation chain
worker_token = worker.sign(action, parent_token=orchestrator_token)

print(f"   Action: {action['action']}")
print(f"   Token: {worker_token[:40]}...")

# =============================================================================
# Verify the Chain
# =============================================================================

print("\n🔍 Verifying Token:")

# Verify the worker's token with their public key
is_valid, passport = Verifier.verify(worker_token, worker.get_public_key_jwk())

print(f"   Valid: {is_valid}")
if passport:
    print(f"   Actor DID: {passport.iss}")
    print(f"   Payload: {json.dumps(passport.payload, indent=6)[:100]}...")
    
    # Check for delegation chain in the vouch claim
    if passport.delegation_chain:
        print(f"   Delegation depth: {len(passport.delegation_chain)}")
        for i, link in enumerate(passport.delegation_chain):
            print(f"     Link {i+1}: {link.iss} → {link.sub}")

# =============================================================================
# Scope Verification Pattern
# =============================================================================

print("\n🔒 Scope Verification Pattern:")


def verify_with_scope(token: str, public_key: str, required_scope: str) -> dict:
    """Verify token and check if action is within authorized scope."""
    is_valid, passport = Verifier.verify(token, public_key)
    
    if not is_valid or not passport:
        return {"allowed": False, "error": "Invalid signature"}
    
    # Check if the action matches authorized scope
    action = passport.payload.get("action", "")
    authorized_by = passport.payload.get("authorized_by", [])
    
    if action == required_scope and len(authorized_by) > 0:
        return {"allowed": True, "action": action, "chain_length": len(authorized_by)}
    
    return {"allowed": False, "error": "Action outside delegated scope"}


# Verify read action (allowed)
result = verify_with_scope(worker_token, worker.get_public_key_jwk(), "database:read")
print(f"   Read action: {result}")

print("""
📝 DELEGATION CHAIN BENEFITS:

Chain of Authority:
   Human → Orchestrator → Worker
   
Scope Limiting:
   Each delegation can reduce scope (write → read only)
   
Auditability:
   Full chain of DIDs recorded in token
   
Parent Token:
   Use parent_token parameter to build chains
""")
