#!/usr/bin/env python3
"""
03_delegation_chain.py - Agent-to-Agent Delegation

Allow agents to delegate authority to sub-agents.

Run: python 03_delegation_chain.py
"""

from vouch import Signer, Verifier, DelegationLink
import json

print("🔗 Delegation Chain")
print("=" * 50)

# =============================================================================
# Scenario: Human -> Orchestrator -> Worker
# =============================================================================

# Human approves an orchestrator
human = Signer(name="Alice (Human)")

# Orchestrator manages tasks
orchestrator = Signer(name="Task Orchestrator")

# Worker does the actual work
worker = Signer(name="Database Worker")

print("👥 Chain:")
print(f"   Human: {human.public_key[:20]}...")
print(f"   Orchestrator: {orchestrator.public_key[:20]}...")
print(f"   Worker: {worker.public_key[:20]}...")

# =============================================================================
# Create Delegation Chain
# =============================================================================

print("\n📝 Creating Delegation Chain:")

# Human delegates to orchestrator
delegation1 = human.delegate(
    to=orchestrator.public_key,
    scope=["database:read", "database:write"],
    expires_in_hours=24,
)
print(f"   Human → Orchestrator: {delegation1[:40]}...")

# Orchestrator delegates to worker (with reduced scope)
delegation2 = orchestrator.delegate(
    to=worker.public_key,
    scope=["database:read"],  # Worker can only read, not write
    expires_in_hours=1,
    parent_delegation=delegation1,  # Chain it
)
print(f"   Orchestrator → Worker: {delegation2[:40]}...")

# =============================================================================
# Worker Acts
# =============================================================================

print("\n⚡ Worker performs action:")

action = {
    "action": "database:read",
    "query": "SELECT * FROM users",
}

# Worker signs with delegation chain
worker_token = worker.sign(
    payload=json.dumps(action),
    delegation_chain=[delegation1, delegation2],
)

print(f"   Action: {action['action']}")
print(f"   Token: {worker_token[:40]}...")

# =============================================================================
# Verify the Chain
# =============================================================================

print("\n🔍 Verifying Chain:")

verifier = Verifier()
result = verifier.verify(worker_token)

print(f"   Valid: {result.valid}")
print(f"   Actor: {result.signer}")
print(f"   Delegation depth: {len(result.delegation_chain)}")
print(f"   Root authority: {result.root_delegate}")

# Check if action is within delegated scope
if "database:read" in result.delegated_scope:
    print("   ✅ Action within delegated scope")
else:
    print("   ❌ Action outside delegated scope")

# =============================================================================
# Delegation Violation
# =============================================================================

print("\n🚫 Scope Violation Example:")

# Worker tries to write (not allowed in their delegation)
bad_action = {
    "action": "database:write",  # Not allowed!
    "query": "DELETE FROM users",
}

print(f"   Worker trying: {bad_action['action']}")
print(f"   Delegated scope: database:read only")
print(f"   ❌ Server should reject this action")

print("""
📝 DELEGATION BENEFITS:

Chain of Authority:
   Human → Orchestrator → Worker
   
Scope Limiting:
   Each delegation can reduce scope
   
Expiry:
   Short-lived delegations for security
   
Auditability:
   Full chain recorded in token
""")
