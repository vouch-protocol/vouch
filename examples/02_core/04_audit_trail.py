#!/usr/bin/env python3
"""
04_audit_trail.py - Create Audit Trails with Auditor

Issue verifiable credentials for agents and log actions.

Run: python 04_audit_trail.py
"""

from vouch import Signer, Auditor, Verifier, generate_identity
import json

print("📋 Audit Trail with Verifiable Credentials")
print("=" * 50)

# =============================================================================
# Setup Auditor (Certificate Authority)
# =============================================================================

# Create auditor identity (this is the authority that issues certificates)
auditor_id = generate_identity(domain="vouch-authority.com")
auditor = Auditor(
    private_key_json=auditor_id.private_key_jwk,
    issuer_did=auditor_id.did,
)

# Create an agent identity
agent_id = generate_identity(domain="financial-agent.example.com")
agent = Signer(private_key=agent_id.private_key_jwk, did=agent_id.did)

print(f"Auditor DID: {auditor.get_issuer_did()}")
print(f"Agent DID: {agent.get_did()}")

# =============================================================================
# Issue Verifiable Credential
# =============================================================================

print("\n📜 Issuing Verifiable Credential:")

# Issue a vouch certificate for the agent
cert_result = auditor.issue_vouch({
    "did": agent.get_did(),
    "integrity_hash": "sha256:abc123def456",  # Hash of agent code/model
    "reputation_score": 85,  # Agent's trust score
})

certificate = cert_result["certificate"]
print(f"   Certificate: {certificate[:50]}...")
print(f"   Issued by: {auditor.get_issuer_did()}")
print(f"   For agent: {agent.get_did()}")

# =============================================================================
# Log Actions with Signed Tokens
# =============================================================================

print("\n📝 Logging Actions (Audit Trail):")

audit_log = []

# Action 1: Query balance
action1 = {"action": "get_balance", "account": "12345", "timestamp": "2026-01-23T10:00:00Z"}
token1 = agent.sign(action1)
audit_log.append({"token": token1, "metadata": {"ip": "10.0.0.1", "department": "treasury"}})
print("   ✅ get_balance logged")

# Action 2: Transfer funds
action2 = {"action": "transfer", "from": "12345", "to": "67890", "amount": 500}
token2 = agent.sign(action2)
audit_log.append({"token": token2, "metadata": {"ip": "10.0.0.1", "approved_by": "manager@example.com"}})
print("   ✅ transfer logged")

# Action 3: Generate report
action3 = {"action": "generate_report", "type": "monthly_summary"}
token3 = agent.sign(action3)
audit_log.append({"token": token3, "metadata": {"ip": "10.0.0.1"}})
print("   ✅ generate_report logged")

# =============================================================================
# Query Audit Log
# =============================================================================

print("\n📊 Query Audit Log:")

print(f"\n   Total logged events: {len(audit_log)}")

for i, entry in enumerate(audit_log):
    token = entry["token"]
    metadata = entry["metadata"]
    
    # Verify and extract payload
    is_valid, passport = Verifier.verify(token, agent.get_public_key_jwk())
    
    if is_valid and passport:
        action = passport.payload.get("action", "unknown")
        print(f"   [{i+1}] Action: {action}")
        print(f"       Signer: {passport.iss}")
        print(f"       IP: {metadata.get('ip', 'N/A')}")

# =============================================================================
# Export for Compliance
# =============================================================================

print("\n📤 Export for Compliance:")

# Export as JSON (for APIs)
export_data = []
for entry in audit_log:
    is_valid, passport = Verifier.verify(entry["token"], agent.get_public_key_jwk())
    if is_valid and passport:
        export_data.append({
            "action": passport.payload,
            "agent_did": passport.iss,
            "timestamp": passport.iat,
            "metadata": entry["metadata"],
            "signature": entry["token"][:50] + "...",
        })

print(f"   Exported {len(export_data)} events as JSON")
print(f"   Sample: {json.dumps(export_data[0], indent=2)[:200]}...")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 AUDIT TRAIL FEATURES:

What's Logged:
  • Full signed token (unforgeable)
  • Agent DID (identity)
  • Action payload
  • Custom metadata (IP, user, etc.)

Verifiable Credentials:
  • Auditor issues certificates for agents
  • Includes reputation score
  • Includes integrity hash of agent code

Compliance:
  • SOC2 audit trail
  • GDPR action logging
  • Financial regulations
""")
