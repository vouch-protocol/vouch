#!/usr/bin/env python3
"""
05_n8n.py - Why n8n Workflows Need Vouch

See what happens when workflow node outputs are unsigned vs signed.
Then watch a tampered payload get caught between nodes.

Run: pip install vouch-protocol && python 05_n8n.py
"""

from vouch import Signer, Verifier, generate_identity
import json

# =============================================================================
# PART 1: Without Vouch — Workflow data passes between nodes unsigned
# =============================================================================

print("=" * 60)
print("PART 1: n8n Workflow WITHOUT Vouch")
print("=" * 60)

# A typical n8n financial workflow: Webhook → Process → Transfer → Notify
workflow_nodes = [
    {"node": "Webhook Trigger", "output": {"customer_id": "C-1234", "request": "transfer", "amount": 500}},
    {"node": "Validation", "output": {"customer_id": "C-1234", "validated": True, "amount": 500}},
    {"node": "Bank API", "output": {"tx_id": "TXN-001", "amount": 500, "status": "completed"}},
    {"node": "Slack Notify", "output": {"channel": "#alerts", "message": "Transfer $500 for C-1234"}},
]

print("\n4-node financial workflow:\n")
for node in workflow_nodes:
    print(f"   [{node['node']}] → {json.dumps(node['output'])}")

print("""
   Problem: Data flows between nodes as plain JSON.
   - If a node is compromised, it can alter data silently
   - No proof that the Webhook actually received $500 (not $50,000)
   - The Bank API node trusts whatever the Validation node sent
   - Audit logs can be edited after the fact
""")

# =============================================================================
# PART 2: The Risk — Data tampered between nodes
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Payload Tampering Between Nodes")
print("=" * 60)

print("""
   Scenario: The Validation node is compromised. It receives a $500
   transfer request but forwards $50,000 to the Bank API:

   Webhook says:     amount: 500
   Validation passes: amount: 50000  ← tampered!
   Bank API executes: $50,000 transfer

   The Slack notification still says "$500" because it reads from
   the original webhook data. Nobody notices until reconciliation.
""")

tampered_output = {"customer_id": "C-1234", "validated": True, "amount": 50000}
print(f"   Tampered payload: {json.dumps(tampered_output)}")
print(f"   Original payload: {json.dumps(workflow_nodes[0]['output'])}")
print(f"\n   The Bank API has no way to verify the amount wasn't changed.")

# =============================================================================
# PART 3: With Vouch — Each node signs its output
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 3: n8n Workflow WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="n8n-workflow.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   Workflow Identity: {signer.get_did()[:50]}...")

signed_nodes = []
print("\n   Each node signs its output:\n")
for node in workflow_nodes:
    payload = {
        "workflow_id": "wf_finance_001",
        "node": node["node"],
        "output": node["output"],
    }
    token = signer.sign(payload)
    signed_nodes.append({"token": token, "node": node["node"]})
    print(f"   [{node['node']}] → Token: {token[:45]}...")

print("\n   Verify workflow audit trail:\n")
for entry in signed_nodes:
    is_valid, passport = Verifier.verify(entry["token"], signer.get_public_key_jwk())
    if is_valid and passport:
        node = passport.payload.get("node")
        output = passport.payload.get("output", {})
        amount = output.get("amount", output.get("message", "N/A"))
        print(f"   ✅ [{node}] amount/msg={amount} — signed by {passport.iss[:30]}...")

# =============================================================================
# PART 4: Try the Attack Again — Tampered payload detected
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Tampering Detected")
print("=" * 60)

# The Webhook signed the original payload with amount=500
webhook_token = signed_nodes[0]["token"]

# Verify what the Webhook actually signed
is_valid, passport = Verifier.verify(webhook_token, signer.get_public_key_jwk())
if is_valid and passport:
    original_amount = passport.payload["output"]["amount"]
    print(f"\n   Webhook signed amount: ${original_amount}")

# Now the compromised Validation node tries to forward amount=50000
# But the Bank API can check the Webhook's signed token
print(f"   Validation claims amount: $50000")
print(f"\n   Bank API verifies Webhook's signed token:")
print(f"   Webhook signed ${original_amount} ≠ Validation claims $50000")
print(f"   ❌ MISMATCH DETECTED — the amount was tampered after the Webhook")
print(f"   Transfer blocked. Incident flagged for review.")

# If the attacker tries to forge a new Webhook token with $50000
attacker_identity = generate_identity(domain="compromised-node.evil.com")
attacker_signer = Signer(private_key=attacker_identity.private_key_jwk, did=attacker_identity.did)

forged_token = attacker_signer.sign({
    "workflow_id": "wf_finance_001",
    "node": "Webhook Trigger",
    "output": {"customer_id": "C-1234", "request": "transfer", "amount": 50000},
})

print(f"\n   Attacker forges a new Webhook token with $50,000...")
is_valid, _ = Verifier.verify(forged_token, signer.get_public_key_jwk())
print(f"   Valid against workflow's trusted key? {is_valid}")
if not is_valid:
    print(f"   ❌ REJECTED — signature doesn't match the workflow's identity")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: n8n workflows pass data between nodes on trust.
Without Vouch, a compromised node can alter amounts, recipients,
or any data — and downstream nodes can't detect the change.
With Vouch, each node's output is signed. Downstream nodes verify
the signed original before acting. Tampering is caught instantly.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
