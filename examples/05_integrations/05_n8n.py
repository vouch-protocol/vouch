#!/usr/bin/env python3
"""
05_n8n.py - Vouch with n8n Workflow Automation

Sign n8n webhook and workflow actions.

Run: python 05_n8n.py
"""

from vouch import Signer, Verifier
import json

print("⚡ n8n + Vouch")
print("=" * 50)

# =============================================================================
# n8n Webhook Integration
# =============================================================================

signer = Signer(name="n8n Workflow")

# Simulate n8n webhook payload
webhook_data = {
    "workflow_id": "wf_abc123",
    "node": "HTTP Request",
    "action": "POST https://api.bank.com/transfer",
    "payload": {"amount": 500, "to": "account_xyz"},
}

# Sign the webhook data
token = signer.sign(json.dumps(webhook_data))

print("📤 Signed Webhook:")
print(f"   Workflow: {webhook_data['workflow_id']}")
print(f"   Action: {webhook_data['action']}")
print(f"   Token: {token[:60]}...")

# =============================================================================
# n8n Custom Node
# =============================================================================

print("""
\n📦 n8n Custom Node Integration:

// In your n8n custom node
const { Vouch } = require('@vouch-protocol/core');

const signer = new Vouch.Signer({
    name: 'n8n Workflow',
    privateKey: process.env.VOUCH_PRIVATE_KEY
});

// Before executing HTTP request
const signedPayload = signer.sign({
    workflow: this.getWorkflowId(),
    node: this.name,
    action: requestOptions,
    timestamp: new Date().toISOString()
});

// Add to headers
requestOptions.headers['X-Vouch-Token'] = signedPayload;
""")

# =============================================================================
# Verification on Receiving End
# =============================================================================

print("\n🔍 Receiving End Verification:")

verifier = Verifier()
result = verifier.verify(token)

print(f"   Valid: {result.valid}")
print(f"   Signer: {result.signer}")
print(f"   Payload: {json.loads(result.payload)['action']}")

print("""
✅ n8n Workflow Benefits:
   • Every HTTP request is signed
   • Webhook callbacks are verifiable
   • Audit trail for all node executions
   • Integration with Vouch ecosystem
""")
