#!/usr/bin/env python3
"""
09_google_adk.py - Vouch with Google Agent Development Kit

Sign ADK agent actions for Gemini-powered agents.

Run: pip install google-adk && python 09_google_adk.py
"""

from vouch import Signer

print("🎯 Google ADK + Vouch")
print("=" * 50)

# =============================================================================
# ADK Agent with Vouch
# =============================================================================

print("""
from google.adk import Agent, Tool
from vouch.integrations.adk import VouchADKAgent

# Create agent with Vouch signing
agent = VouchADKAgent(
    name="Banking Assistant",
    signer=Signer(name="ADK Banking Agent"),
    model="gemini-2.0-flash",
)

# Define tools - all calls will be signed
@agent.tool
def transfer_funds(from_account: str, to_account: str, amount: float) -> str:
    '''Transfer funds between accounts.'''
    return f"Transferred ${amount}"

@agent.tool
def check_balance(account: str) -> float:
    '''Check account balance.'''
    return 1000.00

# Run agent - all tool calls signed
response = agent.run("Transfer $100 from checking to savings")

# Access audit log
for action in agent.get_signed_actions():
    print(f"Signed: {action.tool_name} at {action.timestamp}")
""")

# =============================================================================
# Demo
# =============================================================================

signer = Signer(name="ADK Banking Agent")

# Simulate ADK tool call
tool_call = {
    "agent": "Banking Assistant",
    "tool": "transfer_funds",
    "args": {"from_account": "checking", "to_account": "savings", "amount": 100},
    "model": "gemini-2.0-flash",
}

import json

token = signer.sign(json.dumps(tool_call))

print("\n📋 Signed ADK Tool Call:")
print(f"   Agent: {tool_call['agent']}")
print(f"   Tool: {tool_call['tool']}")
print(f"   Amount: ${tool_call['args']['amount']}")
print(f"   Token: {token[:50]}...")

# Verify
from vouch import Verifier

verifier = Verifier()
result = verifier.verify(token)
print(f"\n   ✅ Verified: {result.valid}")
print(f"   Signer: {result.signer}")

print("""
✅ Google ADK Benefits:
   • Native Gemini 2.0 support
   • All tool calls signed
   • Built for Google Cloud
   • Enterprise audit trail
""")
