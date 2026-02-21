#!/usr/bin/env python3
"""
01_langchain.py - Why LangChain Agents Need Vouch

See what happens when LangChain tool calls are unsigned vs signed.
Then watch a forged tool call get caught.

Run: pip install vouch-protocol && python 01_langchain.py
"""

from vouch import Signer, Verifier, generate_identity
import json
import copy

# =============================================================================
# PART 1: Without Vouch — LangChain tool calls have no proof of origin
# =============================================================================

print("=" * 60)
print("PART 1: LangChain WITHOUT Vouch")
print("=" * 60)

# A typical LangChain agent makes tool calls like this:
tool_calls = [
    {"tool": "transfer_funds", "args": {"from": "savings", "to": "checking", "amount": 500}},
    {"tool": "check_balance", "args": {"account": "checking"}},
    {"tool": "send_notification", "args": {"to": "user@example.com", "msg": "Transfer complete"}},
]

print("\nAgent executes 3 tool calls:\n")
for call in tool_calls:
    print(f"   {call['tool']}({json.dumps(call['args'])})")

print("""
   Problem: These are just dicts. Anyone can forge them.
   - No proof the agent actually made these calls
   - No way to detect if args were tampered in transit
   - If something goes wrong, who do you blame?
   - A compromised plugin could inject tool calls silently
""")

# =============================================================================
# PART 2: The Risk — A forged tool call looks identical to a real one
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Forged Tool Call")
print("=" * 60)

real_call = {"tool": "transfer_funds", "args": {"from": "savings", "to": "checking", "amount": 500}}
forged_call = {"tool": "transfer_funds", "args": {"from": "savings", "to": "attacker_account", "amount": 50000}}

print(f"\n   Real call:   {json.dumps(real_call)}")
print(f"   Forged call: {json.dumps(forged_call)}")
print(f"\n   Are they distinguishable? Both are plain JSON.")
print(f"   A downstream service has NO WAY to tell them apart.")
print(f"   The attacker changed the recipient and amount — undetected.")

# =============================================================================
# PART 3: With Vouch — Every tool call is cryptographically signed
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 3: LangChain WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="langchain-agent.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   Agent Identity: {signer.get_did()[:50]}...")

signed_calls = []
print("\n   Signing all tool calls:\n")
for call in tool_calls:
    token = signer.sign(call)
    signed_calls.append({"token": token, "tool": call["tool"]})
    print(f"   {call['tool']} → Token: {token[:50]}...")

print("\n   Verifying all tool calls:\n")
for entry in signed_calls:
    is_valid, passport = Verifier.verify(entry["token"], signer.get_public_key_jwk())
    if is_valid and passport:
        tool = passport.payload.get("tool")
        args = passport.payload.get("args", {})
        print(f"   ✅ {tool}({json.dumps(args)}) — signed by {passport.iss[:35]}...")

# =============================================================================
# PART 4: Try the Attack Again — Vouch catches the forgery
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Forgery Detected")
print("=" * 60)

# Take the real signed token and try to use it with tampered data
real_token = signed_calls[0]["token"]

# Attacker tries to verify with a different key (they don't have the real one)
attacker_identity = generate_identity(domain="attacker.evil.com")
attacker_signer = Signer(private_key=attacker_identity.private_key_jwk, did=attacker_identity.did)

# Attacker forges a new token with their own key
forged_token = attacker_signer.sign(forged_call)

print(f"\n   Attacker forges: transfer $50,000 to attacker_account")
print(f"   Forged token: {forged_token[:50]}...")

# The receiving service verifies against the REAL agent's public key
is_valid, passport = Verifier.verify(forged_token, signer.get_public_key_jwk())
print(f"\n   Verify forged token against real agent's key:")
print(f"   Valid? {is_valid}")
if not is_valid:
    print(f"   ❌ REJECTED — signature doesn't match the trusted agent's key")
    print(f"   The $50,000 transfer is blocked. The real agent never signed it.")

# Meanwhile, the real token still verifies
is_valid, passport = Verifier.verify(real_token, signer.get_public_key_jwk())
print(f"\n   Verify real token against real agent's key:")
print(f"   Valid? {is_valid}")
if is_valid and passport:
    print(f"   ✅ ACCEPTED — {passport.payload.get('tool')}({json.dumps(passport.payload.get('args'))}) is authentic")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: Without Vouch, any tool call can be forged.
With Vouch, every call carries cryptographic proof of origin.
Forgeries are detected instantly.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
