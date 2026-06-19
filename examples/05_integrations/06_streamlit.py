#!/usr/bin/env python3
"""
06_streamlit.py - Why Streamlit AI Dashboards Need Vouch

See what happens when AI dashboard actions are unsigned vs signed.
Then watch a falsified AI response get caught.

Run: pip install vouch-protocol && python 06_streamlit.py
"""

from vouch import Signer, Verifier, generate_identity
import json

# =============================================================================
# PART 1: Without Vouch — Dashboard actions have no verifiable record
# =============================================================================

print("=" * 60)
print("PART 1: Streamlit Dashboard WITHOUT Vouch")
print("=" * 60)

# A typical AI-powered dashboard session
session_log = [
    {"action": "query", "user": "alice@corp.com", "input": "What's our Q3 revenue forecast?"},
    {"action": "ai_response", "model": "gpt-4", "output": "Q3 forecast: $12.5M based on pipeline"},
    {"action": "export", "user": "alice@corp.com", "format": "csv", "rows": 1250},
]

print("\nDashboard session with AI:\n")
for entry in session_log:
    if entry["action"] == "query":
        print(f'   [User Query] "{entry["input"]}"')
    elif entry["action"] == "ai_response":
        print(f'   [AI Response] "{entry["output"]}"')
    elif entry["action"] == "export":
        print(f"   [Data Export] {entry['rows']} rows as {entry['format']}")

print("""
   Problem: The session log is just an array of dicts.
   - If the AI said "$12.5M" but someone later claims it said "$20M", who's right?
   - The export could be modified after download — no integrity proof
   - Session logs are mutable — anyone with DB access can edit them
   - For regulated industries (finance, healthcare), this is a compliance gap
""")

# =============================================================================
# PART 2: The Risk — AI response is falsified after the fact
# =============================================================================

print("=" * 60)
print("PART 2: The Risk — Falsified AI Response")
print("=" * 60)

print("""
   Scenario: The AI forecast said "$12.5M". A trader makes decisions
   based on this. The trade goes wrong. The trader edits the session
   log to make it look like the AI said "$20M" — shifting blame to
   the AI system.

   Original log entry:
     {"action": "ai_response", "output": "Q3 forecast: $12.5M"}

   Falsified log entry:
     {"action": "ai_response", "output": "Q3 forecast: $20M"}
""")

original = {"action": "ai_response", "output": "Q3 forecast: $12.5M based on pipeline"}
falsified = {"action": "ai_response", "output": "Q3 forecast: $20M based on pipeline"}
print(f"   Original: {json.dumps(original)}")
print(f"   Falsified: {json.dumps(falsified)}")
print("\n   Both are plain JSON. In a dispute, there's no way to prove")
print("   which version is authentic. The AI can't defend itself.")

# =============================================================================
# PART 3: With Vouch — Every dashboard action is signed
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 3: Streamlit Dashboard WITH Vouch")
print("=" * 60)

identity = generate_identity(domain="streamlit-dashboard.example.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"\n   Dashboard Identity: {signer.get_did()[:50]}...")

audit_log = []
print("\n   Signing all session actions:\n")

# Sign user query
query_payload = {
    "action": "query",
    "user": "alice@corp.com",
    "input": "What's our Q3 revenue forecast?",
}
query_token = signer.sign(query_payload)
audit_log.append(("User Query", query_token))
print(f"   [Query] → Token: {query_token[:45]}...")

# Sign AI response
response_payload = {
    "action": "ai_response",
    "model": "gpt-4",
    "output": "Q3 forecast: $12.5M based on pipeline",
    "confidence": 0.87,
}
response_token = signer.sign(response_payload)
audit_log.append(("AI Response", response_token))
print(f"   [AI Response] → Token: {response_token[:45]}...")

# Sign data export
export_payload = {"action": "export", "user": "alice@corp.com", "format": "csv", "rows": 1250}
export_token = signer.sign(export_payload)
audit_log.append(("Data Export", export_token))
print(f"   [Export] → Token: {export_token[:45]}...")

print("\n   Verify session audit log:\n")
for label, token in audit_log:
    is_valid, passport = Verifier.verify(token, signer.get_public_key_jwk())
    if is_valid and passport:
        action = passport.payload.get("action")
        print(f"   ✅ {label}: action={action} | DID={passport.iss[:30]}...")

# =============================================================================
# PART 4: Try the Attack Again — Falsified response is caught
# =============================================================================

print(f"\n{'=' * 60}")
print("PART 4: Attack Defeated — Falsification Detected")
print("=" * 60)

# The signed AI response token contains the ORIGINAL output
is_valid, passport = Verifier.verify(response_token, signer.get_public_key_jwk())
if is_valid and passport:
    signed_output = passport.payload.get("output")
    print(f'\n   Signed AI response: "{signed_output}"')
    print('   Trader claims AI said: "Q3 forecast: $20M based on pipeline"')
    print("\n   The cryptographic record proves the AI said $12.5M, not $20M.")
    print("   The token is immutable — it can't be edited without invalidating")
    print("   the signature. The trader's falsification attempt fails.")

# Can the trader forge a new token with $20M?
attacker_identity = generate_identity(domain="trader-laptop.local")
attacker_signer = Signer(private_key=attacker_identity.private_key_jwk, did=attacker_identity.did)

forged_token = attacker_signer.sign(
    {
        "action": "ai_response",
        "model": "gpt-4",
        "output": "Q3 forecast: $20M based on pipeline",
    }
)

print("\n   Trader forges a new token with $20M...")
is_valid, _ = Verifier.verify(forged_token, signer.get_public_key_jwk())
print(f"   Valid against dashboard's trusted key? {is_valid}")
if not is_valid:
    print("   ❌ REJECTED — not signed by the dashboard's identity")
    print("   The original $12.5M response stands as the authentic record.")

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAKEAWAY: AI dashboards generate advice that drives decisions.
Without Vouch, session logs can be edited to shift blame.
With Vouch, every query, response, and export carries an
immutable cryptographic signature. What the AI actually said
is provable — protecting both users and the AI system.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
