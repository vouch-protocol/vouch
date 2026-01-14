#!/usr/bin/env python3
"""
02_verify_token.py - Verify Incoming Tokens

Verify Vouch tokens on your API server.

Run: python 02_verify_token.py
"""

from vouch import Signer, Verifier, VerificationError
import json

print("🔍 Verify Tokens")
print("=" * 50)

# =============================================================================
# Setup
# =============================================================================

# Create a verifier
verifier = Verifier()

# Simulate an incoming token (from previous example)
signer = Signer(name="API Client Agent", email="agent@example.com")
token = signer.sign(
    json.dumps({"method": "POST", "url": "https://api.bank.com/transfer", "body": {"amount": 100}})
)

# =============================================================================
# Basic Verification
# =============================================================================

print("📥 Received Token:")
print(f"   {token[:50]}...")

result = verifier.verify(token)

print("\n🔍 Verification Result:")
print(f"   Valid: {result.valid}")
print(f"   Signer: {result.signer}")
print(f"   Email: {result.email}")
print(f"   Payload: {result.payload[:50]}...")
print(f"   Issued At: {result.issued_at}")
print(f"   Public Key: {result.public_key[:20]}...")

# =============================================================================
# Access Control Pattern
# =============================================================================

print("\n🔒 Access Control Pattern:")


def verify_and_authorize(token: str, allowed_agents: list) -> dict:
    """Verify token and check if agent is allowed."""
    try:
        result = verifier.verify(token)

        if not result.valid:
            return {"allowed": False, "error": "Invalid signature"}

        if result.public_key not in allowed_agents:
            return {"allowed": False, "error": "Agent not authorized"}

        return {
            "allowed": True,
            "agent": result.signer,
            "action": json.loads(result.payload),
        }

    except VerificationError as e:
        return {"allowed": False, "error": str(e)}


# Check authorization
allowed = [signer.public_key]  # Whitelist this agent
auth_result = verify_and_authorize(token, allowed)

print(f"   Allowed: {auth_result['allowed']}")
print(f"   Agent: {auth_result.get('agent', 'N/A')}")

# =============================================================================
# Handle Errors
# =============================================================================

print("\n❌ Error Handling:")

# Bad token
try:
    bad_result = verifier.verify("invalid.token.here")
    print(f"   Bad token: {bad_result.valid}")
except VerificationError as e:
    print(f"   Bad token error: {e}")

# Tampered token
tampered = token[:-5] + "XXXXX"
try:
    result = verifier.verify(tampered)
    print(f"   Tampered token valid: {result.valid}")
except VerificationError as e:
    print(f"   Tampered token error: {e}")

print("""
✅ Verification Steps:
   1. Parse token structure (header.payload.signature)
   2. Verify signature with public key
   3. Check expiry if present
   4. (Optional) Check revocation list
   5. (Optional) Check agent allowlist
""")
