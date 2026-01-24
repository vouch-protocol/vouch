#!/usr/bin/env python3
"""
02_verify_token.py - Verify Incoming Tokens

Verify Vouch tokens on your API server.

Run: python 02_verify_token.py
"""

from vouch import Signer, Verifier, VerificationError, generate_identity
import json

print("🔍 Verify Tokens")
print("=" * 50)

# =============================================================================
# Setup
# =============================================================================

# Create an identity and signer (simulating a client)
identity = generate_identity(domain="api-client.example.com")
signer = Signer(
    private_key=identity.private_key_jwk,
    did=identity.did,
)

# Sign a request (simulating incoming token)
request_payload = {
    "method": "POST",
    "url": "https://api.bank.com/transfer",
    "body": {"amount": 100},
}
token = signer.sign(request_payload)

# =============================================================================
# Basic Verification
# =============================================================================

print("📥 Received Token:")
print(f"   {token[:50]}...")

# Verify returns (is_valid, passport) tuple
is_valid, passport = Verifier.verify(token, signer.get_public_key_jwk())

print("\n🔍 Verification Result:")
print(f"   Valid: {is_valid}")
if passport:
    print(f"   Signer DID: {passport.iss}")
    print(f"   Payload: {passport.payload}")
    print(f"   Issued At: {passport.iat}")
    print(f"   Expires At: {passport.exp}")

# =============================================================================
# Instance-based Verification with Trusted Roots
# =============================================================================

print("\n🔒 Using Trusted Roots:")

# Create verifier with trusted DIDs
verifier = Verifier(
    trusted_roots={identity.did: signer.get_public_key_jwk()},
    allow_did_resolution=False,  # Only trust explicit roots
)

# Verify using check_vouch (uses trusted roots)
is_valid, passport = verifier.check_vouch(token)
print(f"   Valid with trusted root: {is_valid}")

# =============================================================================
# Access Control Pattern
# =============================================================================

print("\n🔒 Access Control Pattern:")


def verify_and_authorize(token: str, verifier: Verifier, allowed_dids: list) -> dict:
    """Verify token and check if agent is allowed."""
    try:
        is_valid, passport = verifier.check_vouch(token)

        if not is_valid or not passport:
            return {"allowed": False, "error": "Invalid signature"}

        if passport.iss not in allowed_dids:
            return {"allowed": False, "error": "Agent not authorized"}

        return {
            "allowed": True,
            "agent_did": passport.iss,
            "action": passport.payload,
        }

    except VerificationError as e:
        return {"allowed": False, "error": str(e)}


# Check authorization
allowed_dids = [identity.did]  # Whitelist this agent
auth_result = verify_and_authorize(token, verifier, allowed_dids)

print(f"   Allowed: {auth_result['allowed']}")
print(f"   Agent DID: {auth_result.get('agent_did', 'N/A')}")

# =============================================================================
# Handle Errors
# =============================================================================

print("\n❌ Error Handling:")

# Bad token
try:
    is_valid, passport = Verifier.verify("invalid.token.here")
    print(f"   Bad token valid: {is_valid}")
except Exception as e:
    print(f"   Bad token error: {type(e).__name__}")

# Tampered token
tampered = token[:-5] + "XXXXX"
try:
    is_valid, passport = Verifier.verify(tampered, signer.get_public_key_jwk())
    print(f"   Tampered token valid: {is_valid}")
except Exception as e:
    print(f"   Tampered token error: {type(e).__name__}")

print("""
✅ Verification Steps:
   1. Parse token structure (header.payload.signature)
   2. Verify signature with public key
   3. Check expiry if present
   4. (Optional) Check revocation list
   5. (Optional) Check agent allowlist
""")
