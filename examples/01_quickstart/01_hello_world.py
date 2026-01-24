#!/usr/bin/env python3
"""
01_hello_world.py - Your First Vouch Signature

This is the simplest possible example of Vouch Protocol.
Sign and verify your first message using cryptographic identity.

Run: python 01_hello_world.py
"""

from vouch import Signer, Verifier, generate_identity

# 1. Generate a new identity (Ed25519 keypair)
identity = generate_identity(domain="example.com")
print(f"🔑 Generated identity with DID: {identity.did}")

# 2. Create a signer with the identity
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

# 3. Sign a payload (must be a dict for JWT claims)
payload = {"action": "greet", "message": "Hello from Vouch Protocol!"}
signed_token = signer.sign(payload)

print(f"\n✅ Signed payload: {payload}")
print(f"📝 Token: {signed_token[:80]}...")

# 4. Verify the signature
# verify() returns (is_valid, passport) tuple
is_valid, passport = Verifier.verify(signed_token, signer.get_public_key_jwk())

print("\n🔍 Verification result:")
print(f"   Valid: {is_valid}")
if passport:
    print(f"   Signer DID: {passport.iss}")
    print(f"   Payload: {passport.payload}")

print("""
That's it! You've:
✅ Generated a cryptographic identity (Ed25519)
✅ Signed a payload as a JWT (JWS)
✅ Verified the signature is authentic
""")
