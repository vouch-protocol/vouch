#!/usr/bin/env python3
"""
01_hello_world.py - Your First Vouch Signature

This is the simplest possible example of Vouch Protocol.
In just 10 lines, you'll sign and verify your first message.

Run: python 01_hello_world.py
"""

from vouch import Signer, Verifier

# 1. Create a signer (generates a new key pair automatically)
signer = Signer(name="Alice")

# 2. Sign a message
message = "Hello from Vouch Protocol!"
signed_token = signer.sign(message)

print(f"✅ Signed message: {message}")
print(f"📝 Token: {signed_token[:80]}...")

# 3. Verify the signature
verifier = Verifier()
result = verifier.verify(signed_token)

print(f"\n🔍 Verification result:")
print(f"   Valid: {result.valid}")
print(f"   Signer: {result.signer}")
print(f"   Message: {result.payload}")

# That's it! You've:
# ✅ Created a cryptographic identity
# ✅ Signed a message with Ed25519
# ✅ Verified the signature is authentic
