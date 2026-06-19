#!/usr/bin/env python3
"""
01_hello_world.py - Your First Vouch Credential

The simplest possible example of Vouch Protocol v1.0: sign an action as a W3C
Verifiable Credential with a Data Integrity proof (eddsa-jcs-2022), then verify
it. This is the modern credential path; new code should use it.

Run: python 01_hello_world.py
"""

from vouch import Signer, Verifier, generate_identity

# 1. Generate a new identity (Ed25519 keypair).
identity = generate_identity(domain="example.com")
print(f"🔑 Generated identity with DID: {identity.did}")

# 2. Create a signer with the identity.
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

# 3. Sign an action as a Verifiable Credential. The intent binds the action to a
#    concrete resource; every Vouch credential requires action, target, and resource.
signed = signer.sign_credential(
    intent={
        "action": "greet",
        "target": "world",
        "resource": "https://example.com/greetings",
    }
)
print(f"\n✅ Signed a Verifiable Credential (cryptosuite: {signed['proof']['cryptosuite']})")

# 4. Verify the credential. verify_credential returns (is_valid, passport).
is_valid, passport = Verifier.verify_credential(signed, public_key=identity.public_key_jwk)

print("\n🔍 Verification result:")
print(f"   Valid: {is_valid}")
if passport:
    print(f"   Issuer DID: {passport.iss}")
    print(f"   Intent: {passport.intent}")

print("""
That's it! You've:
✅ Generated a cryptographic identity (Ed25519)
✅ Signed an action as a W3C Verifiable Credential with a Data Integrity proof (eddsa-jcs-2022)
✅ Verified the credential is authentic
""")
