#!/usr/bin/env python3
"""
01_hello_world.py - Your First Vouch Credential

The simplest possible example of Vouch Protocol. Issue and verify your
first credential using cryptographic identity.

This uses the modern v1.0 path: a W3C Verifiable Credential with a Data
Integrity proof (cryptosuite eddsa-jcs-2022). It is human-readable JSON,
not a JWT/JWS. For the legacy v0.x JWS "Vouch-Token" path, see
02_core/01_sign_request.py.

Run: python 01_hello_world.py
"""

from vouch import Signer, Verifier, generate_identity

# 1. Generate a new identity (Ed25519 keypair)
identity = generate_identity(domain="example.com")
print(f"🔑 Generated identity with DID: {identity.did}")

# 2. Create a signer with the identity
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

# 3. Issue a credential for an intent.
#    action, target, and resource are required in v1.0; the resource
#    binding is what prevents confused-deputy attacks.
intent = {
    "action": "greet",
    "target": "world",
    "resource": "https://example.com/greetings",
}
credential = signer.sign_credential(intent=intent)

print("\n✅ Issued a Vouch credential (Verifiable Credential 2.0 + Data Integrity)")
print(f"📝 cryptosuite: {credential['proof']['cryptosuite']}")

# 4. Verify the credential.
#    verify_credential() accepts an Ed25519PublicKey, a Multikey string,
#    or a JWK (string or dict). It returns (is_valid, passport).
is_valid, passport = Verifier.verify_credential(credential, public_key=signer.get_public_key_jwk())

print("\n🔍 Verification result:")
print(f"   Valid: {is_valid}")
if passport:
    print(f"   Issuer DID: {passport.iss}")
    print(f"   Intent: {passport.intent}")

print("""
That's it! You've:
✅ Generated a cryptographic identity (Ed25519)
✅ Issued a signed Verifiable Credential (eddsa-jcs-2022, not a JWT)
✅ Verified the credential is authentic
""")
