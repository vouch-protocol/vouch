#!/usr/bin/env python3
"""
01_hello_world.py - Your First Vouch Credential

The simplest possible example of Vouch Protocol v1.0: sign an action as a W3C
Verifiable Credential with a Data Integrity proof (eddsa-jcs-2022), then verify
it. This is the modern credential path; new code should use it.

Run: python 01_hello_world.py
"""

import vouch

# An Agent bundles a fresh identity with its signer, so there is one object to
# pass around. The intent binds the action to a concrete resource; every Vouch
# credential requires action, target, and resource.
agent = vouch.Agent("example.com")
print(f"🔑 Generated identity with DID: {agent.did}")

signed = agent.sign(
    action="greet",
    target="world",
    resource="https://example.com/greetings",
)
print(f"\n✅ Signed a Verifiable Credential (cryptosuite: {signed['proof']['cryptosuite']})")

# The agent knows its own key, so verifying its own credential needs no key
# argument. verify returns (is_valid, passport).
is_valid, passport = agent.verify(signed)

print("\n🔍 Verification result:")
print(f"   Valid: {is_valid}")
if passport:
    print(f"   Issuer DID: {passport.issuer}")
    print(
        f"   Action / target / resource: "
        f"{passport.action} / {passport.target} / {passport.resource}"
    )

# No-class path: the same flow with module-level one-liners and a plain keypair.
keys = vouch.generate_identity("example.com")
signed2 = vouch.sign(keys, action="greet", target="world", resource="https://example.com/greetings")
ok2, who2 = vouch.verify(signed2, keys.public_key_jwk)
print(f"\n🔁 One-liner path valid: {ok2} (issuer {who2.issuer})")

print("""
That's it! You've:
✅ Generated a cryptographic identity (Ed25519)
✅ Signed an action as a W3C Verifiable Credential with a Data Integrity proof (eddsa-jcs-2022)
✅ Verified the credential is authentic
""")
