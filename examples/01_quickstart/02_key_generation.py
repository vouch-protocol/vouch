#!/usr/bin/env python3
"""
02_key_generation.py - Create and Manage Your Identity

Learn how to:
- Generate a persistent key pair
- Save and load keys
- Use the KeyManager for secure storage

Run: python 02_key_generation.py
"""

from vouch import generate_identity, Signer, KeyPair
from vouch.keys import KeyManager
import os
import tempfile

# =============================================================================
# OPTION 1: Generate a New Identity
# =============================================================================

print("📝 Option 1: Generate a new identity")

identity = generate_identity(domain="example.com")
print(f"   DID: {identity.did}")
print(f"   Private Key (JWK): {identity.private_key_jwk[:40]}...")
print(f"   Public Key (JWK):  {identity.public_key_jwk[:40]}...")

# =============================================================================
# OPTION 2: Create Signer from Generated Identity
# =============================================================================

print("\n📝 Option 2: Use identity with Signer")

signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
print(f"   ✅ Created signer for DID: {signer.get_did()}")

# Sign something
token = signer.sign({"action": "test"})
print(f"   📝 Signed token: {token[:50]}...")

# =============================================================================
# OPTION 3: Save Key to File (Simple)
# =============================================================================

print("\n📝 Option 3: Save key to file (simple)")

# Generate and save
new_identity = generate_identity(domain="my-agent.example.com")
key_file = os.path.join(tempfile.gettempdir(), "vouch_key.json")

with open(key_file, "w") as f:
    import json

    json.dump(
        {
            "did": new_identity.did,
            "private_key_jwk": new_identity.private_key_jwk,
            "public_key_jwk": new_identity.public_key_jwk,
        },
        f,
    )

print(f"   ✅ Saved identity to {key_file}")

# Load from file
with open(key_file) as f:
    loaded_data = json.load(f)

loaded_signer = Signer(private_key=loaded_data["private_key_jwk"], did=loaded_data["did"])
print(f"   ✅ Loaded signer for DID: {loaded_signer.get_did()}")

# Clean up
os.remove(key_file)

# =============================================================================
# OPTION 4: Using KeyManager (Encrypted Storage)
# =============================================================================

print("\n📝 Option 4: Using KeyManager for secure storage")

# Create a temp directory for keys
temp_key_dir = os.path.join(tempfile.gettempdir(), "vouch_keys_demo")
os.makedirs(temp_key_dir, exist_ok=True)

manager = KeyManager(key_dir=temp_key_dir)

# Generate and save an identity
agent_identity = generate_identity(domain="secure-agent.example.com")
agent_identity = KeyPair(
    private_key_jwk=agent_identity.private_key_jwk,
    public_key_jwk=agent_identity.public_key_jwk,
    did=agent_identity.did,
)

# Save with encryption (password protected)
manager.save_identity(agent_identity, password="demo-password-123")
print(f"   ✅ Saved encrypted identity: {agent_identity.did}")

# Load with password
loaded_identity = manager.load_identity(agent_identity.did, password="demo-password-123")
print(f"   ✅ Loaded encrypted identity: {loaded_identity.did}")

# List all identities
identities = manager.list_identities()
print(f"   📋 Stored identities: {len(identities)}")

# Clean up
import shutil

shutil.rmtree(temp_key_dir, ignore_errors=True)

# =============================================================================
# OPTION 5: Multiple Identities
# =============================================================================

print("\n📝 Option 5: Multiple identities")

alice = generate_identity(domain="alice.example.com")
bob = generate_identity(domain="bob.example.com")
charlie = generate_identity(domain="charlie.example.com")

print(f"   Alice DID:   {alice.did}")
print(f"   Bob DID:     {bob.did}")
print(f"   Charlie DID: {charlie.did}")

# Each has a unique cryptographic identity!

print("\n✅ You now know how to manage Vouch identities!")
