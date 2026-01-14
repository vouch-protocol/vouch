#!/usr/bin/env python3
"""
02_key_generation.py - Create and Manage Your Identity

Learn how to:
- Generate a persistent key pair
- Save and load keys
- Use environment variables for keys

Run: python 02_key_generation.py
"""

from vouch import generate_identity, Signer
import os

# =============================================================================
# OPTION 1: Generate a New Identity
# =============================================================================

print("📝 Option 1: Generate a new identity")

identity = generate_identity()
print(f"   Private Key: {identity.private_key[:20]}...")
print(f"   Public Key:  {identity.public_key[:20]}...")

# =============================================================================
# OPTION 2: Use Environment Variable (Recommended for Production)
# =============================================================================

print("\n📝 Option 2: Use environment variable")

# Set this in your shell or .env file:
# export VOUCH_PRIVATE_KEY="your-base64-private-key"

if os.getenv("VOUCH_PRIVATE_KEY"):
    signer = Signer(name="Production Agent")  # Auto-loads from env
    print("   ✅ Loaded key from VOUCH_PRIVATE_KEY")
else:
    print("   ⚠️  VOUCH_PRIVATE_KEY not set, using ephemeral key")

# =============================================================================
# OPTION 3: Save Key to File
# =============================================================================

print("\n📝 Option 3: Save key to file")

# Generate and save
identity = generate_identity()
key_file = "/tmp/vouch_key.txt"
with open(key_file, "w") as f:
    f.write(identity.private_key)

print(f"   ✅ Saved private key to {key_file}")

# Load from file
with open(key_file) as f:
    loaded_key = f.read().strip()

signer = Signer(name="My Agent", private_key=loaded_key)
print("   ✅ Loaded key from file")
print(f"   Public Key: {signer.public_key[:30]}...")

# =============================================================================
# OPTION 4: Multiple Identities
# =============================================================================

print("\n📝 Option 4: Multiple identities")

alice = Signer(name="Alice")
bob = Signer(name="Bob")
charlie = Signer(name="Charlie")

print(f"   Alice's public key:   {alice.public_key[:20]}...")
print(f"   Bob's public key:     {bob.public_key[:20]}...")
print(f"   Charlie's public key: {charlie.public_key[:20]}...")

# Each has a unique cryptographic identity!

print("\n✅ You now know how to manage Vouch identities!")
