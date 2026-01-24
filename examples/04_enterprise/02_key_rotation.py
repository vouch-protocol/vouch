#!/usr/bin/env python3
"""
02_key_rotation.py - Automatic Key Rotation

Rotate signing keys automatically for security.

Run: python 02_key_rotation.py
"""

from vouch import RotatingKeyProvider, KeyConfig, Signer, generate_identity

print("🔄 Key Rotation")
print("=" * 50)

# =============================================================================
# Setup Keys
# =============================================================================

print("\n🔑 Generating keys for rotation...")

# Generate multiple keys for rotation
key1_identity = generate_identity(domain="agent.example.com")
key2_identity = generate_identity(domain="agent.example.com")

# Create KeyConfig objects
key1 = KeyConfig(
    private_key_jwk=key1_identity.private_key_jwk,
    did=key1_identity.did,
    key_id="key-2026-q1",
)

key2 = KeyConfig(
    private_key_jwk=key2_identity.private_key_jwk,
    did=key2_identity.did,
    key_id="key-2026-q2",
)

print(f"   Key 1 ID: {key1.key_id}")
print(f"   Key 2 ID: {key2.key_id}")
print(f"   DID: {key1.did}")

# =============================================================================
# Create Rotating Key Provider
# =============================================================================

print("\n🔄 Setting up rotation...")

# Create rotating key provider with multiple keys
provider = RotatingKeyProvider(
    keys=[key1, key2],
    rotation_interval_hours=24,  # Rotate every 24 hours
)

print(f"   Keys configured: {provider.key_count}")
print(f"   Active key: {provider.active_key_id}")

# =============================================================================
# Use with Signer
# =============================================================================

print("\n🔐 Creating Signer with Rotation:")

# Get a signer from the provider
signer = provider.get_signer()
print(f"   Got signer for DID: {signer.get_did()}")

# Sign something
token = signer.sign({"action": "test", "data": "important"})
print(f"   Signed token: {token[:50]}...")

# =============================================================================
# Key Management
# =============================================================================

print("\n📋 Key Management:")

# Get current active key
active_key = provider.get_active_key()
print(f"   Active key ID: {active_key.key_id}")
print(f"   Active key DID: {active_key.did}")

# Add a new key
key3_identity = generate_identity(domain="agent.example.com")
key3 = KeyConfig(
    private_key_jwk=key3_identity.private_key_jwk,
    did=key3_identity.did,
    key_id="key-2026-q3",
)
provider.add_key(key3)
print(f"\n   Added key: {key3.key_id}")
print(f"   Total keys: {provider.key_count}")

# Remove an old key
provider.remove_key("key-2026-q1")
print(f"   Removed key: key-2026-q1")
print(f"   Remaining keys: {provider.key_count}")

# =============================================================================
# Production Pattern
# =============================================================================

print("\n🏭 Production pattern:")

print("""
# In production, configure rotation callback:

def on_rotation(new_key_id: str):
    logger.info(f"Rotated to key: {new_key_id}")
    # Update key in DID document
    # Notify monitoring
    
provider = RotatingKeyProvider(
    keys=[key1, key2, key3],
    rotation_interval_hours=24,
    on_rotation=on_rotation,
)

# Use with existing Signer if needed:
signer = Signer(
    private_key=active_key.private_key_jwk,
    did=active_key.did,
)
""")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 KEY ROTATION BENEFITS:

Security:
  • Limits exposure if key compromised
  • Automatic rotation reduces risk
  • Multiple active keys for HA

Compliance:
  • Meet rotation requirements (SOC2, PCI)
  • Key versioning with key_id
  • Cryptographic key lifecycle

Configuration:
  • rotation_interval_hours: How often to rotate
  • on_rotation: Callback when rotation occurs
  • add_key/remove_key: Dynamic key management
""")
