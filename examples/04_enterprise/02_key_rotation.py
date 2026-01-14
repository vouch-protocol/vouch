#!/usr/bin/env python3
"""
02_key_rotation.py - Automatic Key Rotation

Rotate signing keys automatically for security.

Run: python 02_key_rotation.py
"""

from vouch import RotatingKeyProvider, KeyConfig, Signer
from datetime import timedelta

print("🔄 Key Rotation")
print("=" * 50)

# =============================================================================
# Create Rotating Key Provider
# =============================================================================

print("Setting up key rotation...")

config = KeyConfig(
    rotation_interval=timedelta(days=30),  # Rotate every 30 days
    key_overlap=timedelta(days=7),  # Old key valid for 7 days after rotation
    algorithm="ed25519",
)

provider = RotatingKeyProvider(config=config)

print(f"  Rotation interval: {config.rotation_interval.days} days")
print(f"  Key overlap: {config.key_overlap.days} days")

# =============================================================================
# Use with Signer
# =============================================================================

print("\n🔐 Creating Signer with Rotation:")

# Get current key
current_key = provider.get_current_key()
print(f"  Current key ID: {current_key.key_id[:20]}...")
print(f"  Expires: {current_key.expires_at}")

# Create signer with rotating provider
signer = Signer(
    name="Enterprise Agent",
    key_provider=provider,
)

# Sign something
token = signer.sign("Important action")
print(f"\n  Signed with key: {signer.current_key_id[:20]}...")

# =============================================================================
# Manual Rotation
# =============================================================================

print("\n🔄 Manual Key Rotation:")

# Force rotation (normally automatic)
old_key_id = provider.get_current_key().key_id
provider.rotate()
new_key_id = provider.get_current_key().key_id

print(f"  Old key: {old_key_id[:20]}...")
print(f"  New key: {new_key_id[:20]}...")
print(f"  Old key still valid: {provider.is_valid(old_key_id)}")

# =============================================================================
# Key History
# =============================================================================

print("\n📋 Key History:")

for key in provider.get_key_history(limit=5):
    status = "active" if key.is_active else "expired"
    print(f"  {key.key_id[:15]}... ({status})")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 KEY ROTATION BENEFITS:

Security:
  • Limits exposure if key compromised
  • Automatic rotation reduces risk
  • Overlap period ensures continuity

Compliance:
  • Meet rotation requirements (SOC2, PCI)
  • Full key audit trail
  • Cryptographic key lifecycle

Configuration:
  • rotation_interval: How often to rotate
  • key_overlap: Grace period for old keys
  • algorithm: ed25519, rsa2048, etc.
""")
