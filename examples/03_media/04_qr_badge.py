#!/usr/bin/env python3
"""
04_qr_badge.py - Add Visual Verification Badge to Images

Learn how to:
- Add QR codes with verification links
- Customize badge position
- Create scannable proof

Run: python 04_qr_badge.py photo.jpg
"""

import sys
from pathlib import Path
from vouch.media.badge import BadgeFactory, BadgeOptions

# =============================================================================
# Create a BadgeFactory
# =============================================================================

# Default: bottom-right corner
factory = BadgeFactory()

print("🏭 BadgeFactory Configuration:")
config = factory.get_config()
print(f"   Position: {config.position}")
print(f"   Size: {config.size}px")
print(f"   Include QR: {config.include_qr}")
print(f"   Base URL: {config.base_url}")

# =============================================================================
# Add badge to an image
# =============================================================================

# Get input image
image_path = sys.argv[1] if len(sys.argv) > 1 else "sample.jpg"

# Create sample if needed
if not Path(image_path).exists():
    print(f"\n⚠️  Creating sample image...")
    from PIL import Image
    img = Image.new('RGB', (800, 600), color='steelblue')
    img.save(image_path)

# Add badge
signature_hash = "example_signature_hash_abc123"
result = factory.add_badge(image_path, signature_hash)

if result.success:
    print(f"\n✅ Badge added!")
    print(f"   Output: {result.output_path}")
    print(f"   Verify URL: {result.verify_url}")
else:
    print(f"\n❌ Error: {result.error}")

# =============================================================================
# Different positions
# =============================================================================

print("\n📍 AVAILABLE POSITIONS:")
positions = ['top-left', 'top-right', 'bottom-left', 'bottom-right', 'center-bottom']

for pos in positions:
    factory.set_position(pos)
    output = f"/tmp/badge_{pos}.jpg"
    result = factory.add_badge(image_path, signature_hash, output)
    status = "✅" if result.success else "❌"
    print(f"   {status} {pos}")

# =============================================================================
# Custom options
# =============================================================================

print("\n⚙️  CUSTOM OPTIONS:")

custom_factory = BadgeFactory(BadgeOptions(
    position='top-right',
    size=128,  # Bigger QR code
    opacity=0.8,
    padding=24,
    base_url='https://verify.mycompany.com',
))

result = custom_factory.add_badge(image_path, signature_hash, "/tmp/custom_badge.jpg")
print(f"   Custom verify URL: {result.verify_url}")

# =============================================================================
# Explanation
# =============================================================================

print("""
🔗 HOW QR VERIFICATION WORKS:

1. User sees signed image with QR badge
2. Scans QR with phone camera
3. Opens vouch.me/v/abc123
4. Website shows:
   - Is signature valid?
   - Who signed it?
   - When was it signed?
   - Organization (if any)

📱 NO APP NEEDED - just a phone camera!
""")
