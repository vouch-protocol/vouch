#!/usr/bin/env python3
"""
01_sign_image.py - Sign an Image with Vouch Protocol

Learn how to:
- Sign images with Ed25519 (no certificates needed!)
- Create .vouch sidecar files
- Understand the signature structure

Run: python 01_sign_image.py my_photo.jpg
"""

import sys
from pathlib import Path
from vouch.media.native import sign_image_native, generate_keypair

# =============================================================================
# Generate or load your identity
# =============================================================================

private_key, did = generate_keypair()
print(f"🔑 Generated DID: {did[:40]}...")

# =============================================================================
# Sign an image
# =============================================================================

# Use provided image or default
image_path = sys.argv[1] if len(sys.argv) > 1 else "sample.jpg"

if not Path(image_path).exists():
    print("⚠️  Creating sample image for demo...")
    from PIL import Image
    img = Image.new('RGB', (800, 600), color='steelblue')
    img.save(image_path)

# Sign it!
result = sign_image_native(
    source_path=image_path,
    private_key=private_key,
    did=did,
    display_name="Alice Photographer",
    email="alice@example.com",
    credential_type="PRO",  # FREE or PRO
)

if result.success:
    print("\n✅ Image signed successfully!")
    print(f"   Original:  {result.source_path}")
    print(f"   Signed:    {result.output_path}")
    print(f"   Sidecar:   {result.sidecar_path}")
    
    print("\n📋 Signature Details:")
    print(f"   Version:   {result.signature.version}")
    print(f"   Signer:    {result.signature.display_name}")
    print(f"   DID:       {result.signature.did[:30]}...")
    print(f"   Timestamp: {result.signature.timestamp}")
    print(f"   Hash:      {result.signature.image_hash[:20]}...")
else:
    print(f"❌ Error: {result.error}")

# =============================================================================
# What gets created?
# =============================================================================

print("""
📁 FILES CREATED:
   photo.jpg          <- Original (unchanged)
   photo_signed.jpg   <- Copy of original
   photo_signed.jpg.vouch <- Sidecar with signature (JSON)

🔒 SIDECAR CONTAINS:
   - Signer's DID (decentralized identifier)
   - Ed25519 signature
   - SHA-256 hash of image
   - Timestamp
   - Claim type (captured/signed/shared)
""")
