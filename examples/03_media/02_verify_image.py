#!/usr/bin/env python3
"""
02_verify_image.py - Verify a Signed Image

Learn how to:
- Verify a Vouch signature
- Check signer identity
- Detect tampered images

Run: python 02_verify_image.py signed_photo.jpg
"""

import sys
from pathlib import Path
from vouch.media.native import verify_image_native, truncate_did

# =============================================================================
# Verify an image
# =============================================================================

image_path = sys.argv[1] if len(sys.argv) > 1 else "sample_signed.jpg"

if not Path(image_path).exists():
    print(f"❌ File not found: {image_path}")
    print("   Run 01_sign_image.py first to create a signed image")
    sys.exit(1)

result = verify_image_native(image_path)

# =============================================================================
# Show results
# =============================================================================

if result.is_valid:
    print("✅ VALID SIGNATURE")
    print(f"   Source: {result.source}")  # 'sidecar' or 'embedded'

    if result.signature:
        sig = result.signature
        print("\n🔐 Signer:")
        print(f"   Name:  {sig.display_name}")
        if sig.email:
            print(f"   Email: {sig.email}")
        print(f"   DID:   {truncate_did(sig.did)}")
        print(f"   Tier:  {sig.credential_type}")

        print("\n📋 Claim:")
        print(f"   Type:  {sig.claim_type.upper()}")
        print(f"   Chain: {sig.chain_id}")
        print(f"   Depth: {sig.chain_depth}")
        print(f"   Trust: {sig.chain_strength:.0%}")

        # Show org credentials if present
        if sig.credentials:
            print("\n🏢 Organization:")
            for cred in sig.credentials:
                org = cred.get("issuer_name", cred.get("issuer", "Unknown"))
                role = cred.get("role", "Unknown")
                print(f"   {org} - {role}")
else:
    print("❌ INVALID OR MISSING SIGNATURE")
    if result.error:
        print(f"   Error: {result.error}")

# =============================================================================
# What can verification tell you?
# =============================================================================

print("""
📝 VERIFICATION CHECKS:
   ✓ Signature matches image hash (not tampered)
   ✓ Signer's public key is valid
   ✓ Claim type (captured/signed/shared)
   ✓ Chain of custody (if reshared)
   ✓ Org credentials (if attached)

⚠️  WHAT IT CANNOT CHECK (without network):
   - Is the signer trusted?
   - Is the org verified?
   - Has the credential been revoked?
   
   For these, use ProManager.verify_chain()
""")
