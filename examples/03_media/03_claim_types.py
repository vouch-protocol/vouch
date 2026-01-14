#!/usr/bin/env python3
"""
03_claim_types.py - Understanding CAPTURED, SIGNED, and SHARED Claims

Learn the three claim types and when to use each:
- CAPTURED: "I took this photo" (requires EXIF proof)
- SIGNED: "I vouch for this image" (default)
- SHARED: "I'm resharing someone else's signed image"

Run: python 03_claim_types.py
"""

from vouch.media.native import (
    sign_image_native, 
    generate_keypair,
    ClaimType,
    analyze_exif,
)
from PIL import Image
import tempfile
from pathlib import Path

# Generate test identity
private_key, did = generate_keypair()

# =============================================================================
# CLAIM TYPE 1: CAPTURED
# =============================================================================

print("📷 CLAIM TYPE: CAPTURED")
print("=" * 50)
print("Use when: You took the photo yourself")
print("Requires: Strong EXIF metadata (camera, GPS, timestamp)")
print()

# Create a fake "downloaded" image (no EXIF)
with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
    img = Image.new('RGB', (100, 100), 'red')
    img.save(f.name)
    
    # Analyze EXIF
    analysis = analyze_exif(f.name)
    print("EXIF Analysis:")
    print(f"   Has camera info: {analysis.has_camera_info}")
    print(f"   Has GPS: {analysis.has_gps}")
    print(f"   Has timestamp: {analysis.has_timestamp}")
    print(f"   Confidence: {analysis.confidence_score:.0%}")
    print(f"   Is likely original: {analysis.is_likely_original}")
    print(f"   Suggested claim: {analysis.suggested_claim_type.value}")
    
    # Try to claim CAPTURED anyway
    result = sign_image_native(
        source_path=f.name,
        private_key=private_key,
        did=did,
        display_name="Test",
        claim_type=ClaimType.CAPTURED,  # Force CAPTURED
    )
    
    print(f"\n   ⚠️  Result: {result.signature.claim_type.upper()}")
    if result.warning:
        print(f"   Warning: {result.warning}")

# =============================================================================
# CLAIM TYPE 2: SIGNED (Default)
# =============================================================================

print("\n✍️  CLAIM TYPE: SIGNED")
print("=" * 50)
print("Use when: You vouch for the image (didn't take it)")
print("Requires: Nothing special")
print()

with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
    img = Image.new('RGB', (100, 100), 'blue')
    img.save(f.name)
    
    result = sign_image_native(
        source_path=f.name,
        private_key=private_key,
        did=did,
        display_name="Editor",
        # claim_type not specified = auto-detect (defaults to SIGNED)
    )
    
    print(f"   Claim type: {result.signature.claim_type.upper()}")
    print(f"   Chain ID: {result.signature.chain_id}")
    print(f"   Chain depth: {result.signature.chain_depth}")

# =============================================================================
# CLAIM TYPE 3: SHARED
# =============================================================================

print("\n🔄 CLAIM TYPE: SHARED")
print("=" * 50)
print("Use when: Resharing someone else's signed image")
print("Requires: The parent signature")
print()

# First, original signer signs
original_key, original_did = generate_keypair()
with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
    img = Image.new('RGB', (100, 100), 'green')
    img.save(f.name)
    
    original_result = sign_image_native(
        source_path=f.name,
        private_key=original_key,
        did=original_did,
        display_name="Original Creator",
    )
    
    print(f"   Original signer: {original_result.signature.display_name}")
    print(f"   Original chain: {original_result.signature.chain_id}")
    print(f"   Original depth: {original_result.signature.chain_depth}")

    # Now, someone shares it
    sharer_key, sharer_did = generate_keypair()
    shared_result = sign_image_native(
        source_path=f.name,
        private_key=sharer_key,
        did=sharer_did,
        display_name="Re-sharer",
        claim_type=ClaimType.SHARED,
        parent_signature=original_result.signature,  # Link to parent!
    )
    
    print(f"\n   Sharer: {shared_result.signature.display_name}")
    print(f"   Same chain: {shared_result.signature.chain_id}")
    print(f"   New depth: {shared_result.signature.chain_depth}")
    print(f"   Trust strength: {shared_result.signature.chain_strength:.0%}")
    print(f"   Parent hash: {shared_result.signature.parent_hash}")

# =============================================================================
# TRUST DECAY
# =============================================================================

print("\n📉 TRUST DECAY")
print("=" * 50)
print("Each reshare reduces trust strength:")
print("   Depth 0: 100% (original)")
print("   Depth 1: 83%")
print("   Depth 2: 71%")
print("   Depth 5: 50%")
print("   Depth 10: 33%")
print("   Formula: 1 / (1 + 0.2 * depth)")
