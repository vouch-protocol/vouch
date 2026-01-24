#!/usr/bin/env python3
"""
Example: Verify C2PA Manifests in Media Files

The `vouch verify` command (and this script) can verify C2PA content
credentials embedded in images, videos, and other media files.

This works OFFLINE - no daemon needed!
"""

from pathlib import Path

# Try to import c2pa
try:
    import c2pa
    C2PA_AVAILABLE = True
except ImportError:
    C2PA_AVAILABLE = False
    print("⚠️ c2pa-python not installed. Run: pip install c2pa-python")


def verify_image(file_path: str) -> dict | None:
    """
    Verify C2PA manifest in an image.
    
    Returns manifest info if found, None if unsigned.
    """
    if not C2PA_AVAILABLE:
        raise ImportError("c2pa-python required for verification")
    
    try:
        reader = c2pa.Reader.from_file(file_path)
        manifest_store = reader.get_manifest_store()
        
        if not manifest_store:
            return None
        
        return {
            "verified": True,
            "manifests": manifest_store,
        }
        
    except Exception as e:
        # No manifest found or parse error
        if "no manifest" in str(e).lower() or "jumbf" in str(e).lower():
            return None
        raise


def display_manifest(manifest_store: dict):
    """Pretty-print manifest information."""
    manifests = manifest_store.get("manifests", {})
    active_id = manifest_store.get("active_manifest")
    
    for manifest_id, manifest in manifests.items():
        is_active = " (Active)" if manifest_id == active_id else ""
        print(f"\n📜 Manifest: {manifest_id[:20]}...{is_active}")
        
        if isinstance(manifest, dict):
            # Claim generator
            generator = manifest.get("claim_generator", "Unknown")
            print(f"   Generator: {generator}")
            
            # Signature info
            sig_info = manifest.get("signature_info", {})
            if sig_info:
                issuer = sig_info.get("issuer", "Unknown")
                timestamp = sig_info.get("time", "Unknown")
                print(f"   Signed by: {issuer}")
                print(f"   Timestamp: {timestamp}")
            
            # Assertions
            assertions = manifest.get("assertions", [])
            if assertions:
                print(f"   Assertions: {len(assertions)}")


def verify_file(file_path: str):
    """Verify a file and display results."""
    path = Path(file_path)
    
    if not path.exists():
        print(f"❌ File not found: {file_path}")
        return
    
    print(f"\n🔍 Verifying: {path.name}")
    print(f"   Size: {path.stat().st_size:,} bytes")
    
    result = verify_image(str(path))
    
    if result is None:
        print("\n⚠️ No C2PA manifest found")
        print("   This file has not been signed with content credentials.")
    else:
        print("\n✅ Valid C2PA manifest found!")
        display_manifest(result["manifests"])


def batch_verify(directory: str):
    """Verify all media files in a directory."""
    media_extensions = {".jpg", ".jpeg", ".png", ".webp", ".mp4", ".mov", ".pdf"}
    
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"❌ Not a directory: {directory}")
        return
    
    files = [f for f in dir_path.iterdir() if f.suffix.lower() in media_extensions]
    
    print(f"\n📂 Scanning {len(files)} media files in {directory}")
    
    signed = 0
    unsigned = 0
    
    for file in files:
        result = verify_image(str(file))
        if result:
            print(f"✅ {file.name}")
            signed += 1
        else:
            print(f"⚠️ {file.name} (unsigned)")
            unsigned += 1
    
    print(f"\n📊 Results: {signed} signed, {unsigned} unsigned")


def main():
    import sys
    
    if not C2PA_AVAILABLE:
        print("Install c2pa-python: pip install c2pa-python")
        return
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python verify_media.py <file>      - Verify a single file")
        print("  python verify_media.py <directory> - Verify all media in directory")
        print("\nExamples:")
        print("  python verify_media.py photo.jpg")
        print("  python verify_media.py ./images/")
        return
    
    target = sys.argv[1]
    path = Path(target)
    
    if path.is_dir():
        batch_verify(target)
    else:
        verify_file(target)


if __name__ == "__main__":
    main()
