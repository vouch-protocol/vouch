#!/usr/bin/env python3
"""
C2PA Signing Example for Vouch Protocol.

Demonstrates how to sign images with C2PA manifests using Vouch Protocol.
Supports JPEG, PNG, WebP, GIF, and TIFF formats.

Usage:
    python c2pa_signing_example.py <input_image> [output_image]
    
Example:
    python c2pa_signing_example.py photo.jpg photo_signed.jpg
"""

import argparse
import json
import sys
from pathlib import Path

# Supported formats
SUPPORTED_FORMATS = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
}


def get_manifest(title: str = "Vouch Protocol Signed Image") -> dict:
    """
    Create a C2PA manifest definition.
    
    Note: In production, you would include your certificate paths here.
    """
    return {
        "alg": "PS256",
        "claim_generator": "Vouch Protocol/1.0",
        "title": title,
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "softwareAgent": "Vouch Protocol v1.0"
                        }
                    ]
                }
            },
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org/",
                    "@type": "CreativeWork",
                    "author": [
                        {
                            "@type": "Organization",
                            "name": "Vouch Protocol"
                        }
                    ]
                }
            }
        ]
    }


def sign_image_with_c2pa(
    input_path: Path,
    output_path: Path,
    private_key_path: Path,
    cert_chain_path: Path,
    title: str = None
) -> dict:
    """
    Sign an image with a C2PA manifest.
    
    Args:
        input_path: Path to source image
        output_path: Path for signed output
        private_key_path: Path to private key (PEM)
        cert_chain_path: Path to certificate chain (PEM)
        title: Optional title for the manifest
        
    Returns:
        Dict with signing result and manifest info
    """
    try:
        import c2pa
    except ImportError:
        raise RuntimeError("c2pa-python is required. Install with: pip install c2pa-python")
    
    # Validate input format
    ext = input_path.suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {ext}. Supported: {list(SUPPORTED_FORMATS.keys())}")
    
    # Load credentials
    with open(private_key_path, "rb") as f:
        private_key = f.read()
    with open(cert_chain_path, "rb") as f:
        sign_cert = f.read()
    
    # Create manifest
    manifest = get_manifest(title or input_path.stem)
    manifest["private_key"] = str(private_key_path)
    manifest["sign_cert"] = str(cert_chain_path)
    
    # Create signer info
    signer_info = c2pa.C2paSignerInfo(
        alg="PS256",
        sign_cert=sign_cert,
        private_key=private_key,
        ta_url=""
    )
    
    # Build and sign
    builder = c2pa.Builder(json.dumps(manifest))
    
    with open(input_path, "rb") as source:
        with open(output_path, "wb") as dest:
            result = builder.sign(
                signer_info,
                SUPPORTED_FORMATS[ext],
                source,
                dest
            )
    
    return {
        "success": True,
        "input": str(input_path),
        "output": str(output_path),
        "manifest_bytes": len(result),
        "format": SUPPORTED_FORMATS[ext]
    }


def verify_image(image_path: Path) -> dict:
    """
    Verify a C2PA-signed image.
    
    Args:
        image_path: Path to signed image
        
    Returns:
        Dict with verification result and manifest info
    """
    try:
        import c2pa
    except ImportError:
        raise RuntimeError("c2pa-python is required. Install with: pip install c2pa-python")
    
    try:
        reader = c2pa.Reader.from_file(str(image_path))
        manifest_store = json.loads(reader.json())
        
        active = manifest_store.get("active_manifest")
        validation = manifest_store.get("validation_state", "Unknown")
        
        result = {
            "is_valid": validation == "Valid",
            "active_manifest": active,
            "validation_state": validation,
        }
        
        # Extract signer info if available
        if active and "manifests" in manifest_store:
            manifest = manifest_store["manifests"].get(active, {})
            sig_info = manifest.get("signature_info", {})
            result["signer"] = {
                "issuer": sig_info.get("issuer"),
                "common_name": sig_info.get("common_name"),
                "algorithm": sig_info.get("alg")
            }
            result["claim_generator"] = manifest.get("claim_generator_info", [])
        
        return result
        
    except Exception as e:
        return {
            "is_valid": False,
            "error": str(e)
        }


def main():
    parser = argparse.ArgumentParser(
        description="Sign or verify images with C2PA manifests using Vouch Protocol"
    )
    parser.add_argument("input", help="Input image path")
    parser.add_argument("output", nargs="?", help="Output path (for signing)")
    parser.add_argument("--verify", "-v", action="store_true", help="Verify instead of sign")
    parser.add_argument("--key", "-k", help="Private key path (PEM)")
    parser.add_argument("--cert", "-c", help="Certificate chain path (PEM)")
    parser.add_argument("--title", "-t", help="Manifest title")
    
    args = parser.parse_args()
    input_path = Path(args.input)
    
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    if args.verify:
        # Verify mode
        print(f"Verifying: {input_path}")
        result = verify_image(input_path)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("is_valid") else 1)
    
    else:
        # Sign mode
        if not args.key or not args.cert:
            print("Error: --key and --cert are required for signing")
            print("Example: python c2pa_signing_example.py photo.jpg --key leaf.key --cert chain.pem")
            sys.exit(1)
        
        output_path = Path(args.output) if args.output else input_path.with_stem(f"{input_path.stem}_signed")
        
        print(f"Signing: {input_path} -> {output_path}")
        try:
            result = sign_image_with_c2pa(
                input_path,
                output_path,
                Path(args.key),
                Path(args.cert),
                args.title
            )
            print(json.dumps(result, indent=2))
            print(f"\n✓ Signed successfully: {output_path}")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
