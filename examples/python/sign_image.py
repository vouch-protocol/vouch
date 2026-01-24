#!/usr/bin/env python3
"""
Example: Sign Images with C2PA Content Credentials

When you sign an image through Vouch, a C2PA manifest is embedded directly
into the file, making the signature part of the image itself.
"""

from pathlib import Path
from vouch_sdk import VouchClient, VouchConnectionError


def sign_jpeg_image():
    """Sign a JPEG image - C2PA manifest is embedded."""
    client = VouchClient()
    
    # Find or create a sample image
    image_path = Path("sample.jpg")
    
    if not image_path.exists():
        # Create a minimal valid JPEG (1x1 pixel, red)
        create_sample_jpeg(image_path)
        print(f"Created sample image: {image_path}")
    
    # Sign the image
    signed_bytes = client.sign_file(str(image_path), origin="image-signer")
    
    # Save the signed version
    output_path = Path("sample_signed.jpg")
    output_path.write_bytes(signed_bytes)
    
    print(f"✅ Image signed!")
    print(f"   Original: {image_path} ({image_path.stat().st_size} bytes)")
    print(f"   Signed: {output_path} ({output_path.stat().st_size} bytes)")
    print(f"   C2PA manifest embedded: {output_path.stat().st_size > image_path.stat().st_size}")


def sign_png_image():
    """Sign a PNG image."""
    client = VouchClient()
    
    png_path = Path("sample.png")
    
    if not png_path.exists():
        create_sample_png(png_path)
        print(f"Created sample PNG: {png_path}")
    
    signed_bytes = client.sign_file(str(png_path), origin="png-signer")
    
    output_path = Path("sample_signed.png")
    output_path.write_bytes(signed_bytes)
    
    print(f"✅ PNG signed: {output_path}")


def sign_image_batch():
    """Sign all images in a directory."""
    client = VouchClient()
    
    image_extensions = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".tiff"}
    
    for path in Path(".").iterdir():
        if path.suffix.lower() in image_extensions:
            try:
                signed = client.sign_file(str(path), origin="batch-image-signer")
                
                output = Path("signed_images") / path.name
                output.parent.mkdir(exist_ok=True)
                output.write_bytes(signed)
                
                print(f"✅ {path.name}")
                
            except Exception as e:
                print(f"❌ {path.name}: {e}")


def create_sample_jpeg(path: Path):
    """Create a minimal valid JPEG file."""
    # Minimal JPEG: 1x1 red pixel
    jpeg_data = bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB,
        0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07,
        0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B,
        0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E,
        0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C,
        0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34,
        0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34,
        0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01,
        0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
        0x3F, 0x00, 0xFB, 0xD5, 0xDB, 0x20, 0xAE, 0x58, 0xA9, 0xFF, 0xD9
    ])
    path.write_bytes(jpeg_data)


def create_sample_png(path: Path):
    """Create a minimal valid PNG file."""
    # Minimal PNG: 1x1 red pixel
    png_data = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
        0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,  # IDAT chunk
        0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0xFE,
        0xD4, 0xE3, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,  # IEND chunk
        0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
    ])
    path.write_bytes(png_data)


def main():
    try:
        print("\n🖼️ Example 1: Sign JPEG image")
        sign_jpeg_image()
        
        print("\n🖼️ Example 2: Sign PNG image")
        sign_png_image()
        
    except VouchConnectionError:
        print("❌ Daemon not running. Start with: vouch-bridge")


if __name__ == "__main__":
    main()
