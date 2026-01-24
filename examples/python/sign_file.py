#!/usr/bin/env python3
"""
Example: Sign Files (Any Type)

Demonstrates signing files using the Vouch SDK.
For media files (images, video, audio), C2PA manifests are embedded.
For other files, the signature is returned alongside the file.
"""

from pathlib import Path
from vouch_sdk import VouchClient, VouchConnectionError, NoKeysConfiguredError


def sign_single_file():
    """Sign a single file."""
    client = VouchClient()
    
    # Path to the file you want to sign
    file_path = Path("document.pdf")  # or any file
    
    if not file_path.exists():
        # Create a sample file for demo
        file_path.write_text("Sample document content for signing.")
    
    # Sign the file
    signed_bytes = client.sign_file(str(file_path), origin="file-signer")
    
    # Save the signed version
    output_path = file_path.with_suffix(".signed" + file_path.suffix)
    output_path.write_bytes(signed_bytes)
    
    print(f"✅ Signed: {file_path} → {output_path}")
    print(f"   Original size: {file_path.stat().st_size} bytes")
    print(f"   Signed size: {output_path.stat().st_size} bytes")


def sign_multiple_files():
    """Sign multiple files in a directory."""
    client = VouchClient()
    
    # Find all Python files in current directory
    for file_path in Path(".").glob("*.py"):
        try:
            signed_bytes = client.sign_file(str(file_path), origin="batch-signer")
            
            output_path = Path("signed") / file_path.name
            output_path.parent.mkdir(exist_ok=True)
            output_path.write_bytes(signed_bytes)
            
            print(f"✅ {file_path.name}")
            
        except Exception as e:
            print(f"❌ {file_path.name}: {e}")


def sign_from_bytes():
    """Sign binary data without a file."""
    client = VouchClient()
    
    # Generate some binary data
    binary_data = b"Binary content: \x00\x01\x02\x03\xff\xfe\xfd"
    
    # Sign the bytes directly
    signed_bytes = client.sign_bytes(
        data=binary_data,
        filename="data.bin",
        origin="memory-signer"
    )
    
    print(f"✅ Signed {len(binary_data)} bytes → {len(signed_bytes)} bytes")


def sign_from_stream():
    """Sign data from a file-like object (stream)."""
    from io import BytesIO
    
    client = VouchClient()
    
    # Simulate a stream (could be from network, database, etc.)
    stream = BytesIO(b"Streamed content that needs signing")
    
    signed_bytes = client.sign_bytes(
        data=stream,
        filename="streamed.txt",
        origin="stream-signer"
    )
    
    print(f"✅ Signed streamed data: {len(signed_bytes)} bytes")


def sign_large_file():
    """Sign a large file (demonstrates streaming)."""
    client = VouchClient()
    
    # Create a large test file (10MB)
    large_file = Path("large_test.bin")
    
    if not large_file.exists():
        print("Creating 10MB test file...")
        with open(large_file, "wb") as f:
            for _ in range(1024):  # 1024 * 10KB = 10MB
                f.write(b"X" * 10240)
    
    print(f"Signing {large_file} ({large_file.stat().st_size / 1024 / 1024:.1f} MB)...")
    
    signed_bytes = client.sign_file(str(large_file), origin="large-file-signer")
    
    output_path = large_file.with_suffix(".signed.bin")
    output_path.write_bytes(signed_bytes)
    
    print(f"✅ Large file signed: {output_path}")
    
    # Cleanup
    large_file.unlink()
    output_path.unlink()


def main():
    try:
        print("\n📁 Example 1: Sign single file")
        sign_single_file()
        
        print("\n📁 Example 2: Sign from bytes")
        sign_from_bytes()
        
        print("\n📁 Example 3: Sign from stream")
        sign_from_stream()
        
        # print("\n📁 Example 4: Sign large file")
        # sign_large_file()  # Uncomment to test with large files
        
    except VouchConnectionError:
        print("❌ Daemon not running. Start with: vouch-bridge")
    except NoKeysConfiguredError:
        print("❌ No keys configured.")


if __name__ == "__main__":
    main()
