#!/usr/bin/env python3
"""
Example: Sign Text Content

Demonstrates signing arbitrary text (code, documents, messages) with your Vouch identity.
"""

from vouch_sdk import (
    VouchClient,
    VouchConnectionError,
    NoKeysConfiguredError,
    UserDeniedSignatureError,
)


def sign_text_basic():
    """Basic text signing."""
    client = VouchClient()
    
    content = "Hello, World! This text was signed by Vouch."
    
    result = client.sign(content, origin="example-script")
    
    print("✅ Content signed successfully!")
    print(f"   Signature: {result['signature'][:32]}...")
    print(f"   Timestamp: {result['timestamp']}")
    print(f"   DID: {result.get('did', 'N/A')}")


def sign_code_with_metadata():
    """Sign code with additional metadata."""
    client = VouchClient()
    
    code = '''
def fibonacci(n):
    """Calculate the nth Fibonacci number."""
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
'''
    
    # Include metadata about the code
    result = client.sign(
        content=code,
        origin="ide-plugin",
        filename="fibonacci.py",
        language="python",
        version="1.0.0",
    )
    
    print("✅ Code signed with metadata!")
    print(f"   Signature: {result['signature'][:32]}...")


def sign_json_document():
    """Sign a JSON document (converts to string)."""
    import json
    
    client = VouchClient()
    
    document = {
        "type": "invoice",
        "number": "INV-2026-001",
        "amount": 1500.00,
        "currency": "USD",
        "items": [
            {"description": "Consulting", "price": 1000},
            {"description": "Support", "price": 500},
        ]
    }
    
    # Convert to canonical JSON (sorted keys for reproducibility)
    content = json.dumps(document, sort_keys=True)
    
    client.sign(content, origin="billing-system", document_type="invoice")
    
    print("✅ JSON document signed!")
    print(f"   Document: {document['type']} #{document['number']}")


def sign_with_custom_url():
    """Connect to a non-default daemon URL."""
    # Useful for remote daemons or custom ports
    client = VouchClient(daemon_url="http://localhost:9999")
    
    client.sign("Content", origin="custom-client")
    print("✅ Signed via custom URL!")


def main():
    try:
        print("\n📝 Example 1: Basic text signing")
        sign_text_basic()
        
        print("\n📝 Example 2: Sign code with metadata")
        sign_code_with_metadata()
        
        print("\n📝 Example 3: Sign JSON document")
        sign_json_document()
        
    except VouchConnectionError:
        print("❌ Daemon not running. Start with: vouch-bridge")
    except NoKeysConfiguredError:
        print("❌ No keys configured. Generate via daemon.")
    except UserDeniedSignatureError:
        print("⚠️ You declined to sign in the popup.")


if __name__ == "__main__":
    main()
