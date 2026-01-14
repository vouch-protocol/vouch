#!/usr/bin/env python3
"""
01_sign_request.py - Sign HTTP Requests

Attach Vouch tokens to outgoing API calls.

Run: python 01_sign_request.py
"""

from vouch import Signer
import json

print("📤 Sign HTTP Requests")
print("=" * 50)

# =============================================================================
# Create a Signer
# =============================================================================

signer = Signer(
    name="API Client Agent",
    email="agent@example.com",
)

print(f"Agent: {signer.name}")

# =============================================================================
# Sign a Request
# =============================================================================

# The intent you're signing
request_intent = {
    "method": "POST",
    "url": "https://api.bank.com/transfer",
    "body": {
        "from": "account_123",
        "to": "account_456",
        "amount": 100.00,
    },
}

# Sign it
token = signer.sign(json.dumps(request_intent))

print("\n📝 Signed Request:")
print(f"   Method: {request_intent['method']}")
print(f"   URL: {request_intent['url']}")
print(f"   Token: {token[:50]}...")

# =============================================================================
# Attach to HTTP Request
# =============================================================================

print("\n📤 Attaching to HTTP Request:")

print("""
import requests

response = requests.post(
    "https://api.bank.com/transfer",
    json={"from": "account_123", "to": "account_456", "amount": 100},
    headers={
        "Authorization": "Bearer your-api-key",
        "X-Vouch-Token": token,  # 👈 Add Vouch signature
    }
)
""")

# =============================================================================
# Example Headers
# =============================================================================

headers = {
    "Authorization": "Bearer your-api-key",
    "X-Vouch-Token": token,
    "Content-Type": "application/json",
}

print("   Headers:")
for k, v in headers.items():
    if k == "X-Vouch-Token":
        print(f"     {k}: {v[:40]}...")
    else:
        print(f"     {k}: {v}")

print("""
✅ The API server can now:
   1. Authenticate with API key (who can access)
   2. Verify Vouch token (who did this action)
   3. Log the signed intent (audit trail)
""")
