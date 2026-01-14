#!/usr/bin/env python3
"""
03_token_anatomy.py - What's Inside a Vouch Token?

Learn the structure of a Vouch token:
- Header (algorithm, type)
- Payload (signer, intent, timestamp)
- Signature (Ed25519)

Run: python 03_token_anatomy.py
"""

from vouch import Signer
import json
import base64

# Create a signer and sign something
signer = Signer(name="ExampleBot", email="bot@example.com")
token = signer.sign("Transfer $100 to account 12345")

print("🔐 VOUCH TOKEN ANATOMY")
print("=" * 60)

# A Vouch token has 3 parts separated by dots: HEADER.PAYLOAD.SIGNATURE
parts = token.split(".")
if len(parts) == 3:
    header_b64, payload_b64, signature_b64 = parts

    # Decode header
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    print("\n📋 HEADER (Algorithm & Type)")
    print(json.dumps(header, indent=2))
    # {
    #   "alg": "EdDSA",      <- Ed25519 algorithm
    #   "typ": "vouch+jwt"   <- Vouch token type
    # }

    # Decode payload
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    print("\n📦 PAYLOAD (Claims)")
    print(json.dumps(payload, indent=2))
    # {
    #   "sub": "ExampleBot",           <- Signer name
    #   "email": "bot@example.com",    <- Signer email
    #   "pub": "z6Mk...",              <- Public key (did:key format)
    #   "payload": "Transfer $100...", <- The signed content
    #   "iat": 1704672000,             <- Issued at (Unix timestamp)
    #   "exp": 1704675600              <- Expires at
    # }

    print("\n✍️  SIGNATURE (Ed25519)")
    print(f"   {signature_b64[:40]}...")
    print(f"   Length: {len(signature_b64)} chars")

print("\n" + "=" * 60)
print("KEY POINTS:")
print("  • Header: Tells verifiers which algorithm to use")
print("  • Payload: Contains the signed intent + signer identity")
print("  • Signature: Cryptographic proof (unforgeable)")
print("  • Together: Provides non-repudiation for AI agents")
