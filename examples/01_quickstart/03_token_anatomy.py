#!/usr/bin/env python3
"""
03_token_anatomy.py - What's Inside a Vouch Token?

Learn the structure of a Vouch token:
- Header (algorithm, type)
- Payload (claims including signer DID, intent, timestamp)
- Signature (Ed25519)

Run: python 03_token_anatomy.py
"""

from vouch import Signer, generate_identity
import json
import base64

# Create an identity and signer
identity = generate_identity(domain="example-bot.com")
signer = Signer(private_key=identity.private_key_jwk, did=identity.did)

# Sign a payload (must be a dict)
payload = {"action": "transfer", "amount": 100, "to_account": "12345"}
token = signer.sign(payload)

print("🔐 VOUCH TOKEN ANATOMY")
print("=" * 60)

# A Vouch token has 3 parts separated by dots: HEADER.PAYLOAD.SIGNATURE
parts = token.split(".")
if len(parts) == 3:
    header_b64, payload_b64, signature_b64 = parts

    # Decode header
    # Add padding if needed
    header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_padded))
    print("\n📋 HEADER (Algorithm & Type)")
    print(json.dumps(header, indent=2))
    # {
    #   "alg": "EdDSA",      <- Ed25519 algorithm
    #   "typ": "vouch+jwt"   <- Vouch token type
    #   "kid": "did:web:..." <- Key ID (the signer's DID)
    # }

    # Decode payload
    payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload_padded))
    print("\n📦 PAYLOAD (Claims)")
    print(json.dumps(claims, indent=2))
    # {
    #   "jti": "...",              <- Unique token ID (nonce)
    #   "iss": "did:web:...",      <- Issuer (signer's DID)
    #   "sub": "did:web:...",      <- Subject (same as issuer for self-signed)
    #   "iat": 1704672000,         <- Issued at (Unix timestamp)
    #   "nbf": 1704672000,         <- Not before
    #   "exp": 1704675600,         <- Expires at
    #   "vouch": {                 <- Vouch-specific claims
    #     "version": "1.0",
    #     "payload": {...}         <- The signed content
    #   }
    # }

    print("\n✍️  SIGNATURE (Ed25519)")
    print(f"   {signature_b64[:40]}...")
    print(f"   Length: {len(signature_b64)} chars")

print("\n" + "=" * 60)
print("KEY POINTS:")
print("  • Header: Tells verifiers which algorithm to use (EdDSA)")
print("  • Payload: Contains the signed intent + signer DID + timestamps")
print("  • Signature: Cryptographic proof (unforgeable)")
print("  • Together: Provides non-repudiation for AI agents")
