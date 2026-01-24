# PAD-001: Cryptographic Binding of AI Agent Identity

**Publication Date:** December 28, 2025  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Prior Art  
**License:** Apache 2.0

## 1. Abstract

This disclosure describes a method for cryptographically binding AI agent identity to stated intent using Ed25519 digital signatures in a JWS (JSON Web Signature) format. Unlike traditional API authentication which only identifies *who* is calling, this system provides non-repudiation by binding *what* the agent intends to do with *who* they claim to be.

## 2. Problem Statement

Current AI agent authentication relies on:
- Bearer tokens (no binding to intent)
- API keys (shared secrets, no non-repudiation)
- OAuth (designed for humans, not agents)

These approaches fail to provide:
1. **Intent binding** - Proof that the agent authorized a specific action
2. **Non-repudiation** - Cryptographic proof that cannot be denied
3. **Agent-to-agent trust** - Verification between autonomous systems

## 3. The Novel Solution: Vouch Protocol

We disclose a protocol where AI agents sign their intent using:

### 3.1 Token Structure
```json
{
  "jti": "unique-request-id",
  "iss": "did:web:agent.example.com",
  "iat": 1703808000,
  "exp": 1703808300,
  "vouch": {
    "version": "1.0",
    "payload": {
      "action": "transfer_funds",
      "amount": 100,
      "recipient": "account_123"
    }
  }
}
```

### 3.2 Cryptographic Binding
- Ed25519 signature over canonical JSON
- Decentralized Identity (DID) for agent identification
- JWS compact serialization for transport

## 4. Prior Art Acknowledgement & Differentiation

We acknowledge:
- **JWT/JWS (RFC 7515)** - Token format
- **DIDs (W3C)** - Identity format

**Differentiation:** This disclosure applies these standards specifically to **AI agent identity** with the addition of:
- Intent payload binding
- Reputation scoring integration
- Agent-to-agent verification flows

## 5. Implementation

Reference implementation available at: https://github.com/vouch-protocol/vouch

---

*This document is published as prior art to prevent patent assertion on the described concepts.*
