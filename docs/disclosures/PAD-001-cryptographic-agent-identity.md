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

---

## 9. Update (April 27, 2026): Data Integrity Embodiment

The mechanism described above (binding AI agent identity to stated intent
via Ed25519 digital signatures) can be equivalently realized using W3C Data
Integrity proofs (`eddsa-jcs-2022` cryptosuite, optionally
`hybrid-eddsa-mldsa44-jcs-2026` for post-quantum coverage) attached to W3C
Verifiable Credentials. The substantive novel claim is unchanged:
cryptographic non-repudiation that binds *who* the agent is (DID) to *what*
the agent intends to do (a structured intent payload) and *when* (temporal
claims).

In this embodiment:
- The credential is a Verifiable Credential (`VerifiableCredential` +
 `VouchCredential` types) per the VC Data Model 2.0.
- The `credentialSubject.intent` field carries the structured intent
 payload (action, target, resource).
- The `proof` object is a Data Integrity proof: JCS canonicalization
 (RFC 8785) of the credential plus unsigned proof, SHA-256, Ed25519
 signature, multibase-encoded `proofValue`.
- Verification methods are encoded as `Multikey` in the issuer's DID
 Document (Controlled Identifiers), enabling algorithm-agnostic key
 resolution.

This embodiment is disclosed as additional prior art covering the same
inventive concept of cryptographically binding AI agent identity to intent
under modern open standards. The original JWS embodiment, Data
Integrity embodiment, and the hybrid post-quantum embodiment are all
disclosed forms of the same underlying invention.
