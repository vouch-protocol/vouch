# Vouch Protocol - Threat Model & Security Assurance Case

This document describes the threat model, trust boundaries, and security design principles of Vouch Protocol.

---

## 1. Overview

Vouch Protocol provides cryptographic identity for AI agents. This document justifies why security requirements are met.

---

## 2. Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Private Keys | Ed25519 signing keys (and optional ML-DSA-44 for hybrid profile) | **Critical** - Must never be exposed |
| Vouch Credentials (v1.0) | Verifiable Credentials secured by Data Integrity proofs | Medium - Contain claims, time-limited |
| Vouch Tokens (legacy v0.x) | Signed JWS tokens | Medium - Contain claims, time-limited |
| Public Keys | Ed25519 (and optional ML-DSA-44) verification keys | Low - Intentionally public |
| Agent DIDs | Decentralized identifiers | Low - Public identifiers |

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│          TRUSTED ZONE               │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│ │ AI Agent  │───▶│ Vouch SDK  │───▶│ Private Key │   │
│ │ (LangChain, │  │ (signing)  │  │ (keystore) │   │
│ │ CrewAI)  │  └─────────────┘  └─────────────┘   │
│ └─────────────┘                       │
└────────────────────────────┬────────────────────────────────┘
               │ Vouch-Token (HTTP Header)
               ▼
┌─────────────────────────────────────────────────────────────┐
│          UNTRUSTED ZONE               │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│ │ Network   │───▶│ API Server │───▶│ Vouch SDK  │   │
│ │ (Internet) │  │ (receiver) │  │ (verify)  │   │
│ └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Trust Boundary**: The HTTP network layer is untrusted. All tokens must be cryptographically verified.

---

## 4. Threat Analysis

### 4.1 Threats & Mitigations

| Threat | Attack Vector | Mitigation | Status |
|--------|---------------|------------|--------|
| **Key Theft** | Attacker steals private key file | Keys encrypted with Scrypt + ChaCha20-Poly1305 | ✅ Mitigated |
| **Token Forgery** | Attacker creates fake token | Ed25519 signatures - computationally infeasible to forge | ✅ Mitigated |
| **Replay Attack** | Attacker reuses old valid token | `iat` (issued-at) and `exp` (expiry) claims enforce time limits | ✅ Mitigated |
| **Impersonation** | Attacker claims different identity | DID bound to public key - cannot be spoofed | ✅ Mitigated |
| **Man-in-the-Middle** | Attacker intercepts/modifies token | Token integrity protected by signature; recommend HTTPS | ✅ Mitigated |
| **Algorithm Confusion** | Attacker tricks verifier into using weak algorithm | Only Ed25519 supported - no algorithm negotiation | ✅ Mitigated |

### 4.2 Out of Scope

- Physical security of the machine running the agent
- Compromise of the operating system
- Side-channel attacks on cryptographic operations
- Social engineering attacks

---

## 5. Secure Design Principles Applied

| Principle | How Applied |
|-----------|-------------|
| **Defense in Depth** | Multiple layers: key encryption, signature verification, time limits |
| **Least Privilege** | Tokens contain only necessary claims, short expiry times |
| **Fail Secure** | Invalid signatures always reject - no fallback to unsigned |
| **Secure Defaults** | Strong crypto (Ed25519) used by default, no weak options |
| **Separation of Concerns** | Private keys isolated in keystore, not embedded in code |
| **Don't Roll Your Own Crypto** | Uses `cryptography` library (OpenSSL backend) |

---

## 6. Common Weaknesses Countered

| CWE | Weakness | How Countered |
|-----|----------|---------------|
| CWE-327 | Use of Broken Crypto | Only Ed25519 - no MD5, SHA1, DES, etc. |
| CWE-330 | Insufficient Randomness | Uses OS-provided CSPRNG via `cryptography` |
| CWE-347 | Improper Verification | All tokens verified before processing |
| CWE-757 | Algorithm Downgrade | No algorithm negotiation - Ed25519 only |
| CWE-798 | Hardcoded Credentials | Keys stored externally in encrypted keystore |
| CWE-916 | Weak Password Hashing | Scrypt with high cost parameters for key derivation |

---

## 7. Cryptographic Choices

| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| Default signing | Ed25519 (EdDSA, RFC 8032) | Modern, fast, small keys, no known weaknesses |
| Hybrid signing (optional) | Ed25519 + ML-DSA-44 (FIPS 204) | Quantum-safe migration path; both signatures must validate |
| Cryptosuite (default) | `eddsa-jcs-2022` (Data Integrity) | standards-aligned; no JOSE/JWS dependency in v1.0 |
| Cryptosuite (hybrid) | `hybrid-eddsa-mldsa44-jcs-2026` | Defined per Specification §13.2 |
| Canonicalization | JCS (RFC 8785) | Deterministic, parser-independent, no JSON-LD overhead |
| Key encoding | Multikey (Controlled Identifiers) | Algorithm-agnostic, future-compatible |
| Legacy token format (v0.x) | JWS Compact (RFC 7515) | Retained for backward compatibility window |
| Key encryption | ChaCha20-Poly1305 | AEAD cipher, resistant to timing attacks |
| Key derivation | Scrypt | Memory-hard, resistant to GPU/ASIC attacks |

---

## 8. Quantum-Safe Threat Model (v1.0)

The hybrid post-quantum profile addresses two specific threats:

| Threat | How Hybrid Profile Mitigates |
|---|---|
| **Harvest-Now, Decrypt-Later (signatures)** | Vouch credentials are short-lived (default 5 min) so encryption-style harvest attacks are not the primary concern. The hybrid profile's relevance is *retroactive forgery*: if a quantum adversary breaks Ed25519 in 2030, they could forge a signature dated 2026. Hybrid signatures bind the credential under **both** Ed25519 and ML-DSA-44, so even a compromise of Ed25519 cannot produce a valid hybrid signature. |
| **Algorithm transition risk** | NIST CNSA 2.0 and U.S. NSM-10 mandate quantum-resistant cryptography on phased timelines (CNSA 2.0 phases starting 2027). Adopting the hybrid profile now ensures continued validity through and beyond the migration cutoff. |

The default `eddsa-jcs-2022` cryptosuite provides the same classical
security level as v0.x. Implementations MAY support the hybrid profile
in v1.0; v1.1 is expected to RECOMMEND it for regulated sectors.

---

## 9. References

- [Ed25519 Paper](https://ed25519.cr.yp.to/)
- [RFC 8032 - EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [W3C `eddsa-jcs-2022` cryptosuite](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 7515 - JWS (legacy)](https://tools.ietf.org/html/rfc7515)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

*Last Updated: 2026-04-27*
