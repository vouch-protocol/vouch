# Vouch Protocol - Threat Model & Security Assurance Case

This document describes the threat model, trust boundaries, and security design principles of Vouch Protocol.

---

## 1. Overview

Vouch Protocol provides cryptographic identity for AI agents. This document justifies why security requirements are met.

---

## 2. Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Private Keys | Ed25519 signing keys | **Critical** - Must never be exposed |
| Vouch Tokens | Signed JWS tokens | Medium - Contain claims, time-limited |
| Public Keys | Ed25519 verification keys | Low - Intentionally public |
| Agent DIDs | Decentralized identifiers | Low - Public identifiers |

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │ AI Agent    │───▶│ Vouch SDK   │───▶│ Private Key │      │
│  │ (LangChain, │    │ (signing)   │    │ (keystore)  │      │
│  │  CrewAI)    │    └─────────────┘    └─────────────┘      │
│  └─────────────┘                                             │
└────────────────────────────┬────────────────────────────────┘
                             │ Vouch-Token (HTTP Header)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │ Network     │───▶│ API Server  │───▶│ Vouch SDK   │      │
│  │ (Internet)  │    │ (receiver)  │    │ (verify)    │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
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
| Signing | Ed25519 (EdDSA) | Modern, fast, small keys, no known weaknesses |
| Key Format | JWK (RFC 7517) | Interoperable, widely supported |
| Token Format | JWS Compact (RFC 7515) | Industry standard, compact for HTTP headers |
| Key Encryption | ChaCha20-Poly1305 | AEAD cipher, resistant to timing attacks |
| Key Derivation | Scrypt | Memory-hard, resistant to GPU/ASIC attacks |

---

## 8. References

- [Ed25519 Paper](https://ed25519.cr.yp.to/)
- [RFC 7515 - JWS](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JWK](https://tools.ietf.org/html/rfc7517)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

*Last Updated: 2026-01-15*
