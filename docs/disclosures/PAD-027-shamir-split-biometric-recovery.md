# PAD-027: Method for Shamir Secret Sharing of Biometric Enrollment Data Bound to Decentralized Identifiers

**Identifier:** PAD-027
**Title:** Method for Shamir Secret Sharing of Biometric Enrollment Data Bound to Decentralized Identifiers
**Publication Date:** February 28, 2026
**Prior Art Effective Date:** February 28, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Biometric Recovery / Secret Sharing / Decentralized Identity / Privacy
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-026 (DID-Linked Voiceprint Enrollment), PAD-014 (Vouch Sonic)

---

## 1. Abstract

A system and method for bundling a user's Ed25519 private key and voice biometric centroid (feature vector) into a single identity bundle, then splitting that bundle using Shamir Secret Sharing (SSS) so that recovery of a threshold number of shares reconstructs both the cryptographic signing key and the enrolled voiceprint in a single operation. The identity bundle is a JSON envelope containing the private key in hexadecimal form, the voice centroid vector, the embedding type, the enrollment sample count, and a voiceprint hash. This bundle is serialized to bytes and split into N shares (default 5) with a reconstruction threshold of K shares (default 3). Each share is individually encrypted with AES-256-GCM using a passphrase-derived key (PBKDF2, 100,000 iterations) before storage or distribution.

Key innovations:
- Combined biometric and cryptographic recovery: Shamir splitting is applied to the entire identity bundle rather than just the private key, so that recovering the threshold number of shares restores both the signing key and the voice biometric centroid without requiring voice re-enrollment.
- Privacy-preserving share distribution: Each share individually reveals nothing about the key or the centroid (information-theoretically secure below threshold), and AES-256-GCM encryption adds a second protective layer even if shares are exposed.
- Flexible distribution model: Shares can be stored on a server (encrypted), distributed to trusted contacts, saved to USB drives, or printed as QR codes.
- Elimination of re-enrollment burden: Users who lose their device recover their full identity (key + voiceprint) in one step, avoiding the requirement to provide 3+ new voice samples.

---

## 2. Problem Statement

### 2.1 Key Recovery Without Biometric Recovery

Existing Shamir Secret Sharing implementations (such as those used in 1Password, HashiCorp Vault, and cryptocurrency wallet recovery) split only cryptographic keys or seed phrases. When a user loses a device that held both an Ed25519 private key and a voice biometric enrollment, recovering the key alone is insufficient. The user must also re-enroll their voice by providing 3 or more fresh voice samples, a process that is burdensome, time-sensitive, and error-prone.

### 2.2 Voice Enrollment Is Costly to Repeat

Voice biometric enrollment as described in PAD-026 requires:
- A minimum of 3 high-quality voice samples.
- A quiet environment with consistent microphone characteristics.
- User cooperation and time (typically 2-5 minutes).

For elderly users, users with speech impairments, or users in noisy environments, re-enrollment is especially difficult. In enterprise settings, coordinating re-enrollment across a fleet of devices adds operational overhead.

### 2.3 Device Loss Destroys Two Independent Assets

A lost or destroyed device results in the simultaneous loss of two independent identity assets:
1. The Ed25519 private key (used for signing Vouch-Tokens and authenticating the DID).
2. The voice biometric centroid (used for voice ownership verification per PAD-026).

No existing system provides a unified recovery mechanism for both assets. Users must follow two separate recovery workflows: one for the key and one for the voiceprint.

### 2.4 No Existing System Bundles Biometric Data with Shamir Splitting

A review of prior art shows:
- Standard Shamir implementations split only keys, secrets, or seed phrases.
- Voice biometric systems do not incorporate any secret sharing recovery mechanism.
- No system combines DID-bound identity, voice biometric centroids, and Shamir Secret Sharing into a single recovery protocol.

---

## 3. Solution (The Invention)

### 3.1 Identity Bundle Construction

The system constructs an identity bundle that packages both the cryptographic key and the voice biometric enrollment into a single JSON envelope:

```json
{
  "version": 1,
  "privateKey": "a3b2c1d4e5f6...64_hex_chars",
  "voiceCentroid": {
    "vector": [0.234, -0.891, 0.456, ...],
    "embeddingType": "dsp_basic",
    "sampleCount": 5,
    "voiceprintHash": "e7a1b3c5d9f2..."
  }
}
```

Fields:
- `version`: Integer schema version for forward compatibility.
- `privateKey`: The Ed25519 private key encoded as a hexadecimal string (64 characters for 32 bytes).
- `voiceCentroid.vector`: The centroid feature vector (13 floats for `dsp_basic`, 192 floats for `ml_ecapa`).
- `voiceCentroid.embeddingType`: Either `"dsp_basic"` (13-dimensional DSP features) or `"ml_ecapa"` (192-dimensional ECAPA-TDNN embeddings).
- `voiceCentroid.sampleCount`: The number of enrollment samples used to compute the centroid.
- `voiceCentroid.voiceprintHash`: The SHA-256 truncated hash of the centroid as defined in PAD-026.

The maximum bundle size is approximately 4KB: 32 bytes for the private key, up to 1.5KB for the centroid JSON (192 floats at full precision), and the remaining metadata.

### 3.2 Shamir Secret Sharing Split

The identity bundle is serialized to a byte array (UTF-8 encoded JSON), then split using Shamir Secret Sharing over GF(256):

1. A random polynomial of degree K-1 is generated for each byte of the serialized bundle, with the secret byte as the constant term.
2. The polynomial is evaluated at N distinct non-zero points in GF(256) to produce N shares.
3. Lagrange interpolation over any K of the N shares recovers the original polynomial and thus the secret byte.

Default parameters:
- N = 5 (total shares generated)
- K = 3 (threshold for reconstruction)

This means any 3 of the 5 shares are sufficient to reconstruct the full identity bundle. Fewer than 3 shares reveal no information about the bundle (information-theoretic security).

### 3.3 Share Encryption

Before storage or distribution, each share is individually encrypted:

1. The user provides a passphrase (never transmitted to any server).
2. A 16-byte random salt is generated.
3. PBKDF2-HMAC-SHA-256 with 100,000 iterations derives a 256-bit AES key from the passphrase and salt.
4. A 12-byte random IV is generated.
5. The share data is encrypted with AES-256-GCM, producing ciphertext and a 16-byte authentication tag.
6. The encrypted share is formatted as: `VOUCH-SHARE:<index>:<hexdata>`

The `<hexdata>` portion encodes the salt, IV, authentication tag, and ciphertext in a deterministic layout.

This dual protection (Shamir threshold + AES encryption) means that an attacker who obtains fewer than K shares learns nothing, and an attacker who obtains K or more shares but lacks the passphrase still cannot decrypt them.

### 3.4 Share Distribution

Shares can be distributed through multiple channels:

| Channel | Description | Security Properties |
|---------|-------------|---------------------|
| Server (encrypted) | One share stored on the server | Protected by AES-256-GCM; server cannot decrypt without passphrase |
| Trusted contacts | Shares given to family members or colleagues | Each contact holds one share; no single contact can reconstruct |
| USB drive | Share saved to a physical storage device | Offline storage; immune to network attacks |
| Printed QR code | Share encoded as a QR code and printed on paper | Air-gapped; survives digital device failure |

The recommended distribution for a 5-share, 3-threshold configuration:
- 1 share on the server (encrypted)
- 2 shares to trusted contacts
- 1 share on a USB drive
- 1 share as a printed QR code

### 3.5 Recovery Process

When a user needs to recover their identity:

1. The user collects at least K (default 3) shares from their distributed storage locations.
2. For each share, the user enters their passphrase to decrypt the AES-256-GCM layer.
3. The decrypted shares are combined using Lagrange interpolation over GF(256).
4. The resulting byte array is deserialized from UTF-8 JSON into the identity bundle.
5. The Ed25519 private key is restored from the `privateKey` field.
6. The voice biometric centroid is restored from the `voiceCentroid` field.
7. The DID is re-derived from the Ed25519 public key (computed from the restored private key).
8. The voice enrollment is restored to the new device without requiring any new voice samples.

The user is immediately able to sign Vouch-Tokens and pass voice verification checks, with no re-enrollment step.

### 3.6 Privacy Properties

1. **Information-theoretic security below threshold:** Fewer than K shares reveal absolutely no information about the identity bundle. This is a mathematical property of Shamir Secret Sharing, not dependent on computational hardness.
2. **Non-invertible voice centroid:** The centroid vector (13 or 192 floating-point numbers) is a lossy, many-to-one mapping from voice audio. It cannot be used to reconstruct intelligible speech or the original voice recordings.
3. **Passphrase never leaves the client:** The AES encryption passphrase is entered on the user's device and used locally for key derivation. It is never transmitted to any server.
4. **No raw audio in the bundle:** The bundle contains only the mathematical centroid vector, not raw audio samples or high-fidelity spectrograms.
5. **Deletion and revocation:** If a user suspects share compromise, they can generate a new identity bundle with a fresh key and new voice enrollment, invalidating all previous shares.

---

## 4. Prior Art Differentiation

### 4.1 Existing Shamir Secret Sharing Systems

| System | What Is Split | Biometric Recovery | DID Binding |
|--------|---------------|-------------------|-------------|
| 1Password Emergency Kit | Master password / secret key | No | No |
| HashiCorp Vault (Unseal) | Master encryption key | No | No |
| Cryptocurrency wallets (BIP39) | Seed phrase / private key | No | No |
| SLIP-0039 (Shamir Backup) | Wallet seed | No | No |
| This disclosure | Private key + voice centroid bundle | Yes | Yes |

### 4.2 Existing Voice Biometric Systems

| System | Recovery Mechanism | Secret Sharing | Key Bundling |
|--------|-------------------|----------------|--------------|
| Azure Speaker Recognition | Re-enrollment required | No | No |
| AWS Voice ID | Re-enrollment required | No | No |
| Apple Siri Voice Recognition | Device-bound, no export | No | No |
| PAD-026 (Vouch Voice ID) | Re-enrollment required | No | No |
| This disclosure | Shamir recovery of centroid | Yes | Yes |

### 4.3 Novel Combination

This disclosure is the first to combine:
1. **DID-bound cryptographic identity** (Ed25519 private key tied to a Decentralized Identifier).
2. **Voice biometric centroid** (multi-sample averaged feature vector per PAD-026).
3. **Shamir Secret Sharing** (information-theoretically secure threshold splitting).
4. **AES-256-GCM encryption** (passphrase-protected share storage).
5. **Unified recovery** (single reconstruction step restores both signing capability and voice enrollment).

No existing system, product, or publication combines all five elements.

---

## 5. Technical Specifications

### 5.1 Identity Bundle Schema

```json
{
  "version": 1,
  "privateKey": "<64-character hex string, 32 bytes Ed25519 seed>",
  "voiceCentroid": {
    "vector": ["<array of 13 or 192 IEEE 754 float64 values>"],
    "embeddingType": "dsp_basic | ml_ecapa",
    "sampleCount": "<integer, minimum 3>",
    "voiceprintHash": "<32-character hex string, SHA-256 truncated>"
  }
}
```

### 5.2 Bundle Size Estimates

| Component | Size (bytes) | Notes |
|-----------|-------------|-------|
| Version + metadata | ~50 | JSON keys and formatting |
| Private key (hex) | 64 | 32 bytes as hex |
| Centroid (dsp_basic, 13 floats) | ~200 | JSON array of 13 floats |
| Centroid (ml_ecapa, 192 floats) | ~1,500 | JSON array of 192 floats |
| Embedding type + sample count | ~50 | String + integer |
| Voiceprint hash | 32 | Hex string |
| **Total (dsp_basic)** | **~400** | |
| **Total (ml_ecapa)** | **~1,700** | |
| **Maximum with overhead** | **~4,000** | Conservative upper bound |

### 5.3 Shamir Parameters

| Parameter | Default | Range | Notes |
|-----------|---------|-------|-------|
| Total shares (N) | 5 | 2-255 | GF(256) limits maximum to 255 |
| Threshold (K) | 3 | 2-N | Minimum shares for reconstruction |
| Field | GF(256) | Fixed | Galois Field with 256 elements |
| Polynomial degree | K-1 = 2 | 1-254 | Determined by threshold |
| Evaluation points | 1 through N | Non-zero elements of GF(256) | Each share uses a distinct point |

### 5.4 Encryption Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Cipher | AES-256-GCM | Authenticated encryption |
| Key derivation | PBKDF2-HMAC-SHA-256 | Password-based key derivation |
| PBKDF2 iterations | 100,000 | Tuned for client-side performance |
| Salt length | 16 bytes | Random per share |
| IV length | 12 bytes | Random per encryption |
| Auth tag length | 16 bytes | GCM default |
| Key length | 256 bits | Derived from passphrase |

### 5.5 Share Format

Each encrypted share is encoded as:

```
VOUCH-SHARE:<index>:<hexdata>
```

Where:
- `<index>` is the share index (1 through N), encoded as a decimal integer.
- `<hexdata>` is the hexadecimal encoding of: `salt (16 bytes) || iv (12 bytes) || tag (16 bytes) || ciphertext (variable)`.

Example:
```
VOUCH-SHARE:3:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...
```

### 5.6 Recovery Verification

After reconstruction, the system validates the recovered bundle:
1. Parse the JSON and verify the `version` field.
2. Derive the Ed25519 public key from the recovered private key.
3. Recompute the DID from the public key and verify it matches the expected DID.
4. Recompute the voiceprint hash from the recovered centroid vector and verify it matches `voiceprintHash`.
5. If all checks pass, the recovery is accepted and the identity is restored.

---

## 6. Use Cases

### 6.1 Professional User Device Loss

A professional user loses their phone, which held their Ed25519 private key and voice enrollment. They contact two trusted colleagues who hold shares, retrieve their server-stored share, and combine the three shares on their new device. Both the signing key and the voice centroid are restored. The user can immediately sign documents and pass voice verification without recording 3 new voice samples.

### 6.2 Senior Citizen Assisted Recovery

An elderly user has their shares distributed among family members. When the user gets a new device, a family member helps them collect 3 shares and enter the passphrase. The full identity is restored in a single step, avoiding the difficulty of re-enrollment for someone who may struggle with the voice recording process.

### 6.3 Enterprise Fleet Recovery

An IT administrator manages identity recovery for a corporate fleet. When an employee's device is lost or replaced, the administrator retrieves the server-stored share and coordinates with the employee's designated recovery contacts. The employee's signing key and voice enrollment are restored without requiring a visit to an enrollment station or a supervised voice recording session.

### 6.4 Cross-Device Migration

A user purchases a new device and wants to migrate their full identity. They retrieve 3 of their 5 shares (for example, from the server, a USB drive, and a trusted contact), enter their passphrase, and restore both the signing key and voice enrollment on the new device. The migration is complete in one step rather than requiring separate key import and voice re-enrollment workflows.

---

## 7. Conclusion

This disclosure describes a method for bundling an Ed25519 private key and a voice biometric centroid into a single identity bundle, splitting that bundle using Shamir Secret Sharing, encrypting each share with AES-256-GCM, and distributing the encrypted shares across multiple storage channels. The core innovation is that Shamir splitting is applied to the combined identity bundle rather than the private key alone, so that recovering the threshold number of shares restores both cryptographic signing capability and voice biometric enrollment in a single step. This eliminates the need for voice re-enrollment after device loss, reduces recovery friction for all users (especially elderly and enterprise users), and preserves the privacy properties of both the key and the centroid through information-theoretic security below the threshold and AES encryption above it.

---

## 8. References

- A. Shamir, "How to Share a Secret" (Communications of the ACM, 1979)
- W3C Decentralized Identifiers (DIDs) v1.0
- NIST SP 800-132 (Recommendation for Password-Based Key Derivation)
- NIST SP 800-38D (Recommendation for Block Cipher Modes of Operation: GCM)
- RFC 7518 (JSON Web Algorithms)
- B. Desplanques et al., "ECAPA-TDNN: Emphasized Channel Attention, Propagation and Aggregation in TDNN Based Speaker Verification" (Interspeech 2020)
- SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes (SatoshiLabs)
- Vouch Protocol: PAD-001 (Cryptographic Agent Identity), PAD-014 (Vouch Sonic), PAD-026 (DID-Linked Voiceprint Enrollment)

---

**License:** This disclosure is published under Creative Commons CC0 1.0 Universal (Public Domain Dedication). It is released as defensive prior art to prevent patent monopolization of the described techniques. Anyone is free to implement, modify, and extend this system without restriction.

**Prior Art Declaration:** This document establishes prior art effective February 28, 2026, under 35 U.S.C. Section 102(a)(1) and equivalent international provisions.
