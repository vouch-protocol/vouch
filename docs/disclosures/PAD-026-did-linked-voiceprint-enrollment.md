# PAD-026: DID-Linked Voiceprint Enrollment with Privacy-Preserving Feature Vectors

**Identifier:** PAD-026
**Title:** Method for Decentralized Identity-Linked Voice Biometric Enrollment Using Privacy-Preserving Feature Vectors and Centroid Averaging
**Publication Date:** February 28, 2026
**Prior Art Effective Date:** February 28, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Biometric Authentication / Voice Processing / Decentralized Identity / Privacy
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-014 (Vouch Sonic), PAD-025 (Edge-First Content Provenance), PAD-001 (Cryptographic Agent Identity)

---

## 1. Abstract

A system and method for enrolling and verifying voice ownership using mathematical feature vectors cryptographically bound to a Decentralized Identifier (DID). The system extracts a fixed-dimensional feature vector from voice audio, never stores the raw audio recording, and binds the resulting voiceprint to an Ed25519-backed DID.

Key innovations:
- Multi-sample centroid averaging: Multiple enrollment samples are averaged into a centroid vector that is more robust than any single sample.
- Cosine similarity verification: Voice matching uses cosine similarity against the stored centroid, with a configurable threshold (default 0.85).
- Embedding type migration: The system supports transparent upgrade from basic DSP features (13-dimensional) to ML-derived embeddings (192-dimensional ECAPA-TDNN) without breaking existing enrollments.
- Privacy by construction: Only mathematical feature vectors (non-invertible) are stored. Raw voice recordings are processed and discarded on the client device.
- Cryptographic proof of voice ownership: Successful voice verification triggers issuance of a signed Vouch-Token (Ed25519 JWT) that proves the verified voice belongs to the claimed DID.

---

## 2. Problem Statement

### 2.1 Voice Cloning Threat

Modern AI voice synthesis can clone a person's voice from minutes of sample audio. Once cloned, synthetic speech is indistinguishable from the original by human listeners. This enables:
- Impersonation in phone calls and voice messages.
- Fabricated audio evidence in legal proceedings.
- Unauthorized voice acting and narration.
- Social engineering attacks using trusted voices.

There is no widely deployed mechanism for individuals to prove "this is my voice" with cryptographic certainty.

### 2.2 Centralized Voice Biometric Risks

Existing voice biometric systems (Azure Speaker Recognition, AWS Voice ID, Nuance) are centralized:
- Voice samples are uploaded to and processed on cloud servers.
- The biometric data is controlled by the cloud provider.
- Users cannot independently verify or revoke their voiceprint.
- A breach exposes raw voice data or high-fidelity embeddings.
- The biometric is not bound to a portable, user-controlled identity.

### 2.3 Single-Sample Fragility

Many voice enrollment systems capture a single voice sample and derive a voiceprint from it. This is fragile because:
- A single sample captures a snapshot of voice characteristics that vary naturally (time of day, health, emotional state, microphone quality).
- Verification against a single-sample enrollment produces high false-rejection rates.
- Users must re-enroll when conditions change, losing continuity.

### 2.4 Identity Binding Gap

Even systems that perform voice verification well do not bind the result to a portable, cryptographic identity:
- Cloud voice APIs return a match/no-match boolean, but do not issue a signed attestation.
- The verification result cannot be independently audited by third parties.
- There is no standard for "proving to someone else that my voice was verified."

---

## 3. Solution (The Invention)

### 3.1 System Architecture

The voice enrollment and verification system has three layers:

**Layer 1: Feature Extraction (Client-Side)**
Voice audio is processed on the user's device to produce a fixed-dimensional feature vector. Two extraction methods are supported:

*DSP Basic (13-dimensional):*
1. Zero-crossing rate (temporal roughness measure)
2. RMS energy (loudness)
3. Spectral centroid (brightness of the spectrum)
4. Fundamental frequency F0 via normalized autocorrelation (pitch)
5. Spectral bandwidth (spread of the spectrum)
6. Spectral rolloff at 85% energy threshold (high-frequency content)
7. Spectral flatness (tonality vs. noise ratio)
8. Six mel-scale band energies (0-200, 200-500, 500-1k, 1k-2k, 2k-4k, 4k-8k Hz)

*ML Enhanced (192-dimensional):*
ECAPA-TDNN speaker verification model running via ONNX Runtime Web on the client device. Produces a 192-dimensional embedding in a learned speaker space.

Both methods produce vectors that can be compared using cosine similarity.

**Layer 2: Enrollment and Storage (Server-Side)**
The server stores:
- Feature vectors from each enrollment sample (`voiceid:{did}:features` list)
- Centroid average recomputed after each new sample (`voiceid:{did}:avg`)
- Enrollment metadata: sample count, embedding type, timestamps, voiceprint hash

The server never receives or stores raw audio.

**Layer 3: Verification and Proof (Server-Side)**
When verification succeeds (cosine similarity >= threshold), the server issues a signed Vouch-Token:
```json
{
  "type": "voice_verification",
  "did": "did:key:z6Mk...",
  "confidence": 92,
  "method": "cosine_similarity",
  "embeddingType": "ml_ecapa",
  "verifiedAt": "2026-02-28T12:00:00Z",
  "signature": "ed25519_signature"
}
```

This token is a portable, cryptographically signed proof that the voice was verified against the DID's enrolled voiceprint.

### 3.2 Multi-Sample Centroid Averaging

Instead of storing a single voiceprint, the system collects multiple enrollment samples and averages their feature vectors:

```
Sample 1 -> extract features -> [f1_1, f1_2, ..., f1_n]
Sample 2 -> extract features -> [f2_1, f2_2, ..., f2_n]
Sample 3 -> extract features -> [f3_1, f3_2, ..., f3_n]
                                        |
                                        v
                              Centroid = mean([S1, S2, S3])
                              = [(f1_1+f2_1+f3_1)/3, ...]
```

Benefits:
- The centroid is more stable than any individual sample.
- Natural voice variation (morning vs. evening, different microphones) is captured.
- Adding more samples incrementally improves the centroid without re-enrollment.
- Minimum 3 samples required before verification is activated (configurable).

The centroid is recomputed after each new enrollment sample, stored separately from individual vectors.

### 3.3 Cosine Similarity Verification

Verification compares the test feature vector against the stored centroid:

```
similarity = dot(test, centroid) / (||test|| * ||centroid|| + epsilon)
match = similarity >= 0.85
confidence = round(similarity * 100)
```

Properties:
- Scale-invariant (does not depend on absolute magnitude of features).
- Symmetric (comparing A to B gives the same result as B to A).
- Bounded between -1 and 1 (with voice features typically between 0.5 and 1.0).
- Epsilon (1e-10) prevents division by zero for edge cases.

The threshold (0.85) is tuned for the balance between security (rejecting imposters) and usability (accepting natural voice variation). It is configurable per deployment.

### 3.4 Embedding Type Migration

The system supports two embedding types that can coexist:

| Property | dsp_basic | ml_ecapa |
|----------|-----------|----------|
| Dimensions | 13 | 192 |
| Extraction | Deterministic DSP | Neural network inference |
| Client requirements | Any browser (WASM) | Browser with ONNX support |
| Accuracy | Moderate | High |
| Model size | 0 KB (algorithmic) | ~3 MB (quantized ONNX) |

Migration behavior:
1. User enrolls with `dsp_basic` (default, works everywhere).
2. Later, user opts into `ml_ecapa` (higher accuracy, requires model download).
3. System detects embedding type change, clears old enrollment vectors.
4. User re-enrolls with 3 new samples using the ML model.
5. Old `dsp_basic` enrollment is cleanly replaced.

The `embeddingType` field in the enrollment record ensures verification always uses matching dimensionality. A `dsp_basic` test vector is never compared against an `ml_ecapa` centroid.

### 3.5 Voiceprint Hash and Reverse Lookup

The centroid vector is hashed into a 32-character hex string:

```
voiceprint_hash = SHA-256(
  round(centroid[0] * 10000) + ":" +
  round(centroid[1] * 10000) + ":" +
  ...
).hex()[0:32]
```

This hash serves as a compact, one-way identifier for the voiceprint. A reverse lookup table (`voiceid:print:{hash}` -> `did`) enables looking up the DID from a voiceprint match, similar to how PAD-005 enables reverse signature lookup.

### 3.6 Privacy Properties

1. **No raw audio storage:** Voice recordings are processed on the client device and immediately discarded. Only feature vectors are transmitted.
2. **Non-invertible features:** A 13-dimensional or 192-dimensional feature vector cannot be used to reconstruct intelligible speech. The extraction is a lossy, many-to-one mapping.
3. **One-way voiceprint hash:** The SHA-256 hash of the centroid cannot be reversed to recover the centroid values.
4. **DID portability:** The voiceprint is bound to a DID, not to a platform account. The user controls the DID via their Ed25519 private key.
5. **Deletion:** Users can delete their Voice ID at any time, which removes all feature vectors, the centroid, and the reverse lookup entry.

---

## 4. Prior Art Differentiation

### 4.1 Existing Voice Biometric Systems

| System | Identity Binding | Audio Privacy | Multi-Sample | Cryptographic Proof |
|--------|-----------------|---------------|-------------|-------------------|
| Azure Speaker Recognition | Azure account | Audio uploaded to Azure | Single profile | No signed token |
| AWS Voice ID | AWS account | Audio uploaded to AWS | Streaming enrollment | No signed token |
| Apple Siri Voice Recognition | Apple ID | On-device (iOS only) | Continuous learning | No signed token |
| This disclosure | Ed25519 DID | On-device (any browser) | Centroid averaging | Vouch-Token (Ed25519 JWT) |

### 4.2 Novel Combinations

This disclosure combines:
- **Decentralized identity (DIDs)** for portable, user-controlled identity binding.
- **Multi-sample centroid averaging** for robust enrollment that improves over time.
- **Embedding type migration** for transparent upgrade from DSP to ML without enrollment loss.
- **Cryptographic verification proof** (Vouch-Token) for third-party auditable voice ownership claims.
- **Client-side processing** (WASM/ONNX) for raw audio privacy.

No existing system combines all five properties.

### 4.3 Differences from Speaker Verification Literature

Traditional speaker verification (i-vectors, x-vectors, ECAPA-TDNN) focuses on the ML model accuracy. This disclosure focuses on the system-level architecture: how the model output is enrolled, stored, averaged, migrated, bound to a DID, and used to issue cryptographic proofs.

---

## 5. Technical Specifications

### 5.1 Feature Vector Schema

**DSP Basic (13-dim):**

| Index | Feature | Range | Description |
|-------|---------|-------|-------------|
| 0 | ZCR | [0, 1] | Zero-crossing rate |
| 1 | RMS | [0, 1] | Root mean square energy |
| 2 | Centroid | [0, sampleRate/2] Hz | Spectral center of mass |
| 3 | F0 | [60, 400] Hz or 0 | Fundamental frequency |
| 4 | Bandwidth | [0, sampleRate/2] Hz | Spectral spread |
| 5 | Rolloff | [0, sampleRate/2] Hz | 85% energy frequency |
| 6 | Flatness | [0, 1] | Geometric/arithmetic mean ratio |
| 7-12 | Mel bands | log scale | 6 mel-scale band energies |

**ML Enhanced (192-dim):**
- Normalized embedding vector from ECAPA-TDNN.
- Values typically in [-1, 1] range after L2 normalization.

### 5.2 Redis Storage Schema

```
voiceid:{did}              -> Hash: {did, displayName, voiceprintHash,
                                     enrolledAt, updatedAt, sampleCount,
                                     embeddingType}
voiceid:{did}:features     -> List: [JSON(vector1), JSON(vector2), ...]
voiceid:{did}:avg          -> String: JSON(centroid_vector)
voiceid:print:{hash}       -> String: did (reverse lookup)
```

### 5.3 Verification Thresholds

| Scenario | Threshold | Rationale |
|----------|-----------|-----------|
| Same speaker, same microphone | >= 0.92 typical | Minimal variation |
| Same speaker, different microphone | >= 0.85 typical | Acoustic path variation |
| Same speaker, different time of day | >= 0.80 typical | Natural voice variation |
| Different speaker | < 0.60 typical | Distinct vocal characteristics |
| AI voice clone | 0.50 - 0.75 typical | Lacks micro-characteristics |

Default match threshold: 0.85 (configurable per deployment).

### 5.4 Minimum Enrollment Requirements

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Minimum samples | 3 | Statistical stability of centroid |
| Minimum duration per sample | 2 seconds | Sufficient for F0 and spectral features |
| Maximum samples | Unlimited | More samples improve centroid |
| Sample rate | >= 16000 Hz | Nyquist for voice frequencies |

---

## 6. Use Cases

### 6.1 Podcaster Voice Ownership Proof
A podcaster enrolls their Voice ID with 5 samples. When an AI-generated clone of their voice appears online, they can prove ownership by demonstrating their enrolled voiceprint matches the original recordings but not the clone. The Vouch-Token serves as cryptographic evidence.

### 6.2 Voice Actor Contract Protection
A voice actor enrolls their Voice ID before signing a contract. The contract references their DID. If the studio uses AI to generate additional dialogue without permission, the actor can demonstrate that the AI-generated audio does not match their enrolled voiceprint, proving unauthorized synthesis.

### 6.3 Senior Citizen Scam Protection
An elderly person enrolls their family members' Voice IDs. When receiving a phone call claiming to be from a family member, they can verify the caller's voice against the enrolled voiceprint. AI-cloned voices typically score below the 0.85 threshold, flagging the call as suspicious.

### 6.4 Legal Audio Evidence
A lawyer enrolls a client's Voice ID. When audio evidence is submitted in court, the lawyer can verify whether the voice in the recording matches the client's enrolled voiceprint. The Vouch-Token provides a cryptographically signed, timestamped verification result that can be presented as evidence.

### 6.5 Migration from Basic to Enhanced
A user starts with DSP-based enrollment (works on any device). Later, they upgrade to ML-enhanced enrollment (download ~3MB model). The system detects the embedding type change, prompts for 3 new samples, and smoothly replaces the old enrollment. The user's DID and enrollment history are preserved.

---

## 7. Conclusion

This disclosure describes a voice biometric enrollment and verification system that binds voiceprints to decentralized identities (DIDs), processes all audio locally on the user's device, stores only non-invertible feature vectors, supports incremental improvement through centroid averaging, enables transparent migration between extraction methods, and issues cryptographically signed proofs of voice ownership. The combination of privacy-preserving architecture, DID-based identity binding, and portable verification tokens creates a system for proving voice ownership that is both technically robust and respectful of user privacy.

---

## 8. References

- W3C Decentralized Identifiers (DIDs) v1.0
- B. Desplanques et al., "ECAPA-TDNN: Emphasized Channel Attention, Propagation and Aggregation in TDNN Based Speaker Verification" (Interspeech 2020)
- D. Snyder et al., "X-Vectors: Robust DNN Embeddings for Speaker Recognition" (ICASSP 2018)
- ONNX Runtime Web (Microsoft)
- Vouch Protocol: PAD-001 (Cryptographic Agent Identity), PAD-014 (Vouch Sonic), PAD-025 (Edge-First Content Provenance)
- RFC 7518 (JSON Web Algorithms)
- A. Shamir, "How to Share a Secret" (Communications of the ACM, 1979)

---

**License:** This disclosure is published under Creative Commons CC0 1.0 Universal (Public Domain Dedication). It is released as defensive prior art to prevent patent monopolization of the described techniques. Anyone is free to implement, modify, and extend this system without restriction.

**Prior Art Declaration:** This document establishes prior art effective February 28, 2026, under 35 U.S.C. Section 102(a)(1) and equivalent international provisions.
