# PAD-028: Unified Cross-Modal Identity-Bound Provenance System

**Identifier:** PAD-028
**Title:** Method for Unified Cross-Modal Content Provenance Under a Single Decentralized Identifier
**Publication Date:** March 1, 2026
**Prior Art Effective Date:** March 1, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Content Authentication / Multi-Modal Provenance / Decentralized Identity / Media Security
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-014 (Vouch Sonic), PAD-026 (DID-Linked Voiceprint Enrollment), PAD-025 (Edge-First Content Provenance), PAD-001 (Cryptographic Agent Identity)

---

## 1. Abstract

A system and method for establishing verifiable content provenance across multiple media modalities — images, audio, video, documents, and voice — under a single cryptographic identity (Decentralized Identifier backed by Ed25519). Unlike existing provenance systems that operate on a single content type using a single mechanism, this system unifies five independent provenance technologies under one identity:

1. **Image provenance** via C2PA Content Credentials (embedded JUMBF manifests with Ed25519 signatures).
2. **Audio provenance** via psychoacoustic steganographic watermarking (Vouch Sonic, as disclosed in PAD-014) binding a DID into the audio waveform.
3. **Voice provenance** via DID-linked voice biometric enrollment (as disclosed in PAD-026) proving the speaker's identity through centroid-averaged feature vectors.
4. **Video provenance** via frame-level deepfake detection combined with temporal perceptual fingerprinting and C2PA signing.
5. **Document provenance** via C2PA Content Credentials applied to PDF and other document formats.

The key innovation is the **cross-modal verification graph**: any piece of content signed through any modality can be traced back to the same DID, enabling a verifier to establish that the same entity (person, organization, or AI agent) produced content across different media types. The system maintains a server-side provenance registry that indexes all signing events by DID, creating a unified audit trail regardless of content modality.

Furthermore, the system enables **cross-modal corroboration**: when a video contains both a C2PA-signed visual track and a Sonic-watermarked audio track, and the speaker's voice matches a DID-enrolled voiceprint, three independent verification mechanisms corroborate the same identity. The probability of all three being spoofed simultaneously is the product of their individual spoofing probabilities, providing exponentially stronger provenance than any single modality alone.

---

## 2. Problem Statement

### 2.1 Modality-Siloed Provenance

Existing content provenance systems operate in isolation:
- **C2PA** handles images and some video formats, but does not address audio watermarking or voice biometrics.
- **Audio watermarking systems** (Digimarc, Veritone) embed provenance in audio but have no connection to image signing or identity verification.
- **Voice biometric systems** (Nuance, Azure Speaker Recognition) verify speaker identity but do not produce provenance credentials that can be embedded in content.
- **Video authentication** tools detect deepfakes but do not cryptographically sign the verified content.

No system unifies these modalities under a single cryptographic identity. Consequently:
- An enterprise cannot prove that the same camera operator who captured a photo also recorded the accompanying audio narration.
- A journalist cannot cryptographically demonstrate that their published article, the photos within it, the audio interview it references, and the video footage it cites were all produced by the same verified identity.
- A content platform cannot cross-reference image provenance with audio provenance to detect misattribution.

### 2.2 Identity Fragmentation

Each provenance system maintains its own identity namespace:
- C2PA uses X.509 certificates.
- Audio watermarking services use proprietary account identifiers.
- Voice biometric systems use enrollment IDs tied to specific cloud providers.

A single content creator must maintain separate identities across each system, with no cryptographic link between them. There is no mechanism for a verifier to confirm that a C2PA-signed image and a watermarked audio file originate from the same entity.

### 2.3 The Compound Media Problem

Modern content is increasingly multi-modal. A social media post may contain an image, a caption, an audio clip, and a video. A news article includes text, photographs, embedded audio, and video. A legal filing contains documents, photographic evidence, and audio recordings. Currently, each piece of content must be verified independently using different tools, different identity systems, and different trust models. There is no unified verification that spans all media types in a single operation.

---

## 3. Solution (The Invention)

### 3.1 Unified Identity Layer

The system establishes a single Ed25519-backed DID as the root identity for all provenance operations. This DID is:
- Generated once and stored securely (on-device, with optional Shamir backup per PAD-027).
- Registered with a Vouch Protocol-compatible registry.
- Used as the signing identity for ALL content types.

The DID's public key is embedded in:
- C2PA manifests as the signer identity (for images and documents).
- Sonic watermark payloads (for audio).
- Voice biometric enrollment records (linking voiceprint to DID).
- Video signing manifests (for authenticated video).

### 3.2 Cross-Modal Provenance Registry

A server-side registry indexes all signing events by DID:

```json
{
  "did": "did:vouch:abc123",
  "provenance_events": [
    {
      "modality": "image",
      "mechanism": "c2pa",
      "content_hash": "sha256:...",
      "signed_at": "2026-03-01T10:00:00Z",
      "provenance": "captured"
    },
    {
      "modality": "audio",
      "mechanism": "sonic_watermark",
      "watermark_id": "wm_xyz",
      "audio_hash": "sha256:...",
      "embedded_at": "2026-03-01T10:00:05Z"
    },
    {
      "modality": "voice",
      "mechanism": "voiceprint_verification",
      "match_score": 0.94,
      "verified_at": "2026-03-01T10:00:10Z"
    },
    {
      "modality": "document",
      "mechanism": "c2pa",
      "content_hash": "sha256:...",
      "mime_type": "application/pdf",
      "signed_at": "2026-03-01T10:01:00Z"
    }
  ]
}
```

This registry enables:
- **Single-DID provenance lookup:** Given a DID, retrieve all content ever signed by that identity across all modalities.
- **Content-to-identity resolution:** Given any piece of content (image hash, watermark ID, document hash), resolve to the signing DID and discover all other content from the same identity.
- **Temporal correlation:** Identify content produced within the same time window by the same DID across different modalities (e.g., a photo and audio recorded at the same event).

### 3.3 Cross-Modal Corroboration

When multiple modalities verify the same DID simultaneously, the system computes a **compound confidence score**:

Let $p_i$ be the probability of spoofing modality $i$ independently. The compound spoofing probability is:

$$P_{compound} = \prod_{i=1}^{n} p_i$$

For three modalities with individual spoofing probabilities of $10^{-3}$ each:

$$P_{compound} = 10^{-3} \times 10^{-3} \times 10^{-3} = 10^{-9}$$

This exponential reduction in spoofing probability is a direct consequence of the independence of the verification mechanisms (C2PA cryptographic signature, psychoacoustic watermark detection, and voice biometric matching operate on different physical properties of the content).

The system reports this compound score to the verifier:

```json
{
  "verification": {
    "did": "did:vouch:abc123",
    "modalities_verified": ["image_c2pa", "audio_sonic", "voice_biometric"],
    "individual_scores": {
      "image_c2pa": { "valid": true, "confidence": 1.0 },
      "audio_sonic": { "detected": true, "confidence": 0.97 },
      "voice_biometric": { "match": true, "similarity": 0.94 }
    },
    "compound_confidence": 0.9999999,
    "corroboration_level": "triple_verified"
  }
}
```

### 3.4 Enterprise Cross-Modal Provenance

For enterprise use cases, the system extends cross-modal provenance with enterprise identity:
- All content signed under the enterprise's verified identity includes a `cygn.enterprise` assertion identifying the organization.
- The enterprise DID is counter-signed by the service provider (see related patent filing for Content Provenance Certificate Authority).
- Enterprise provenance labels (e.g., "Captured by Zomato") are consistent across all modalities: the same label appears in C2PA manifests, is retrievable from Sonic watermark lookups, and is associated with voice-verified recordings.

### 3.5 Verification API

A single verification endpoint accepts any content type and returns unified provenance:

```
POST /api/v1/verify/multi-modal
Content-Type: application/json

{
  "image": "<base64>",
  "audio": "<base64>",
  "video": "<base64>"
}

Response:
{
  "results": [
    { "modality": "image", "did": "did:vouch:abc123", "mechanism": "c2pa", "valid": true },
    { "modality": "audio", "did": "did:vouch:abc123", "mechanism": "sonic", "detected": true },
    { "modality": "video", "did": "did:vouch:abc123", "mechanism": "c2pa+deepfake", "valid": true, "authentic": true }
  ],
  "unified_did": "did:vouch:abc123",
  "all_modalities_same_identity": true,
  "compound_confidence": 0.9999999
}
```

---

## 4. Prior Art Differentiation

| System | Modalities | Unified Identity | Cross-Modal Corroboration |
|--------|-----------|-----------------|--------------------------|
| C2PA | Image, some video | X.509 certs (no DID) | No |
| Digimarc | Image, audio | Proprietary IDs | No |
| Azure Speaker Recognition | Voice only | Cloud account | No |
| Truepic | Image capture | X.509 certs | No |
| **This Invention** | **Image, audio, voice, video, document** | **Single Ed25519 DID** | **Yes — compound confidence scoring** |

Key differentiators:
1. **No existing system** uses a single DID across five content modalities.
2. **No existing system** computes compound confidence from independent verification mechanisms across modalities.
3. **No existing system** provides a single API endpoint that accepts multi-modal content and returns unified provenance from a single identity.
4. **No existing system** combines C2PA signing, psychoacoustic watermarking, voice biometrics, and deepfake detection under one cryptographic identity.

---

## 5. Technical Implementation

### 5.1 Identity Binding Per Modality

| Modality | Mechanism | DID Binding Method |
|----------|-----------|-------------------|
| Image | C2PA JUMBF manifest | Ed25519 signature in manifest, DID in `stds.schema-org.CreativeWork` author |
| Audio | Sonic watermark (PAD-014) | DID encoded in spread-spectrum payload |
| Voice | Voiceprint enrollment (PAD-026) | Centroid vector stored keyed by DID |
| Video | C2PA + frame analysis | Ed25519 signature in video manifest, per-frame deepfake scores in assertions |
| Document | C2PA JUMBF manifest | Ed25519 signature, DID in author assertion |

### 5.2 Registry Data Model

```
Key: provenance:{did}:events — Sorted Set (score = timestamp)
Key: provenance:content:{content_hash} — Hash (did, modality, mechanism, signed_at)
Key: provenance:watermark:{watermark_id} — Hash (did, audio_hash, embedded_at)
Key: provenance:voice:{did} — Hash (centroid, embedding_type, enrolled_at)
```

### 5.3 Cross-Modal Query Flow

Given an image with a C2PA manifest:
1. Extract DID from C2PA signature.
2. Query `provenance:{did}:events` for all events.
3. Return all content signed by this DID across all modalities.
4. If audio content exists, highlight that the same identity has watermarked audio.
5. If voice enrollment exists, highlight that the identity has a verified voiceprint.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A system that binds a single Ed25519-backed DID to content provenance across five media modalities (image, audio, voice, video, document) using modality-specific mechanisms (C2PA, psychoacoustic watermarking, voice biometric enrollment, deepfake detection, document signing).

2. A cross-modal provenance registry that indexes all signing events by DID, enabling provenance lookup across modalities from any single piece of verified content.

3. A compound confidence scoring method that multiplies independent spoofing probabilities across verified modalities to produce exponentially stronger provenance assurance than any single modality alone.

4. A unified verification API that accepts multi-modal content in a single request and returns corroborated provenance from a single identity.

5. Enterprise cross-modal provenance where a verified organizational identity (e.g., "Captured by Zomato") is consistently embedded across all content modalities signed by that enterprise.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
