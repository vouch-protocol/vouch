# Defensive Disclosure: Method for Context-Adaptive Semantic Consent in Cryptographic Signing

**Disclosure ID:** PAD-010  
**Publication Date:** January 24, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

A security method for "Human-in-the-Loop" verification of cryptographic signing requests. Unlike traditional ledger signing (which often displays raw hex strings or opaque hashes), this method introduces a **"Semantic Analysis Layer"** within the signing daemon. When a request is received, the system analyzes the `Content-Type` (e.g., `image/jpeg`, `text/x-python`, `application/json`) and renders a human-readable preview (Thumbnail, Syntax-Highlighted Code, or Structured Data) in a secure system-level window. The user must physically approve this "Semantic View" to authorize the signature, implementing **"What You See Is What You Sign" (WYSIWYS)**.

---

## Problem Statement

### The Blind Signing Crisis

Current cryptographic consent mechanisms are fundamentally broken:

- **Blind Signing:** Users approve signing requests for hashes they cannot visually verify, enabling payload swapping attacks
- **Context Loss:** A generic "Sign this?" prompt does not distinguish between signing a trivial chat message and a critical financial transaction
- **In-Band Spoofing:** When the consent UI is rendered by the same application requesting the signature, the UI can be manipulated
- **Media Opacity:** For images/videos, showing a hash like `a7f9c2...` provides zero context about what is being signed
- **Consent Fatigue:** Repeated generic prompts lead users to auto-approve without inspection

### Real-World Exploits

```
Attack Vector: "UI Redressing"
1. Malicious website shows: "Sign: 'Hello World'"
2. Actual payload sent to signer: "Transfer $10,000 to attacker"
3. User sees "Sign?" popup with opaque hash
4. User approves → funds stolen

This attack is IMPOSSIBLE with Semantic Consent because the
user sees the ACTUAL content being signed, not a description.
```

---

## Disclosed Method

We disclose the **"Context-Adaptive Consent Layer"** which functions as a semantic firewall for intent.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SEMANTIC CONSENT LAYER                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  INCOMING REQUEST:                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  POST /sign-media                                                │   │
│  │  Content-Type: image/jpeg                                        │   │
│  │  Origin: https://twitter.com                                     │   │
│  │  Body: [binary image data]                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                           │                                             │
│                           ▼                                             │
│  STEP 1: SEMANTIC DETECTION                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Analyze Content-Type + Magic Bytes:                             │   │
│  │  • image/*      → Image Preview Mode                             │   │
│  │  • video/*      → Video Thumbnail + Icon Mode                    │   │
│  │  • audio/*      → Audio Icon + Waveform Mode                     │   │
│  │  • text/*       → Syntax-Highlighted Text Mode                   │   │
│  │  • application/json → Structured Data Mode                       │   │
│  │  • application/c2pa → Provenance Manifest Mode                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                           │                                             │
│                           ▼                                             │
│  STEP 2: C2PA ANCESTRY CHECK                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Scan for existing provenance data:                              │   │
│  │  • JUMBF boxes (C2PA manifest)                                   │   │
│  │  • XMP metadata with c2pa namespace                              │   │
│  │                                                                   │   │
│  │  If found: ⚠️ "This file is already signed"                      │   │
│  │            "Add your Vouch to the provenance chain?"             │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                           │                                             │
│                           ▼                                             │
│  STEP 3: SECURE RENDERING (Out-of-Band UI)                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  SYSTEM-LEVEL WINDOW (owned by Daemon, NOT by requesting app):   │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │  🔐 MEDIA SIGNATURE REQUEST                              │    │   │
│  │  │                                                          │    │   │
│  │  │  Origin: https://twitter.com                             │    │   │
│  │  │                                                          │    │   │
│  │  │  ┌────────────────────────────────────┐                  │    │   │
│  │  │  │                                    │                  │    │   │
│  │  │  │      📷 ACTUAL IMAGE PREVIEW       │                  │    │   │
│  │  │  │         (200x200 thumbnail)        │                  │    │   │
│  │  │  │                                    │                  │    │   │
│  │  │  └────────────────────────────────────┘                  │    │   │
│  │  │                                                          │    │   │
│  │  │  photo.jpg                                               │    │   │
│  │  │  image/jpeg • 2.5 MB                                     │    │   │
│  │  │                                                          │    │   │
│  │  │  ⚠️ This file is already signed.                        │    │   │
│  │  │     Add your Vouch to the chain?                         │    │   │
│  │  │                                                          │    │   │
│  │  │  [ Deny ]                    [ Approve ]                 │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                           │                                             │
│                           ▼                                             │
│  STEP 4: DECISION                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  • User clicked "Approve": Proceed with signing                  │   │
│  │  • User clicked "Deny": Return 403 Forbidden                     │   │
│  │  • Timeout (60s): Return 408 Request Timeout                     │   │
│  │  • Window closed: Return 403 Forbidden                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Content-Type Specific Rendering

| Content-Type | Rendering Strategy | Preview Format |
|--------------|-------------------|----------------|
| `image/jpeg`, `image/png` | PIL thumbnail | 200x200 preview |
| `video/mp4`, `video/mov` | First frame + play icon | 🎬 icon + metadata |
| `audio/mpeg`, `audio/wav` | Waveform (optional) | 🎵 icon + duration |
| `text/plain`, `text/markdown` | Syntax highlight | First 500 chars |
| `application/json` | Pretty-print + collapse | Structured tree |
| `application/pdf` | First page thumbnail | Page preview |
| `application/c2pa+json` | Manifest assertions | Provenance tree |

---

## Novel Claims

### Claim 1: WYSIWYS (What You See Is What You Sign)
A signing proxy that dynamically selects a rendering template based on the MIME type of the payload to enforce visual consent, where the rendered preview is cryptographically bound to the actual bytes being signed.

### Claim 2: Out-of-Band Consent UI
The use of a system-level window (owned by the signing daemon) to verify in-band (browser level) requests, preventing UI redressing attacks where the requesting application spoofs the consent dialog.

### Claim 3: C2PA Provenance Chain Detection
Automatic detection of existing C2PA metadata in incoming files, with explicit user consent to "add to the chain" rather than "create new," preserving provenance continuity.

### Claim 4: Semantic Content Classification via Magic Bytes
Using file magic numbers (first N bytes) as a secondary content-type verification, preventing MIME-type spoofing attacks (e.g., sending malware as `image/png`).

### Claim 5: Consent Mode Escalation
A tiered consent model:
- `never`: No prompts (testing only, DANGEROUS)
- `prompt`: Show popup for untrusted origins
- `always`: Show popup for all requests (default, most secure)

### Claim 6: Default-Deny Button Focus
The consent dialog focuses the "Deny" button by default, requiring explicit user action to approve, following security best practices of fail-safe defaults.

### Claim 7: AI Provenance Display
For images with AI-generated metadata (C2PA `ai_training:used` or `c2pa.ai_generated`), display a prominent "⚠️ AI Generated" badge in the consent preview.

---

## Security Analysis

| Attack | Traditional Signing | Semantic Consent |
|--------|-------------------|------------------|
| Payload swapping | ❌ Vulnerable | ✅ Preview shows actual content |
| UI redressing | ❌ Vulnerable | ✅ System window cannot be spoofed |
| Consent fatigue | ❌ Generic prompts | ✅ Rich context aids decision |
| MIME spoofing | ❌ Trust header | ✅ Magic byte verification |
| Rushing user | ❌ No delays | ✅ Default focus on Deny |

---

## Implementation Reference

Reference implementation in:
- `vouch-bridge/bridge.py` - `MediaConsentUI` class
- `vouch-bridge/bridge.py` - `check_existing_c2pa()` function

Repository: https://github.com/vouch-protocol/vouch

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 24, 2026 cannot claim novelty for patent purposes.
