# Defensive Disclosure: Detached Signature Recovery ("Reverse Lookup")

**Disclosure ID:** PAD-005  
**Publication Date:** January 10, 2026  
**Author:** Ramprasad Anandam Gaddam  
**Status:** Public Domain / Prior Art  

---

## Abstract

This disclosure describes a method for recovering authorship attribution of digital content even after cryptographic signatures have been removed or stripped, using a public registry indexed by content hash.

---

## Problem Statement

Digital signatures are traditionally "attached" to the message they sign (e.g., PGP inline signatures, S/MIME). This creates a vulnerability:

1. **Copy-Paste Attack**: User copies text but omits the signature block
2. **Platform Stripping**: Social media platforms remove signature metadata
3. **Format Conversion**: Converting between formats loses signature data

Once detached, the text becomes "orphaned" — its authorship cannot be verified even though the content itself is unchanged. This enables:
- Plagiarism without attribution
- Misinformation spread without accountability
- Loss of provenance in content chains

---

## Disclosed Method

We disclose a system for non-repudiation and authorship discovery of detached content using a queryable registry indexed by content hash.

### Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│              REVERSE LOOKUP ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  INGESTION (At signing time):                               │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐ │
│  │   Content   │ ──▶  │  SHA-256    │ ──▶  │   Registry  │ │
│  │   "Hello"   │      │   Hash      │      │   (KV/DB)   │ │
│  └─────────────┘      └─────────────┘      └─────────────┘ │
│                                                  │          │
│         Stores: hash → {signer_did, timestamp, signature}   │
│                                                             │
│  RECOVERY (At lookup time):                                 │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐ │
│  │  Unknown    │ ──▶  │  SHA-256    │ ──▶  │   Query     │ │
│  │   Text      │      │   Hash      │      │   Registry  │ │
│  └─────────────┘      └─────────────┘      └─────────────┘ │
│                                                  │          │
│                                                  ▼          │
│                             "Signed by Alice on Jan 8, 2026"│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Registry Schema

```json
{
  "content_hash": "sha256:a7b3c9d2e4f5...",
  "signer_did": "did:vouch:alice",
  "display_name": "Alice Reporter",
  "organization": "The New York Times",
  "timestamp": "2026-01-08T12:00:00Z",
  "signature": "eyJhbGciOiJFZERTQSJ9...",
  "original_url": "https://example.com/article"
}
```

### Query Methods

**1. Exact Hash Match (Primary)**
```
GET /api/lookup?hash=sha256:a7b3c9d2...
Response: { found: true, signer: "Alice", ... }
```

**2. Semantic Similarity (Optional Enhancement)**
```
POST /api/lookup/semantic
Body: { text: "AI Agents are the future" }
Response: { similarity: 0.97, original_signer: "Alice", ... }
```

Semantic search uses vector embeddings (e.g., OpenAI embeddings, BERT) to find high-confidence similarity matches even when text has been slightly modified.

### Privacy Considerations

1. **Content Not Stored**: Only hash is stored, not full text (for exact match)
2. **Opt-In Publishing**: Signers explicitly choose to register hashes
3. **Rate Limiting**: Prevents enumeration attacks
4. **No PII in Hash**: Content hash reveals nothing about content

### Security Considerations

1. **Hash Collision Resistance**: SHA-256 provides 128-bit security level
2. **Registry Authenticity**: Registry responses are signed by operator
3. **Tamper Evidence**: Merkle tree or blockchain anchoring for audit log
4. **Denial of Service**: CDN/edge caching for high-volume queries

---

## Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization. The described method is hereby released into the public domain under the Creative Commons CC0 1.0 Universal dedication.

Any party implementing similar functionality after January 10, 2026 cannot claim novelty for patent purposes.

---

## Implementation Reference

Planned implementation in:
- `cloudflare-worker/src/worker.js` - `/lookup` endpoint
- `browser-extension/content.js` - "Find Original Author" feature

Repository: https://github.com/vouch-protocol/vouch
