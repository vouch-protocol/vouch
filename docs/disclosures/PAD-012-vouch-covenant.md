# PAD-012: Method for Embedding Executable Usage Covenants in Media Provenance Manifests

**Identifier:** PAD-012  
**Title:** Method for Embedding Executable Usage Covenants in Media Provenance Manifests ("Vouch Covenant")  
**Publication Date:** January 20, 2026  
**Prior Art Effective Date:** January 20, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Digital Rights Management / Generative AI / Smart Contracts  
**Author:** Ramprasad Anandam Gaddam  

---

## 1. Abstract

A system and method for embedding "Vouch Covenants"—machine-readable, cryptographically binding, and computationally enforceable usage policies—within the C2PA provenance manifests of digital assets. Unlike passive metadata tags that merely suggest usage restrictions, a Covenant functions as a **portable smart contract** that dictates the *terms of engagement* for downstream AI systems, rendering engines, and content platforms.

The Covenant schema defines constraints using a domain-specific language (DSL) with Boolean logic gates, such as `ai_training: forbidden`, `derivative_works: require(royalty_split, 0.05, ETH, creator_wallet)`, or `context: allow_only(news, education) && deny(satire, advertising)`. These covenants are designed to be parsed by "Covenant-Aware" ingestion pipelines and inference engines, effectively functioning as a **"Digital Robots.txt That Travels With The File"**, ensuring the creator's intent is preserved, machine-verifiable, and technically enforced across the asset's entire lifecycle—including after transcoding, format conversion, and cross-platform republication.

---

## 2. Problem Statement

Current digital provenance standards, including C2PA and W3C Verifiable Credentials, focus on **attestation** (who created what, when) but lack mechanisms for **enforcement** (how it may be used downstream).

### 2.1 Passive Metadata Failure
- A metadata tag declaring `ai_training: false` or "Do Not Train" is routinely ignored by web scrapers and model training pipelines.
- There exists no runtime enforcement mechanism at the point of AI inference.

### 2.2 Context Detachment
- When an image is downloaded, its licensing terms (typically hosted on a separate webpage, JSON-LD, or rights.info file) become detached from the binary asset.
- Subsequent handlers have no reliable method to discover or verify the original creator's intent.

### 2.3 Derivative Works Problem
- Current systems cannot enforce inherited restrictions across remix chains.
- A "No Commercial Use" creator loses control when their work is incorporated into a derivative that is then sold.

### 2.4 Platform-Specific Enforcement
- Rights management is currently siloed within platforms (e.g., YouTube Content ID, Adobe Stock licensing).
- No universal, file-level enforcement mechanism exists that operates independently of hosting platforms.

---

## 3. Solution (The Invention)

### 3.1 The "Vouch Covenant" Protocol Extension

A standardized extension to the C2PA manifest assertion store that embeds machine-executable policy logic directly within signed media files.

#### 3.1.1 Covenant Schema Definition

A JSON/CBOR schema defining:

```json
{
  "@context": "https://vouch-protocol.com/covenants/v1",
  "@type": "VouchCovenant",
  "version": "1.0",
  "creator": "did:key:z6Mk...",
  "effective_date": "2026-01-20T00:00:00Z",
  "expiration_date": null,
  "policies": [
    {
      "domain": "ai_training",
      "rule": "DENY_ALL",
      "exceptions": []
    },
    {
      "domain": "derivative_works",
      "rule": "ALLOW_IF",
      "conditions": {
        "attribution": "required",
        "royalty": {
          "percentage": 5,
          "currency": "ETH",
          "recipient": "0xCreatorWallet..."
        }
      }
    },
    {
      "domain": "context",
      "rule": "ALLOW_ONLY",
      "permitted": ["news", "education", "research"],
      "denied": ["advertising", "satire", "political_campaign"]
    },
    {
      "domain": "modifications",
      "rule": "DENY",
      "operations": ["face_swap", "voice_clone", "style_transfer"]
    }
  ],
  "enforcement_mode": "STRICT",
  "fallback_action": "REJECT_WITH_EXPLANATION"
}
```

#### 3.1.2 The Enforcer (Model Guard Architecture)

A method where AI inference engines, image generators, and content processing pipelines integrate a **Covenant Verification Module (CVM)**:

1. **Pre-Processing Hook:** Before any input asset is processed, the CVM extracts and parses the Covenant from the C2PA manifest.
2. **Policy Evaluation Engine:** A lightweight interpreter evaluates the Boolean logic gates against the current operation context (e.g., "Is this a training run? Is output commercial?").
3. **Enforcement Response:**
   - **ALLOW:** Operation proceeds normally.
   - **CONDITIONAL_ALLOW:** Operation proceeds with constraints (e.g., embedded attribution, royalty deduction).
   - **DENY:** Operation is blocked; model outputs null, noise, or an explanatory rejection message.
   - **AUDIT_ONLY:** Operation proceeds but generates a compliance log for the creator.

#### 3.1.3 Recursive Policy Inheritance (Provenance Genetics)

When an asset with a Covenant is used as input for a derivative work:

1. The child asset's Covenant automatically inherits the parent's restrictive policies (Dominant Gene Principle).
2. A child cannot grant permissions that the parent denied (Legal Virality).
3. The inheritance chain is cryptographically linked, forming an auditable "Policy Ancestry Tree."

#### 3.1.4 The Covenant Resolver (Decentralized Registry)

For expired signatures or key rotation scenarios:

- Covenants may include a `resolver_endpoint` pointing to a DID Document or smart contract.
- The resolver provides current policy state, enabling dynamic updates (e.g., creator changes their mind about AI training).
- Resolution is optional; offline enforcement uses the embedded snapshot.

---

## 4. Technical Implementation

### 4.1 Integration Points

| System Type | Integration Method |
|-------------|-------------------|
| Stable Diffusion | Custom Pipeline Component |
| DALL-E / Midjourney | API Gateway Middleware |
| LLM Training | Dataset Ingestion Filter |
| Web Browsers | Content-Security-Policy-like header |
| CDNs | Edge Worker verification |
| NFT Marketplaces | Smart Contract Royalty Enforcement |

### 4.2 Covenant DSL Grammar (Simplified)

```bnf
covenant    := policy+
policy      := domain ":" rule
rule        := "ALLOW_ALL" | "DENY_ALL" | conditional
conditional := ("ALLOW_IF" | "DENY_IF") conditions
conditions  := condition ("&&" | "||" condition)*
condition   := attribute operator value
operator    := "==" | "!=" | "IN" | "NOT_IN" | ">" | "<"
```

### 4.3 Cryptographic Binding

- The Covenant is signed as part of the C2PA manifest using the creator's Ed25519 key.
- Tampering with any policy invalidates the entire manifest signature.
- Counter-signatures allow platforms to attest compliance ("We verified this Covenant at time T").

---

## 5. Claims and Novel Contributions

### Claim 1: Executable Policy Embedding
A method for embedding machine-executable logic gates (Boolean expressions with domain-specific operators) within standard media provenance manifests (C2PA/JUMBF) that dictate the **runtime behavior** of consuming AI applications, rendering engines, and content platforms—transforming passive metadata into active enforcement.

### Claim 2: Recursive Provenance Inheritance
A "Recursive Provenance" mechanism where usage policies act as **dominant genetic traits**, automatically inheriting and enforcing constraints on all downstream derivatives of the signed asset, with cryptographic linkage forming an auditable "Policy Ancestry Tree."

### Claim 3: Fallback Behavior Specification
A method for media files to specify their own handling instructions when covenants are violated or unverifiable, including noise injection, graceful degradation, rejection with explanation, or audit-only logging.

### Claim 4: Dynamic Policy Resolution
A system where embedded covenants may reference external resolvers (DID Documents, smart contracts) for dynamic policy updates while maintaining offline enforcement capability through embedded policy snapshots.

### Claim 5: Cross-Platform Enforcement Portability
A file-level enforcement mechanism that operates independently of hosting platforms, enabling consistent policy enforcement as assets move between social media, AI pipelines, CDNs, and offline storage.

### Claim 6: Context-Aware Conditional Logic
A domain-specific language for expressing context-dependent usage rules that evaluate against runtime environment metadata (commercial/non-commercial, geographic region, industry sector, temporal conditions).

### Claim 7: Cryptographic Counter-Signature Compliance
A method for downstream handlers to add counter-signatures attesting to Covenant verification, creating an auditable chain of compliance across the asset's distribution lifecycle.

### Claim 8: Operation-Specific Denial Granularity
A system for specifying granular operation-level restrictions (e.g., allowing AI upscaling but denying face-swap, permitting format conversion but denying style transfer) rather than binary allow/deny at the asset level.

---

## 6. Prior Art Differentiation

| Existing Solution | Limitation | Vouch Covenant Advancement |
|-------------------|------------|---------------------------|
| robots.txt | Website-level, not file-level; easily ignored | Travels with file; cryptographically bound |
| Creative Commons | Human-readable; no machine enforcement | Machine-executable; runtime enforcement |
| Content ID (YouTube) | Platform-specific; fingerprint-based | Universal; policy-based; cross-platform |
| NFT Royalties | Blockchain-only; limited to sales | Any operation; works offline |
| C2PA Assertions | Attestation only; no enforcement | Enforcement built-in |

---

## 7. Use Cases

1. **Photographer's Portfolio:** Images carry covenants denying AI training and style transfer while allowing news editorial use with attribution.

2. **Voice Actor Protection:** Audio recordings deny voice cloning and synthetic duplication while allowing podcast redistribution.

3. **Academic Research:** Papers permit educational AI summarization but deny commercial training and require citation propagation.

4. **Corporate Brand Assets:** Logos enforce context restrictions (no political use) with strict enforcement mode and noise injection on violation.

---

## 8. Conclusion

The Vouch Covenant system transforms digital provenance from passive attestation into active, portable rights management. By embedding executable policy logic within standard C2PA manifests and defining a universal enforcement architecture, creators gain persistent control over their digital assets regardless of the platform, format, or downstream processing pipeline.

---

## 9. References

- C2PA Technical Specification v1.4
- W3C Verifiable Credentials Data Model v2.0
- Creative Commons Legal Code
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-011
