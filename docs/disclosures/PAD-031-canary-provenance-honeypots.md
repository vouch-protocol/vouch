# PAD-031: Adversarial Provenance Honeypots via Synthetic Canary Identities

**Identifier:** PAD-031  
**Title:** Method for Detecting Provenance Forgery, Stripping, and Credential Reuse Through Synthetic Canary Identities and Trap Watermarks  
**Publication Date:** April 22, 2026  
**Prior Art Effective Date:** April 22, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Adversarial Detection / Content Provenance / Deception Detection / Counterintelligence / Decentralized Identity  
**Author:** Ramprasad Anandam Gaddam  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-005 (Reverse Lookup Registry), PAD-014 (Vouch Sonic), PAD-023 (Content Policy Watermarking), PAD-028 (Cross-Modal Identity-Bound Provenance)  

---

## 1. Abstract

A system and method for embedding deliberately constructed **canary identities**, **trap credentials**, and **honeypot watermarks** into content provenance ecosystems to detect, attribute, and characterize adversarial actors who attempt to forge, strip, clone, or replay provenance credentials. Unlike traditional provenance systems that are purely defensive (sign content, detect tampering, reject invalid credentials), this protocol creates an **offensive detection layer** that converts adversarial behavior into actionable intelligence.

The system introduces several interlocking mechanisms:

1. **Synthetic Canary DIDs:** Artificial agent identities, indistinguishable from real ones, registered in the Vouch Protocol registry. Canary DIDs have valid Ed25519 keypairs, signed manifests, and behavioral histories, but are monitored by a silent alert pipeline. Any verification request against a canary DID triggers an investigation - because legitimate verifiers would never encounter these identities.

2. **Trap Watermarks:** Audio and image content embedded with valid Vouch Sonic watermarks (PAD-014) and C2PA manifests linked to canary DIDs, seeded into distribution channels where provenance stripping is suspected. When the watermark is detected in stripped or re-attributed content, the canary identity traces the content back to the stripping operation.

3. **Credential Bait Documents:** Synthetic `vouch.json` files, API keys, and JWK keypairs planted in locations where credential theft is suspected (public repositories, compromised servers, leaked credential dumps). Usage of these trap credentials triggers silent alerts with the attacker's IP, user-agent, and request patterns.

4. **Provenance Replay Detection:** When a valid signature from a canary DID appears in contexts other than the original trap content, it indicates that an attacker has captured and replayed the credential - revealing the attacker's forgery methodology.

5. **Statistical Adversary Fingerprinting:** Aggregating canary alert events to build behavioral fingerprints of adversarial actors and provenance-stripping tools, enabling detection of systematic attacks that target individual canaries but reveal patterns across the network.

Key innovations:
- **Honeypot methodology applied to cryptographic identity and content provenance** - a domain where this technique has never been deployed.
- **Canary identities are cryptographically indistinguishable from real identities** - an attacker cannot determine whether a DID is real or a canary without attempting to use it (at which point the alert fires).
- **Zero false positives by construction** - a canary DID alert fires only when someone verifies against an identity that has no legitimate usage, eliminating the false-positive problem that plagues behavioral detection systems.
- **Provenance-stripping tool fingerprinting** - the first system capable of identifying and characterizing the tools used to remove content provenance credentials.

---

## 2. Problem Statement

### 2.1 Provenance Systems Are Purely Defensive

Current content provenance technologies (C2PA, Vouch Protocol, Digimarc) operate on a defensive model:
- **Sign** content at point of creation.
- **Verify** signatures at point of consumption.
- **Reject** content with invalid or missing credentials.

This model provides no intelligence about the adversary:
- Who is stripping provenance credentials from content?
- What tools are being used to forge or clone credentials?
- Which distribution channels are laundering un-attributed content?
- How sophisticated are the forgery techniques being deployed?

Without adversarial intelligence, defenders are always reactive - patching vulnerabilities after exploitation rather than proactively detecting and disrupting adversarial operations.

### 2.2 Provenance Stripping Is Undetectable

An attacker who strips all provenance metadata from content (removing C2PA JUMBF manifests, overwriting Exif data, re-encoding audio to destroy watermarks) produces content that appears merely "unsigned" - indistinguishable from content that was never signed in the first place. Current systems cannot:
- Detect that provenance was intentionally stripped (vs. never present).
- Identify the tool or method used for stripping.
- Trace stripped content back to its original attributed source.

### 2.3 Credential Forgery Intelligence Gap

When an attacker forges a Vouch-Token or C2PA manifest, current systems detect the forgery (signature verification fails) but learn nothing about the attacker:
- Was this a credential theft (stolen real key) or a forgery attempt (fabricated key)?
- What is the attacker's operational pattern (targeting specific content types, time windows, geographic regions)?
- Is the same attacker responsible for multiple forgery attempts across the ecosystem?

### 2.4 No Existing System Applies Honeypot Methodology to Provenance

Honeypot and canary token techniques are well-established in network security (Canarytoken, HoneyDB, OpenCanary) and file system monitoring (canary files in ransomware detection). However, no existing system applies these techniques to:
- Content provenance credential ecosystems (C2PA, Vouch Protocol)
- Decentralized identity registries (DID registries)
- Audio/video watermarking systems
- Cryptographic signing infrastructure

---

## 3. Solution (The Invention)

### 3.1 Canary DID Architecture

Canary DIDs are synthetic identities that are **cryptographically valid** and **behaviorally plausible** but serve no legitimate operational purpose. They exist solely to be discovered and used by adversaries.

**Canary DID Properties:**

| Property | Real DID | Canary DID | Distinguishable? |
|----------|----------|------------|-------------------|
| Ed25519 keypair | Valid | Valid | No |
| DID document | Standard format | Standard format | No |
| Registry entry | Present | Present | No |
| `vouch.json` file | Published | Published | No |
| Signed content exists | Yes | Yes (trap content) | No |
| Behavioral history | Real actions | Simulated actions | No (from external view) |
| Alert on verification | No | **YES** | Not until triggered |

**Canary Generation:**

```json
{
 "canary_id": "canary-2026-04-22-a7f3",
 "did": "did:vouch:z6MkCanaryABC123",
 "keypair": {
  "public": "ed25519_public_hex",
  "private": "ed25519_private_hex_held_by_canary_service"
 },
 "cover_identity": {
  "display_name": "DataSynthAI Processing Agent",
  "domain": "datasynthai.example.com",
  "description": "Automated document analysis agent"
 },
 "deployment": {
  "registry_entry": true,
  "vouch_json_published": true,
  "trap_content_signed": 15,
  "credential_bait_deployed": 3
 },
 "alert_config": {
  "alert_on": ["verification_request", "token_presentation", "key_usage"],
  "notification_channels": ["webhook", "email"],
  "capture_fields": ["source_ip", "user_agent", "timestamp", "request_headers", "referring_content"]
 }
}
```

### 3.2 Trap Watermark Deployment

Content embedded with valid watermarks and provenance credentials linked to canary DIDs is distributed into channels where stripping is suspected.

**Trap Content Types:**

| Content Type | Provenance Mechanism | Detection Trigger |
|-------------|---------------------|-------------------|
| Audio files | Vouch Sonic watermark (PAD-014) | Watermark detected in content not distributed through controlled channels |
| Images | C2PA JUMBF manifest signed by canary DID | C2PA verification request against canary DID |
| Documents | C2PA-signed PDF with canary DID | Document verification request against canary DID |
| Video | C2PA + temporal fingerprint (PAD-024) | Frame-level fingerprint match in re-uploaded content |

**Trap Watermark Embedding:**

```
1. Generate trap content (stock photo, ambient audio, sample document)
2. Sign with canary DID's Ed25519 key (valid C2PA manifest or Vouch Sonic watermark)
3. Register watermark metadata in Vouch registry (linked to canary DID)
4. Distribute trap content into suspected stripping channels:
  - Upload to platforms known for provenance removal
  - Include in datasets that may be scraped by AI training pipelines
  - Plant in media libraries used by content mills
  - Embed in public-facing websites
5. Monitor for:
  a. Watermark detection in new contexts → content was redistributed
  b. C2PA verification requests against canary DID → someone is checking credentials
  c. Absence of watermark in redistributed content → watermark was stripped
  d. Modified watermark with different DID → credential replacement attack
```

### 3.3 Credential Bait

Synthetic API keys, JWK keypairs, and `vouch.json` files planted in locations where credential theft is suspected.

**Bait Deployment Locations:**

| Location | Rationale | Alert Trigger |
|----------|-----------|---------------|
| Public GitHub repos (intentional "accidental" commit) | Credential scanning bots harvest leaked keys | API call using bait key |
| Paste sites | Attackers monitor paste sites for credentials | API call or verification using bait credential |
| Compromised/honeypot servers | Attackers who breach a server search for credentials | Usage of discovered bait key |
| Dark web credential markets | Monitor if bait credentials appear in trading channels | Presentation of bait token to any verification endpoint |

**Bait `vouch.json` Format:**

```json
{
 "did": "did:vouch:z6MkCanaryXYZ789",
 "publicKeyJwk": {
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "base64url_public_key"
 },
 "endpoint": "https://canary-monitor.vouch-protocol.com/v1/verify",
 "displayName": "ProdAgent-Finance-v3"
}
```

The `endpoint` resolves to a monitoring service that logs all verification attempts. The display name is designed to be attractive to attackers ("ProdAgent-Finance" suggests a high-value target).

### 3.4 Silent Alert Pipeline

When a canary is triggered, the alert pipeline captures maximum forensic information while remaining invisible to the adversary.

**Alert Event Structure:**

```json
{
 "alert_id": "alert-2026-04-22-001",
 "canary_id": "canary-2026-04-22-a7f3",
 "triggered_at": "2026-04-22T14:32:07Z",
 "trigger_type": "verification_request",
 "forensics": {
  "source_ip": "203.0.113.42",
  "source_asn": "AS13335",
  "geo": "Mumbai, IN",
  "user_agent": "provenance-stripper/2.1 (compatible; curl/8.5)",
  "request_method": "POST",
  "request_path": "/api/v1/verify",
  "request_headers": { "Accept": "application/json" },
  "tls_fingerprint": "ja3:abc123def456",
  "referring_content_hash": "sha256:...",
  "timing": {
   "tcp_handshake_ms": 45,
   "tls_handshake_ms": 120,
   "request_processing_ms": 3
  }
 },
 "content_context": {
  "original_trap_content_id": "trap-audio-001",
  "watermark_present": false,
  "c2pa_manifest_present": true,
  "c2pa_manifest_modified": true,
  "modification_type": "did_replacement"
 }
}
```

### 3.5 Statistical Adversary Fingerprinting

Aggregating canary alerts across the network reveals adversary patterns invisible from individual events.

**Fingerprinting Dimensions:**

| Dimension | What It Reveals |
|-----------|----------------|
| Temporal patterns | Time-of-day, frequency, burst patterns |
| Content type targeting | Does the adversary target audio, images, or documents? |
| Stripping methodology | Does the adversary strip watermarks, modify C2PA, or replace DIDs? |
| Tool signatures | User-agent strings, TLS fingerprints, request patterns |
| Geographic correlation | Source IP clustering, ASN analysis |
| Credential interest | Which bait credentials attract attention? (financial > general) |

**Adversary Profiles:**

```json
{
 "adversary_fingerprint_id": "adv-fp-001",
 "first_seen": "2026-03-15T08:00:00Z",
 "last_seen": "2026-04-22T14:32:07Z",
 "total_canary_triggers": 47,
 "canary_types_triggered": ["did_verification", "watermark_detection", "credential_usage"],
 "content_types_targeted": ["audio", "image"],
 "methodology": "c2pa_manifest_stripping_with_did_replacement",
 "tool_signature": {
  "user_agent_cluster": "provenance-stripper/*",
  "tls_ja3_hash": "abc123def456",
  "request_timing_profile": "automated_batch"
 },
 "threat_assessment": "SYSTEMATIC_COMMERCIAL_STRIPPING_OPERATION",
 "confidence": 0.94
}
```

---

## 4. Prior Art Differentiation

| System | Domain | Canary Identities | Trap Content | Adversary Fingerprinting |
|--------|--------|-------------------|--------------|-------------------------|
| Canarytokens (Thinkst) | File/URL monitoring | Web tokens, DNS | No provenance content | Basic alerting |
| HoneyDB | Network honeypots | IP-based lures | No provenance content | Network-level |
| OpenCanary | Service honeypots | Service emulation | No provenance content | Service-level |
| Ransomware canary files | File system monitoring | Sentinel files | No provenance content | File event monitoring |
| **This disclosure** | **Content provenance** | **Cryptographic DID-based** | **Yes (watermarked + signed)** | **Yes (cross-canary statistical)** |

Key differentiators:
1. **No existing system** creates cryptographically valid decoy identities within a decentralized identity registry for the purpose of adversarial detection.
2. **No existing system** embeds honeypot watermarks in audio/image/video content to detect and characterize provenance stripping operations.
3. **No existing system** provides statistical fingerprinting of adversaries targeting content provenance infrastructure across multiple independent canary events.
4. **No existing system** achieves zero false positive alerting by construction - alerts fire only when an identity that has no legitimate usage is accessed.
5. The combination of **canary identities + trap watermarks + credential bait + adversary fingerprinting** creates a complete adversarial intelligence layer within a provenance ecosystem - a novel application of honeypot methodology to a domain where it has never been deployed.

---

## 5. Technical Implementation

### 5.1 Canary Registry Integration

Canary DIDs are stored in the same registry as real DIDs, with a private `is_canary` flag invisible to external queries:

```
Key: did:{canary_did} - Standard DID document (externally indistinguishable)
Key: canary:registry:{canary_did} - Hash (canary_id, alert_config, deployment_info) [PRIVATE]
Key: canary:alerts:{canary_did} - Sorted Set (score = timestamp, value = alert event JSON)
Key: canary:adversary:{fingerprint_id} - Hash (adversary profile JSON)
```

### 5.2 Verification Endpoint Instrumentation

The Vouch Protocol verification endpoint is instrumented to check every incoming DID against the canary registry before normal verification processing:

```
POST /api/v1/verify
 |
 v
[Extract DID from request]
 |
 +-- Is DID in canary registry?
 |   |
 |   +-- YES: Log full forensics → fire alert → return NORMAL verification result
 |   |    (attacker sees standard response, cannot detect the canary)
 |   |
 |   +-- NO: Normal verification flow
 |
 v
[Return verification result]
```

The critical design choice: **canary verification returns a normal response**, not an error. If canary DIDs returned errors or distinctive responses, an attacker could probe the registry to identify canaries.

### 5.3 Trap Content Lifecycle

```
Phase 1: CREATION
 - Generate trap content (royalty-free media)
 - Sign with canary DID (C2PA or Vouch Sonic)
 - Register metadata in Vouch registry

Phase 2: DEPLOYMENT
 - Distribute into suspected stripping channels
 - Record deployment locations and timestamps
 - Set monitoring parameters

Phase 3: MONITORING
 - Continuous scan for trap content fingerprints (PAD-024 temporal hashing for video, PAD-014 watermark detection for audio)
 - Monitor verification endpoint for canary DID hits
 - Aggregate alert events for fingerprinting

Phase 4: ANALYSIS
 - Build adversary profiles from aggregated alerts
 - Correlate canary triggers with real attack patterns
 - Update canary deployment strategy based on findings

Phase 5: ROTATION
 - Retire triggered canaries (adversary may now know it's a canary)
 - Deploy fresh canaries with new identities
 - Maintain canary density in the registry
```

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A system for creating cryptographically valid synthetic identities (canary DIDs) within a decentralized identity registry that are indistinguishable from real identities but trigger silent alerts when accessed, for the purpose of detecting adversarial actors targeting content provenance infrastructure.

2. A method for embedding honeypot watermarks and provenance credentials (C2PA manifests, Vouch Sonic watermarks) in trap content distributed into suspected stripping channels, where detection of the trap content in modified or stripped form reveals the adversary's methodology and distribution path.

3. A credential bait system that plants synthetic API keys, JWK keypairs, and `vouch.json` files in locations where credential theft is suspected, triggering forensic alerts when the bait credentials are used.

4. A statistical adversary fingerprinting method that aggregates canary alert events across multiple independent canary identities to build behavioral profiles of adversarial actors, revealing temporal patterns, content targeting preferences, stripping methodologies, and tool signatures.

5. A zero-false-positive alerting architecture where canary identity alerts fire only when an identity with no legitimate usage is accessed - eliminating the false positive problem inherent in behavioral anomaly detection.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch

---

## Update (April 27, 2026): Data Integrity Embodiment

The Adversarial Provenance Honeypots protocol seeds canary identities,
trap watermarks, and bait credentials into a provenance ecosystem to
detect adversarial behavior. The novel mechanism is independent of the
specific credential envelope used; the original disclosure included
"synthetic JWK keypairs" and "trap credentials" alongside canary DIDs.

This disclosure additionally covers the embodiment where the canary
credentials are Verifiable Credentials secured by Data Integrity
proofs (`eddsa-jcs-2022` or `hybrid-eddsa-mldsa44-jcs-2026`), and where
the trap credential bundle is a `vouch.json` containing a Multikey-format
private key encoding. The detection logic, the silent alert pipeline, the
content-stripping traceback property, and the offensive intelligence
layer are all unchanged. The standards-aligned canary form is disclosed as
additional prior art covering the same inventive deception-detection
mechanism for content provenance.
