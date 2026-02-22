# PAD-023: Method for Embedding Machine-Readable Content Usage Policies in Audio Watermarks

**Identifier:** PAD-023
**Title:** Method for Embedding Machine-Readable Content Usage Policies in Audio Watermarks
**Publication Date:** February 22, 2026
**Prior Art Effective Date:** February 22, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Content Rights / Audio Security / AI Governance / Digital Rights Management
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for embedding **machine-readable content usage policies** directly into the audio waveform using psychoacoustic steganography, extending the Vouch Sonic protocol (PAD-014) from identity provenance to rights governance. Unlike metadata-based rights management systems (C2PA, ID3, XMP) that are stripped during transcoding, format conversion, or platform processing, the embedded policies survive every transformation that the audio content itself survives--including lossy compression, format conversion, analog re-recording, and streaming delivery.

PAD-014 established the foundation: a spread-spectrum, psychoacoustically-masked watermark carrying cryptographic provenance (signer DID, Ed25519 signature, timestamp). PAD-023 extends the watermark payload to include a compact, CBOR-encoded content usage policy that specifies the creator's terms for how the audio may be used. These terms travel with the audio signal itself, not in strippable metadata containers, enabling any compliant decoder to read and enforce the creator's stated rules without network access or database lookups.

The core innovation is the **policy-carrying watermark**: content protection rules that are as durable as the content they protect. When a musician uploads a song with "No AI Training" encoded in the watermark, that rule persists through YouTube's transcoding pipeline, through MP3 conversion, through analog re-recording, and through any number of format transformations. If the audio is later discovered in an AI training dataset, the embedded policy provides cryptographic evidence of the creator's explicit prohibition--evidence that cannot have been accidentally stripped, because it is part of the audio signal itself.

---

## 2. Problem Statement

### 2.1 The Metadata Stripping Crisis

Content usage policies are currently stored in metadata layers that are routinely destroyed:

**C2PA Content Credentials:**
- Embedded as sidecar files or manifest store entries.
- Stripped by platforms during transcoding (YouTube, Spotify, TikTok).
- Lost when audio is extracted from video containers.
- Not preserved across most audio editing workflows.

**ID3 Tags (MP3):**
- Support license and copyright fields.
- Silently discarded during format conversion (MP3 to WAV, MP3 to OGG).
- Trivially editable by any hex editor or metadata tool.
- No cryptographic binding to the audio content.

**XMP Metadata:**
- Rich rights expression capability.
- Stripped by virtually every transcoding operation.
- Lost during streaming platform ingest.
- Requires specialized tools to read.

**Server-Side Databases:**
- Platforms maintain internal rights databases (YouTube Content ID, Spotify rights management).
- Requires network access and platform cooperation to query.
- Does not travel with the content when downloaded.
- Siloed per platform--no interoperability.

**Legal Text in Descriptions:**
- Human-readable but not machine-readable.
- Separated from the content file itself.
- Lost when content is reposted or shared without context.
- Not enforceable by automated compliance systems.

### 2.2 The Real-World Failure Chain

Consider the lifecycle of a musician's song with a "No AI Training" restriction:

```
Step 1: Musician records song.
        Rights: "No AI Training, No Voice Cloning, Commercial License Required"
        C2PA metadata: ✓ Present
        ID3 tags: ✓ Present

Step 2: Musician uploads to YouTube.
        YouTube transcodes to VP9/Opus for streaming.
        C2PA metadata: ✗ STRIPPED
        ID3 tags: ✗ STRIPPED
        YouTube internal DB: ✓ Present (but siloed)

Step 3: User downloads audio using yt-dlp.
        Extracted as M4A/AAC.
        C2PA metadata: ✗ GONE
        ID3 tags: ✗ GONE
        YouTube DB: ✗ NOT ACCESSIBLE

Step 4: User converts to WAV for editing.
        All remaining container metadata: ✗ GONE

Step 5: AI training company scrapes the WAV file.
        Ingests into training dataset.
        No machine-readable policy exists anywhere in the file.
        The creator's "No AI Training" restriction is invisible.

Step 6: Creator discovers their voice in an AI model.
        No technical evidence that the restriction was communicated.
        Legal burden falls entirely on proving the original terms.
```

At **every step** in this chain, the content protection rules are lost. The audio signal survives intact--only the rules about how it may be used are destroyed.

### 2.3 The Survivability Gap

The fundamental problem is an asymmetry between content durability and policy durability:

| Layer | Survives Lossy Compression | Survives Format Conversion | Survives Platform Transcoding | Survives Analog Re-Recording |
|-------|---------------------------|---------------------------|-------------------------------|------------------------------|
| **Audio signal** | Yes | Yes | Yes | Yes |
| **C2PA metadata** | No | No | No | No |
| **ID3 tags** | Partially | No | No | No |
| **XMP metadata** | No | No | No | No |
| **Server-side DB** | N/A (not in file) | N/A | N/A | N/A |

Content usage policies should be **as durable as the content they govern**. If the audio can survive a transformation, the rules about that audio should survive the same transformation.

### 2.4 The AI Training Data Compliance Challenge

The EU AI Act (Article 53) and US Executive Order 14110 both impose obligations on AI companies to respect content usage restrictions in training data. However, compliance is technically impossible when:

1. There is no machine-readable policy attached to the audio files being ingested.
2. Metadata that once contained rights information was stripped before the file reached the training pipeline.
3. The AI company cannot distinguish "no policy found" (metadata stripped) from "no restrictions" (creator intended open use).

Without a mechanism for usage policies to travel with the audio signal itself, regulatory compliance reduces to "we checked the metadata and found nothing"--which is always true after transcoding, regardless of the creator's actual intent.

---

## 3. Solution (The Invention)

### 3.1 Policy-Carrying Watermark Architecture

Extend the Vouch Sonic watermark payload (PAD-014) to include a compact, binary-encoded content usage policy alongside the existing provenance data.

#### 3.1.1 Extended Payload Structure

```json
{
  "version": "1.0",
  "type": "audio_provenance",
  "signer_did": "did:key:z6MkhaXgBZDvotDkL5LmCWaEe...",
  "content_hash": "sha256:a1b2c3d4...",
  "timestamp_utc": 1737352800,
  "nonce": "random_32_bytes_hex",
  "signature": "ed25519_signature_base64",
  "metadata": {
    "title": "Original Song Title",
    "duration_ms": 240000,
    "sample_rate": 48000
  },
  "policy": {
    "ai_training": "deny",
    "voice_cloning": "deny",
    "derivatives": "allow_with_attribution",
    "commercial": "deny",
    "sampling": "deny",
    "broadcast": "allow",
    "expiry_utc": 1768888800,
    "license_uri": "https://example.com/license/abc123",
    "custom": "no_sampling_without_license"
  }
}
```

#### 3.1.2 CBOR Compact Encoding

The policy field is encoded using CBOR (Concise Binary Object Representation, RFC 8949) to minimize watermark payload size while preserving machine readability:

```python
import cbor2
from typing import Optional


# Standardized policy field codes (1-byte identifiers)
POLICY_CODES = {
    0x01: "ai_training",
    0x02: "voice_cloning",
    0x03: "derivatives",
    0x04: "commercial",
    0x05: "sampling",
    0x06: "broadcast",
    0x07: "sync_licensing",
    0x08: "public_performance",
    0xFE: "expiry_utc",
    0xFF: "custom",
}

# Standardized permission values (1-byte identifiers)
PERMISSION_VALUES = {
    0x00: "deny",
    0x01: "allow",
    0x02: "allow_with_attribution",
    0x03: "allow_noncommercial",
    0x04: "allow_with_license",
    0x05: "contact_creator",
}


def encode_policy(policy: dict) -> bytes:
    """
    Encode a content usage policy into a compact CBOR payload.

    Target: 40-80 bytes for standard policies,
    up to 120 bytes with custom free-text rules.
    """
    compact = {}

    for field_code, field_name in POLICY_CODES.items():
        if field_name in policy:
            value = policy[field_name]

            if field_name == "expiry_utc":
                # Timestamp stored as 4-byte integer
                compact[field_code] = value
            elif field_name == "custom":
                # Free text stored as UTF-8 string (truncated to 64 bytes)
                compact[field_code] = value[:64]
            else:
                # Standard permission values use 1-byte codes
                for val_code, val_name in PERMISSION_VALUES.items():
                    if value == val_name:
                        compact[field_code] = val_code
                        break

    encoded = cbor2.dumps(compact)
    return encoded


def decode_policy(data: bytes) -> dict:
    """
    Decode a CBOR-encoded content usage policy.

    Returns human-readable policy dictionary.
    """
    compact = cbor2.loads(data)
    policy = {}

    for field_code, value in compact.items():
        field_name = POLICY_CODES.get(field_code, f"unknown_{field_code}")

        if field_name == "expiry_utc":
            policy[field_name] = value
        elif field_name == "custom":
            policy[field_name] = value
        else:
            policy[field_name] = PERMISSION_VALUES.get(value, f"unknown_{value}")

    return policy
```

**Payload size analysis:**

| Policy Configuration | CBOR Size | Fits in PAD-014 Capacity |
|----------------------|-----------|--------------------------|
| 4 standard fields (deny/allow) | ~18 bytes | Yes (well within L1-L4) |
| 8 standard fields + expiry | ~38 bytes | Yes (within L2-L4) |
| 8 standard fields + expiry + 64-byte custom text | ~110 bytes | Yes (within L3-L4) |
| Maximum policy (all fields + custom) | ~120 bytes | Yes (within L3-L4) |

The CBOR encoding fits comfortably within the payload capacity established by PAD-014's multi-resolution embedding layers, even at aggressive compression bitrates.

#### 3.1.3 Policy Embedding in the Watermark

The policy payload is integrated into PAD-014's existing watermark structure:

```
PAD-014 Watermark Payload (Original):
┌──────────────────────────────────────────────┐
│ Version (1B) │ Type (1B) │ DID (32B)         │
│ Content Hash (32B) │ Timestamp (4B)          │
│ Nonce (32B) │ Signature (64B)                │
│ Metadata (variable, ~50B)                    │
│ ECC (Reed-Solomon, ~80B)                     │
├──────────────────────────────────────────────┤
│ Total: 256-512 bytes                         │
└──────────────────────────────────────────────┘

PAD-023 Extended Watermark Payload:
┌──────────────────────────────────────────────┐
│ Version (1B) │ Type (1B) │ DID (32B)         │
│ Content Hash (32B) │ Timestamp (4B)          │
│ Nonce (32B) │ Signature (64B)                │
│ Metadata (variable, ~50B)                    │
│ ┌──────────────────────────────────────────┐ │
│ │ POLICY BLOCK (40-120B, CBOR-encoded)     │ │
│ │ Policy Version (1B)                      │ │
│ │ Policy Fields (variable)                 │ │
│ │ Policy Hash (included in signature)      │ │
│ └──────────────────────────────────────────┘ │
│ ECC (Reed-Solomon, ~100B)                    │
├──────────────────────────────────────────────┤
│ Total: 320-640 bytes                         │
└──────────────────────────────────────────────┘
```

The policy block is included in the Ed25519 signature computation, cryptographically binding the usage rules to the signer's identity. Tampering with the policy invalidates the signature.

### 3.2 Self-Enforcing Usage Rules

The embedded policy enables a new class of content protection: **self-enforcing rules** that travel with the audio signal itself.

#### 3.2.1 Compliant Decoder Workflow

```
┌──────────────────────────────────────────────────────┐
│                 COMPLIANT DECODER                      │
├──────────────────────────────────────────────────────┤
│  Audio Input (any format, any transformation history) │
│      ↓                                                │
│  [Vouch Sonic Extraction] (PAD-014 pipeline)          │
│      ↓                                                │
│  [Payload Reconstruction]                             │
│      ↓                                                │
│  [Ed25519 Signature Verification]                     │
│   - Verify signer DID                                 │
│   - Verify signature covers policy block              │
│      ↓                                                │
│  [Policy Extraction]                                  │
│   - CBOR decode policy block                          │
│   - Check policy expiry timestamp                     │
│   - Map policy fields to action permissions            │
│      ↓                                                │
│  [Policy Evaluation]                                  │
│   - Context: What is the intended use?                │
│   - Match intended use against policy fields           │
│   - Return: ALLOW / DENY / CONTACT_CREATOR            │
│      ↓                                                │
│  [Output]                                             │
│   - Verified creator identity (DID)                   │
│   - Verified timestamp                                │
│   - Machine-readable usage permissions                │
│   - Enforcement recommendation                        │
└──────────────────────────────────────────────────────┘
```

#### 3.2.2 No Network Required

A critical property of the policy-carrying watermark: enforcement requires **no network access**. The decoder extracts the policy directly from the audio signal and evaluates it locally. This contrasts with every existing DRM system, which requires server-side license checks:

| System | Network Required for Policy Check | Policy Source |
|--------|----------------------------------|---------------|
| Apple FairPlay | Yes (license server) | Server-side |
| Widevine DRM | Yes (license server) | Server-side |
| C2PA assertions | No (but metadata must be intact) | File metadata |
| Creative Commons (in metadata) | No (but metadata must be intact) | File metadata |
| **PAD-023 Policy Watermark** | **No (extracted from audio signal)** | **Audio waveform** |

### 3.3 Forensic Policy Violation Detection

When watermarked audio is discovered in an unauthorized context (AI training dataset, voice clone model, unlicensed derivative work), the embedded policy provides cryptographic evidence of the violation.

#### 3.3.1 Forensic Evidence Chain

```python
from dataclasses import dataclass
from typing import Optional


@dataclass
class ForensicPolicyReport:
    """
    Generated when watermarked audio is found in a context
    that violates the embedded policy.
    """
    audio_source: str
    extraction_timestamp: float
    signer_did: str
    signer_did_verified: bool
    signature_valid: bool
    original_timestamp: float
    policy: dict
    violation_context: str
    violation_field: str
    violation_severity: str
    evidence_hash: str


def generate_forensic_report(
    audio_file: str,
    intended_use: str,
    extraction_result: dict,
) -> Optional[ForensicPolicyReport]:
    """
    Generate a forensic report when watermarked audio is found
    in a potentially violating context.

    The report provides cryptographic evidence that:
    1. The creator signed the audio (DID + Ed25519 signature)
    2. The creator explicitly set a policy prohibiting this use
    3. The policy was embedded at a specific time (timestamp)
    4. The policy could not have been accidentally stripped
       (it survived in the audio waveform)
    """
    if not extraction_result.get("watermark_found"):
        return None

    policy = extraction_result.get("policy", {})

    # Map intended use to policy field
    use_to_field = {
        "ai_training": "ai_training",
        "voice_cloning": "voice_cloning",
        "derivative_work": "derivatives",
        "commercial_use": "commercial",
        "sampling": "sampling",
        "broadcast": "broadcast",
    }

    policy_field = use_to_field.get(intended_use)
    if not policy_field or policy_field not in policy:
        return None

    permission = policy[policy_field]
    if permission == "deny":
        return ForensicPolicyReport(
            audio_source=audio_file,
            extraction_timestamp=extraction_result["extraction_time"],
            signer_did=extraction_result["signer_did"],
            signer_did_verified=extraction_result["did_verified"],
            signature_valid=extraction_result["signature_valid"],
            original_timestamp=extraction_result["timestamp_utc"],
            policy=policy,
            violation_context=intended_use,
            violation_field=policy_field,
            violation_severity="EXPLICIT_DENIAL",
            evidence_hash=extraction_result["evidence_hash"],
        )

    return None
```

#### 3.3.2 Legal Evidentiary Value

The forensic report establishes a chain of evidence that is significantly stronger than metadata-based rights assertions:

1. **Non-strippability**: The policy was embedded in the audio signal itself. It cannot have been "accidentally" removed during processing. Its presence in the discovered file proves it was present in the original.

2. **Cryptographic binding**: The policy is covered by the Ed25519 signature. Modifying the policy would invalidate the signature. This proves the policy was set by the signer, not injected by a third party.

3. **Temporal evidence**: The embedded timestamp proves when the policy was set. This establishes that the restriction predated the unauthorized use.

4. **Identity evidence**: The signer's DID is embedded and verifiable. The creator's identity is cryptographically bound to the restriction.

5. **Willful infringement indicator**: When a "deny" policy is embedded in the audio waveform and the audio is subsequently found in a prohibited context, the violator cannot claim ignorance--the restriction was literally embedded in the content they used.

### 3.4 Dual-Channel Policy Delivery

For maximum compatibility, the system embeds content usage policies in both strippable metadata and non-strippable watermarks simultaneously.

```
┌─────────────────────────────────────────────────────────┐
│                  DUAL-CHANNEL POLICY                      │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Channel 1: Metadata (C2PA, ID3, XMP)                    │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Rich policy expression (full JSON-LD)                │ │
│  │ Human-readable license text                          │ │
│  │ License URI and contact information                  │ │
│  │ Full C2PA manifest with assertion chain              │ │
│  │                                                       │ │
│  │ Durability: LOW (stripped by transcoding)             │ │
│  │ Richness: HIGH (unlimited space)                     │ │
│  │ Platform support: GROWING (C2PA adoption)            │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
│  Channel 2: Watermark (Vouch Sonic + PAD-023 Policy)     │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Compact CBOR-encoded policy (40-120 bytes)           │ │
│  │ Standardized permission codes                        │ │
│  │ Cryptographic binding to creator identity             │ │
│  │                                                       │ │
│  │ Durability: HIGH (survives all transformations)      │ │
│  │ Richness: LOW (capacity-constrained)                 │ │
│  │ Platform support: UNIVERSAL (signal-level)           │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
│  Resolution Rule:                                        │
│  - If both channels present: metadata is advisory,       │
│    watermark is authoritative                            │
│  - If only metadata present: use metadata                │
│  - If only watermark present: use watermark              │
│  - If conflict: watermark takes precedence               │
│    (cannot have been tampered without breaking signature) │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Technical Details

### 4.1 Policy Field Standardization

The policy encoding defines a standardized vocabulary of content usage categories and permission levels, designed for interoperability across platforms and jurisdictions.

#### 4.1.1 Standard Policy Categories

| Code | Field | Description | Common Values |
|------|-------|-------------|---------------|
| 0x01 | `ai_training` | Use in AI/ML model training datasets | deny, allow, allow_noncommercial |
| 0x02 | `voice_cloning` | Use for voice synthesis or cloning | deny, allow_with_license |
| 0x03 | `derivatives` | Creation of derivative works (remixes, samples) | deny, allow, allow_with_attribution |
| 0x04 | `commercial` | Commercial use of any kind | deny, allow, allow_with_license |
| 0x05 | `sampling` | Use of audio segments in new compositions | deny, allow_with_attribution |
| 0x06 | `broadcast` | Radio, TV, podcast broadcast | allow, allow_with_license |
| 0x07 | `sync_licensing` | Use in film, TV, advertising | deny, allow_with_license, contact_creator |
| 0x08 | `public_performance` | Live performance, venue playback | allow, allow_with_license |
| 0xFE | `expiry_utc` | Unix timestamp when policy expires | Integer (4 bytes) |
| 0xFF | `custom` | Free-text custom restriction | UTF-8 string (max 64 bytes) |

#### 4.1.2 Permission Levels

| Code | Value | Semantics |
|------|-------|-----------|
| 0x00 | `deny` | Explicitly prohibited. Violation is willful infringement. |
| 0x01 | `allow` | Permitted without conditions. |
| 0x02 | `allow_with_attribution` | Permitted if original creator is credited. |
| 0x03 | `allow_noncommercial` | Permitted for non-commercial purposes only. |
| 0x04 | `allow_with_license` | Permitted with a separate license agreement. |
| 0x05 | `contact_creator` | Contact creator for terms. License URI in watermark provides contact path. |

### 4.2 Policy Expiration in Watermark

The `expiry_utc` field enables time-bound usage policies embedded in the audio signal:

```python
import time


def evaluate_policy_with_expiry(
    policy: dict,
    intended_use: str,
    current_time: Optional[float] = None,
) -> dict:
    """
    Evaluate a content usage policy, respecting expiration.

    After expiry, all restrictions lapse (default: allow).
    This enables temporal rights management:
    - "No AI Training until 2030"
    - "Commercial rights revert after 5 years"
    - "Exclusive license expires January 2028"
    """
    if current_time is None:
        current_time = time.time()

    expiry = policy.get("expiry_utc")

    if expiry is not None and current_time > expiry:
        return {
            "permission": "allow",
            "reason": "POLICY_EXPIRED",
            "expiry_utc": expiry,
            "current_time": current_time,
            "note": "All restrictions have lapsed per creator-set expiry",
        }

    # Policy is active -- evaluate normally
    use_to_field = {
        "ai_training": "ai_training",
        "voice_cloning": "voice_cloning",
        "derivative_work": "derivatives",
        "commercial_use": "commercial",
        "sampling": "sampling",
        "broadcast": "broadcast",
        "sync_licensing": "sync_licensing",
        "public_performance": "public_performance",
    }

    field = use_to_field.get(intended_use)
    if field is None or field not in policy:
        return {
            "permission": "unspecified",
            "reason": "NO_POLICY_FOR_USE",
            "note": "Creator did not specify a policy for this use case",
        }

    return {
        "permission": policy[field],
        "reason": "POLICY_ACTIVE",
        "field": field,
        "expiry_utc": expiry,
    }
```

**Time-bound policy examples:**

| Scenario | Policy Configuration | Effect |
|----------|---------------------|--------|
| "No AI Training until 2030" | `ai_training: deny, expiry_utc: 1893456000` | AI training prohibited until Jan 1, 2030; allowed after |
| "5-year exclusive license" | `commercial: deny, expiry_utc: (now + 5 years)` | Commercial use restricted for 5 years, then open |
| "No voice cloning ever" | `voice_cloning: deny, expiry_utc: null` | No expiry; restriction is permanent |
| "Creative Commons for 2 years, then all rights reserved" | `derivatives: allow_with_attribution, expiry_utc: (now + 2 years)` | Open derivative use for 2 years; unspecified after (requires new watermark) |

### 4.3 Attribution Chain via Watermark

When derivative works are created from watermarked audio, the original creator's policy and identity persist in the derivative. This creates an attribution chain that survives any number of transformations.

```
Original Song (Artist A):
  Watermark: DID_A, policy: {derivatives: allow_with_attribution, ai_training: deny}
      |
      v
Remix (Producer B) samples 30 seconds:
  Watermark from original 30-second segment: DID_A still extractable
  Producer B adds their own watermark: DID_B, policy: {derivatives: deny}
      |
      v
The remix now carries TWO watermarks:
  1. DID_A's watermark in the sampled segment (with A's policy)
  2. DID_B's watermark across the full remix (with B's policy)
      |
      v
AI training company ingests the remix:
  Extraction reveals:
  - DID_A: ai_training = DENY (in sampled segment)
  - DID_B: derivatives = DENY (across full mix)

  Both creators' restrictions are discoverable from the audio signal.
```

### 4.4 Cross-Regulation Compliance Signaling

The machine-readable policy watermark maps to specific regulatory frameworks, enabling automated compliance checking by AI companies scanning training data.

#### 4.4.1 Regulatory Mapping

```python
# Mapping from policy fields to regulatory requirements

REGULATORY_MAPPING = {
    "eu_ai_act_article_53": {
        "description": "EU AI Act transparency obligations for GPAI providers",
        "relevant_fields": ["ai_training"],
        "compliance_rule": (
            "If ai_training == 'deny', this content MUST be excluded "
            "from training datasets under Article 53(1)(c) obligation "
            "to respect rights reservations expressed in machine-readable format"
        ),
        "reference": "Regulation (EU) 2024/1689, Article 53(1)(c)",
    },
    "us_eo_14110": {
        "description": "US Executive Order on Safe, Secure, and Trustworthy AI",
        "relevant_fields": ["ai_training", "voice_cloning"],
        "compliance_rule": (
            "AI developers should respect content creator preferences "
            "regarding training data inclusion"
        ),
        "reference": "Executive Order 14110, Section 5.2",
    },
    "dmca_1201": {
        "description": "DMCA anti-circumvention provisions",
        "relevant_fields": ["ai_training", "voice_cloning", "derivatives"],
        "compliance_rule": (
            "Watermark extraction and policy bypass may constitute "
            "circumvention of a technological protection measure"
        ),
        "reference": "17 U.S.C. section 1201",
    },
    "eu_copyright_directive_article_4": {
        "description": "EU Copyright Directive text and data mining opt-out",
        "relevant_fields": ["ai_training"],
        "compliance_rule": (
            "Rights holders who have expressly reserved their rights "
            "in a machine-readable manner must be excluded from TDM. "
            "A watermark-embedded 'deny' constitutes machine-readable reservation."
        ),
        "reference": "Directive (EU) 2019/790, Article 4",
    },
}


def check_regulatory_compliance(
    policy: dict,
    intended_use: str,
    jurisdiction: str,
) -> dict:
    """
    Check whether an intended use of watermarked audio
    complies with relevant regulations given the embedded policy.
    """
    violations = []

    for reg_id, reg_info in REGULATORY_MAPPING.items():
        # Check if this regulation applies to the jurisdiction
        if jurisdiction == "eu" and not reg_id.startswith("eu"):
            continue
        if jurisdiction == "us" and not reg_id.startswith("us") and reg_id != "dmca_1201":
            continue

        for field in reg_info["relevant_fields"]:
            if field in policy and policy[field] == "deny":
                if intended_use in ("ai_training", "voice_cloning", "derivative_work"):
                    violations.append({
                        "regulation": reg_id,
                        "reference": reg_info["reference"],
                        "policy_field": field,
                        "policy_value": "deny",
                        "compliance_rule": reg_info["compliance_rule"],
                    })

    return {
        "compliant": len(violations) == 0,
        "violations": violations,
        "jurisdiction": jurisdiction,
        "recommendation": (
            "PROCEED" if len(violations) == 0
            else "EXCLUDE_FROM_DATASET"
        ),
    }
```

---

## 5. Claims and Novel Contributions

### Claim 1: Policy-Carrying Watermark
A method for embedding machine-readable content usage policies within an audio watermark using psychoacoustic steganography (PAD-014), where the policies survive lossy compression, format conversion, platform transcoding, and analog re-recording alongside the identity provenance--ensuring that content protection rules are as durable as the content they govern.

### Claim 2: Self-Enforcing Usage Rules
A content protection mechanism where usage rules travel with the audio signal itself rather than in strippable metadata containers, enabling any compliant decoder to read and enforce the creator's stated terms without network access, server-side license checks, or platform cooperation.

### Claim 3: Forensic Policy Violation Detection
A forensic evidence system where, when watermarked audio is found in an AI training dataset, voice cloning system, or other prohibited context, the embedded policy provides cryptographic evidence that the creator explicitly prohibited such use--establishing willful infringement through non-strippable, cryptographically signed, temporally anchored restrictions that could not have been accidentally removed.

### Claim 4: Compact Binary Policy Encoding
A CBOR-based encoding scheme for content usage policies that fits within the capacity constraints of psychoacoustic watermarking (40-120 bytes), supporting standardized policy categories (`ai_training`, `voice_cloning`, `derivatives`, `commercial`, `sampling`, `broadcast`, `sync_licensing`, `public_performance`) plus custom free-text rules, with 1-byte field identifiers and 1-byte permission values for maximum compactness.

### Claim 5: Policy Expiration in Watermark
Time-bound usage policies embedded in the audio signal, where an `expiry_utc` timestamp allows restrictions to automatically lapse after a creator-specified date (e.g., "No AI Training until 2030"), enabling temporal rights management without server-side revocation infrastructure--the policy is self-expiring based on its own embedded timestamp.

### Claim 6: Attribution Chain via Watermark
A method for preserving creator attribution and usage policies through derivative works, where the original creator's watermark persists in sampled or remixed audio segments, creating a multi-layer attribution chain where each contributor's identity and policy is independently extractable from the composite audio signal.

### Claim 7: Cross-Regulation Compliance Signaling
Machine-readable policy watermarks that map to specific regulatory frameworks (EU AI Act Article 53, EU Copyright Directive Article 4, US Executive Order 14110, DMCA Section 1201), enabling automated compliance checking by AI companies scanning training data--where a watermark-embedded "deny" constitutes machine-readable rights reservation under applicable law.

### Claim 8: Dual-Channel Policy Delivery
A system where content protection rules are simultaneously embedded in both strippable metadata (C2PA manifests, ID3 tags, XMP) and non-strippable watermarks (Vouch Sonic), with a defined resolution hierarchy where the watermark serves as the authoritative fallback when metadata has been stripped, and conflicts are resolved in favor of the cryptographically signed watermark.

---

## 6. Security Considerations

### 6.1 Attack Resistance

| Attack Vector | Countermeasure |
|---------------|----------------|
| **Policy tampering** | Policy is included in Ed25519 signature; modification invalidates the watermark |
| **Policy removal** | Policy is spread-spectrum encoded in the audio waveform; removal requires destroying the audio quality beyond usability (same robustness as PAD-014 provenance) |
| **Policy downgrade** | Changing "deny" to "allow" invalidates the cryptographic signature |
| **Selective extraction** | An attacker who extracts and re-encodes audio without watermark must destroy the watermark signal, which degrades audio quality |
| **Replay/transplant** | Content hash binding (PAD-014 Claim 12) prevents transplanting a permissive policy from one file to another |
| **Expiry manipulation** | Timestamp is part of the signed payload; advancing the expiry invalidates the signature |
| **Policy forgery** | Requires the creator's Ed25519 private key; public key verification prevents third-party policy injection |

### 6.2 Limitations

1. **Capacity constraints**: The psychoacoustic watermark has finite payload capacity. Complex, multi-clause licensing terms cannot be fully expressed in 40-120 bytes. The `license_uri` field provides a pointer to full terms, while the watermark carries the enforceable summary.

2. **No enforcement mechanism**: The watermark carries the policy but cannot technically prevent unauthorized use. Enforcement depends on compliant decoders, legal frameworks, and forensic discovery. The watermark is evidence, not a lock.

3. **Short audio clips**: Very short audio segments (under 5 seconds) may not carry sufficient redundant watermark data for reliable policy extraction. The minimum reliable embedding duration depends on audio content characteristics and target robustness level.

4. **Heavily compressed audio**: Audio that has already undergone extreme lossy compression (e.g., 32 kbps Opus) may not have sufficient perceptual headroom for additional watermark embedding. The policy extends the payload, increasing the minimum viable bitrate for reliable embedding.

5. **Policy versioning**: If a creator changes their policy after initial embedding, the watermark in existing copies reflects the original policy. There is no mechanism for retroactive policy updates to already-distributed watermarked audio. The `expiry_utc` field provides a partial solution for time-limited restrictions.

6. **Custom field ambiguity**: The free-text `custom` field (max 64 bytes) may be ambiguous or misinterpreted. Standardized policy fields should be preferred; the custom field is a fallback for edge cases not covered by the standard vocabulary.

### 6.3 Privacy Considerations

The watermark embeds the creator's DID in every copy of the audio. Creators should be aware that:

- Every copy of the watermarked audio carries their cryptographic identity.
- The DID can be resolved to verify the creator's identity.
- Anonymous or pseudonymous creators may prefer to use a purpose-specific DID rather than their primary identity.
- The policy itself may reveal information about the creator's licensing strategy.

---

## 7. Implementation Architecture

### 7.1 Encoder Integration Points

| Integration Point | Method | Policy Source |
|-------------------|--------|---------------|
| **DAW Plugins (VST3/AU)** | Plugin UI presents policy checkboxes during export/bounce | Creator selects policy in DAW |
| **CLI Tools** | `vouch sonic sign --policy ai_training=deny,voice_cloning=deny` | Command-line flags |
| **Music Distribution Platforms** | Server-side batch watermarking during upload processing | Platform-provided policy form |
| **Podcast Hosting** | Automatic watermarking during episode publish | Creator dashboard settings |
| **Mobile Recording Apps** | SDK integration for on-device watermarking | App-level policy defaults |
| **Streaming Encoders (OBS/FFmpeg)** | Real-time policy embedding during live broadcast | Pre-configured policy profile |

### 7.2 Decoder Deployment

| Deployment | Use Case | Action on Policy Violation |
|------------|----------|---------------------------|
| **AI Training Pipeline Scanner** | Scan audio files before ingestion into training datasets | Exclude file from dataset; log violation |
| **Voice Cloning System Gate** | Check source audio before voice model training | Block cloning; require explicit license |
| **Content Platform Ingest** | Verify creator terms during upload processing | Display policy to uploader; flag conflicts |
| **Music Sampling Workstation** | Check sample clearance during production | Warn producer of restrictions |
| **Legal/Forensic Analysis** | Investigate unauthorized use after discovery | Generate forensic evidence report |
| **Regulatory Compliance Audit** | Bulk-scan training datasets for policy violations | Generate compliance report per regulation |

### 7.3 Integration with Vouch Protocol Ecosystem

```
┌──────────────────────────────────────────────────────────┐
│                VOUCH PROTOCOL ECOSYSTEM                    │
├──────────────────────────────────────────────────────────┤
│                                                            │
│  PAD-001 (Identity)                                        │
│   └─ DID + Ed25519 keypair for creator identity            │
│       └─ Used as signer_did in watermark                   │
│                                                            │
│  PAD-014 (Vouch Sonic)                                     │
│   └─ Psychoacoustic steganography engine                   │
│       └─ Spread-spectrum embedding                         │
│       └─ Perceptual masking model                          │
│       └─ Multi-resolution layers (L1-L4)                   │
│       └─ Chirp synchronization                             │
│       └─ Resilient decoding pipeline                       │
│           └─ PAD-023 extends the PAYLOAD, reuses engine    │
│                                                            │
│  PAD-023 (This Disclosure)                                 │
│   └─ Content usage policy payload                          │
│       └─ CBOR-encoded policy fields                        │
│       └─ Cryptographic binding to identity                 │
│       └─ Forensic violation detection                      │
│       └─ Regulatory compliance mapping                     │
│                                                            │
│  C2PA Integration                                          │
│   └─ Dual-channel: C2PA metadata + watermark               │
│       └─ Watermark is authoritative fallback               │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

---

## 8. Use Cases

### 8.1 Musicians and Recording Artists

**Scenario:** An independent musician releases a new album and wants to prevent AI companies from using their vocals to train voice synthesis models while allowing non-commercial remixes.

**Policy configuration:**
```json
{
  "ai_training": "deny",
  "voice_cloning": "deny",
  "derivatives": "allow_noncommercial",
  "commercial": "deny",
  "sampling": "allow_with_attribution",
  "broadcast": "allow"
}
```

**Outcome:** The album is uploaded to Spotify, YouTube, and Bandcamp. Each platform transcodes the audio, stripping all metadata. But the watermark survives. When a voice AI startup scrapes the audio from YouTube and uses it to train a vocal synthesis model, a subsequent audit of their training data reveals the embedded policy: `voice_cloning: deny`. The musician has cryptographic evidence of willful infringement--the restriction was literally embedded in the audio the startup used.

### 8.2 Podcasters and Spoken-Word Creators

**Scenario:** A journalist publishes investigative podcast episodes and wants to prevent AI training on their voice while allowing broadcast syndication.

**Policy configuration:**
```json
{
  "ai_training": "deny",
  "voice_cloning": "deny",
  "derivatives": "deny",
  "commercial": "allow_with_license",
  "broadcast": "allow_with_attribution",
  "expiry_utc": null
}
```

**Outcome:** The podcast is distributed across Apple Podcasts, Spotify, and RSS feeds. Each platform processes the audio differently. An AI company building a speech-to-text model scrapes podcast RSS feeds and includes the episodes in training data. The embedded policy survives the pipeline. During an EU AI Act compliance audit, the AI company's training dataset scanner detects the `ai_training: deny` watermark. The episodes are flagged for removal. The journalist is notified that their restrictions were discovered and honored--without any action on their part.

### 8.3 Voice Actors and Narrators

**Scenario:** A professional voice actor records audiobook narration under contract. The contract specifies that the voice may not be cloned and the recordings may not be used for AI training. The voice actor wants these contractual terms to be technically enforceable.

**Policy configuration:**
```json
{
  "ai_training": "deny",
  "voice_cloning": "deny",
  "derivatives": "deny",
  "commercial": "allow_with_license",
  "sampling": "deny",
  "custom": "contractual_restriction_voice_talent_agreement"
}
```

**Outcome:** The audiobook is distributed through Audible, Google Play Books, and direct download. Years later, a voice cloning service begins offering a voice that sounds suspiciously similar. The voice actor's legal team obtains audio samples from the cloning service. Forensic analysis extracts the original watermark from the cloned voice's training data, revealing the `voice_cloning: deny` policy signed by the voice actor's DID. This provides evidence that the cloning service used audio with an explicit prohibition, strengthening the infringement claim.

### 8.4 Enterprise Audio Communications

**Scenario:** A financial services firm records all client advisory calls for regulatory compliance. These recordings contain sensitive information and must never leave the firm's systems or be used for AI training.

**Policy configuration:**
```json
{
  "ai_training": "deny",
  "voice_cloning": "deny",
  "derivatives": "deny",
  "commercial": "deny",
  "sampling": "deny",
  "broadcast": "deny",
  "custom": "confidential_regulated_communication"
}
```

**Outcome:** A disgruntled employee exports call recordings and uploads them to a file-sharing service. The recordings are subsequently scraped by an AI training pipeline. Even though the files have been re-encoded multiple times, the watermark carries the enterprise's `deny-all` policy signed by the firm's corporate DID. When discovered, the embedded policy provides evidence that the recordings were explicitly restricted, supporting both the firm's data loss investigation and any regulatory enforcement action.

### 8.5 Music Labels and Catalog Management

**Scenario:** A record label manages a catalog of 50,000 tracks with varying rights. Some tracks have AI training opt-outs, some have limited derivative rights, and some are fully open. The label needs machine-readable rights that persist regardless of distribution channel.

**Workflow:**
1. Label applies watermark policies during catalog digitization.
2. Each track carries its specific policy in the watermark.
3. When tracks are distributed to streaming platforms, metadata is stripped but policies persist.
4. AI companies scanning for training data can extract policies from any copy of any track.
5. The label can update policies for new releases but cannot retroactively change watermarked copies already in circulation (by design--the original terms are immutable evidence).

### 8.6 Time-Limited Rights

**Scenario:** A musician signs a 3-year exclusive distribution deal. During the exclusivity period, no derivatives or commercial use by third parties is permitted. After the deal expires, the musician wants to allow non-commercial remixes.

**Policy configuration (during exclusivity):**
```json
{
  "ai_training": "deny",
  "voice_cloning": "deny",
  "derivatives": "deny",
  "commercial": "deny",
  "expiry_utc": 1861920000
}
```

**Outcome:** The `expiry_utc` corresponds to the exclusivity end date (January 1, 2029). Any compliant decoder checking this watermark before that date sees the restrictions. After the date, the policy is treated as expired and the default permission is `unspecified` (the musician can then re-watermark with a new, more permissive policy if desired). This enables temporal rights management without requiring server-side revocation.

---

## 9. Conclusion

PAD-023 addresses a critical gap in content rights management: the asymmetry between content durability and policy durability. Audio content survives lossy compression, format conversion, platform transcoding, and analog re-recording. The rules governing that content do not. Every existing rights management system stores policies in metadata layers that are routinely stripped, leaving content protection rules unable to survive the same transformations that the content itself easily survives.

By extending the Vouch Sonic watermark (PAD-014) to carry machine-readable content usage policies alongside cryptographic provenance, this disclosure enables a new paradigm: **content protection rules that are as durable as the content they govern**. The policy-carrying watermark travels with the audio signal itself, embedded using psychoacoustic steganography at frequencies and amplitudes masked by the human auditory system, surviving every transformation the audio survives.

The system's eight novel contributions--policy-carrying watermarks, self-enforcing usage rules, forensic policy violation detection, compact binary policy encoding, policy expiration in watermark, attribution chain via watermark, cross-regulation compliance signaling, and dual-channel policy delivery--collectively establish a comprehensive framework for content rights that is:

1. **Durable**: Policies survive lossy compression, format conversion, platform transcoding, and analog re-recording.
2. **Self-contained**: No network access or database lookup required for policy extraction.
3. **Cryptographically bound**: Policies are signed by the creator's Ed25519 key and cannot be tampered with.
4. **Forensically valuable**: Embedded policies provide evidence of willful infringement that cannot have been accidentally stripped.
5. **Regulation-compatible**: Machine-readable policies map to EU AI Act, EU Copyright Directive, and US regulatory requirements.
6. **Temporally aware**: Time-bound restrictions can automatically lapse without server-side revocation.

For creators--musicians, podcasters, voice actors, and enterprises--this means that their content protection preferences travel with their content, regardless of how many platforms process it, how many formats it is converted through, and how many times it is re-encoded. For AI companies and content platforms, this means that rights reservations are discoverable in the audio signal itself, enabling genuine compliance with creator preferences and regulatory mandates.

---

## 10. References

- C2PA (Coalition for Content Provenance and Authenticity) Technical Specification v2.1
- CBOR (Concise Binary Object Representation), RFC 8949
- EU AI Act, Regulation (EU) 2024/1689, Article 53 -- Obligations for providers of general-purpose AI models
- EU Copyright Directive, Directive (EU) 2019/790, Article 4 -- Exception for text and data mining
- US Executive Order 14110 on Safe, Secure, and Trustworthy AI, Section 5.2
- Digital Millennium Copyright Act (DMCA), 17 U.S.C. Section 1201
- W3C Decentralized Identifiers (DIDs) v1.0
- I. Cox et al., "Digital Watermarking and Steganography" (2nd Edition)
- E. Zwicker and H. Fastl, "Psychoacoustics: Facts and Models"
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-022
- PAD-001: Method for Cryptographic Agent Identity via Ed25519 Keypairs and Decentralized Identifiers
- PAD-014: Method for Robust Acoustic Provenance via Psychoacoustic Steganography ("Vouch Sonic")

---

## 11. Prior Art Declaration

This document is a **Prior Art Disclosure** published to establish prior art and prevent patent monopolization of the described methods. The techniques, architectures, and systems described herein are hereby released into the public domain under the **Creative Commons CC0 1.0 Universal** dedication.

Any person or organization may freely implement, modify, extend, or commercialize the methods described in this disclosure without restriction, license fee, or attribution requirement.

This disclosure is intended to serve as defensive prior art under 35 U.S.C. Section 102(a)(1) and equivalent provisions in other patent jurisdictions. By publishing this disclosure with a specific date and detailed technical description, the author establishes that these methods were publicly known as of the Prior Art Effective Date, precluding subsequent patent claims on the same or substantially similar inventions.

**Author:** Ramprasad Anandam Gaddam
**Date:** February 22, 2026
**License:** CC0 1.0 Universal (Public Domain Dedication)
