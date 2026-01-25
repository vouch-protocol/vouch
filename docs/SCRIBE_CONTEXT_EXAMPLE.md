# Vouch Protocol - Developer Master Context (Public Example)

> **ℹ️ NOTE**: This is a public example of a Scribe Context file. The actual production context contains private architectural details and is git-ignored.

---

## 1. Project Identity & Vision

**Name**: Vouch Protocol
**Tagline**: "The SSL for AI Agents" & "Truth Layer for Media"
**Core Mission**: To provide cryptographically verifiable provenance for:
1.  **AI Agents**: Proving "I am an authorized agent of Company X".
2.  **Media Content**: Proving "This image was captured at this time/place" (C2PA + Vouch).
3.  **Code**: Proving "This code was written by Agent Y".

**Current Version**: `v1.5.0`
**License**: Apache 2.0

---

## 2. Architecture & Directory Structure

### 📂 Core (`vouch/`) - Open Source
*   **`vouch.keys`**: Identity generation (Ed25519/DID).
*   **`vouch.signer`**: Core signing logic for JSON/HTTP.
*   **`vouch.verifier`**: Verification logic.
*   **`vouch.media.c2pa`**: **CRITICAL**. Wrapper around `c2pa-python` for Content Credentials.
    *   `MediaSigner`: Signs images with C2PA manifests.
    *   `MediaVerifier`: Verifies C2PA manifests.
*   **`vouch.media.native`**: Fallback signature format (Ed25519) when C2PA is unavailable.
*   **`vouch.media.badge`**: `BadgeFactory` generates visual QR codes.

### 📂 Scripts
*   **`scripts/scribe.py`**: **Context maintenance tool**. Run this to generate AI context update prompts.

### 📂 Demos (`demo/`)
*   **`vouch-mcp-server/`**: **Active**. Claude MCP server for signing text/images.
*   **`vouch-verify/`**: Streamlit app for media verification.

### 📂 Documentation (`docs/`)
*   **Prior Art Disclosures (PADs)**: Defensively published IP.
    *   PAD-001 to PAD-015.

---

## 3. Key Technical Decisions

### 🤖 Gemini 3 Integration
*   **Purpose**: Deepfake detection and multimodal analysis.
*   **Implementation**: Used in `demo/vouch-verify` to score image authenticity before C2PA verification.

### 🛠️ Technical Constraints
*   **Python Version**: 3.9+ compatibility required.
*   **C2PA**: `c2pa-python` integration requires careful handling of binary extensions.

---

## 4. IP Portfolio (Prior Art Disclosures)

We have published 15 PADs to protect our IP:

| ID | Title | Key Concept |
|----|-------|-------------|
| **PAD-001** | Cryptographic Agent Identity | The core concept. |
| **PAD-002** | Chain of Custody | Agent handoff signing. |
| **PAD-012** | Vouch Covenant | "No AI Training" clauses in signatures. |
| **PAD-013** | Vouch Airgap | QR-code based offline signing. |
| **PAD-014** | Vouch Sonic | Audio steganography for provenance. |
| **PAD-015** | **Ambient Witness Protocol** | Crowd-sourced BLE witnessing (Latest). |

---

## 5. Development Roadmap

### Completed ✅
*   [x] Core Protocol v1.0
*   [x] C2PA Integration (Images/Audio)
*   [x] Browser Extension (Chrome)
*   [x] v1.5.0 Release
*   [x] PAD-001 to PAD-015
*   [x] **Demo 1: Vouch Verify** (Streamlit)
*   [x] **Demo 2: MCP Server** (Claude Integration)

### Active / Next Up 🚧
*   [ ] **Demo 3: Journalist Workflow**
    *   *Goal*: Org credentials for newsrooms.
*   [ ] **Demo 4: Voice Covenant**
    *   *Goal*: "Do not train on my voice" tag.
*   [ ] **Demo 5: VouchCode**
    *   *Goal*: Git commit signing for AI agents.

---

## 6. How to Update This Context

**At the end of every session, run `python scripts/scribe.py save` to generate an update prompt.**
