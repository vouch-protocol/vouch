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

We have published 15 PADs to protect our IP.

> **📄 Full List**: See [`docs/disclosures/README.md`](./disclosures/README.md) for the complete list of PAD-001 to PAD-015.

*   **Key High-Level Concepts**:
    *   **Identity**: PAD-001 (Crypto Identity), PAD-003 (Sidecar).
    *   **Verification**: PAD-004 (DOM Matching), PAD-015 (Ambient Witness).
    *   **Governance**: PAD-012 (Covenants).

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

## 6. Key API Reference (Technical Detail)

> **Context Tip**: Only document *stable, primary interfaces* here. Do not document every internal function; let the code speak for itself.

### `vouch.signer.Signer`
*   `__init__(private_key_jwk: str, did: str)`: Initialize with Ed25519 key.
*   `sign(payload: dict) -> str`: Returns JWS Compact Token.

### `vouch.media.c2pa.MediaSigner`
*   `sign_image(source_path, output_path)`: Embeds C2PA manifest.
    *   **Note**: Requires X.509 cert chain (self-signed allowed for dev).

### `demo.vouch_mcp_server.server` (Tools)
*   `sign_text(text, private_key_jwk, did)`: Returns JWS.
*   `verify_text(token, public_key_jwk)`: Returns validation string.

---

## 7. Feature Deep Dives & Usage

### 📸 Image Signing (`vouch.media.c2pa`)
**Class**: `MediaSigner`
*   **Purpose**: Embeds C2PA (Content Credentials) manifests into images/audio.
*   **Key Dependencies**: `c2pa-python`, `cryptography` (for key handling).
*   **Usage Flow**:
    1.  Load Identity (`vouch.keys.KeyPair`).
    2.  Convert JWK private key to `Ed25519PrivateKey`.
    3.  Generate X.509 Certificate Chain (Self-signed for dev, CA for prod).
    4.  Call `MediaSigner.sign_image(input, output)`.

### 🌐 Browser Extension (`browser-extension/`)
**Manifest**: Manifest V3
*   **`content.js`**:
    *   Implements **PAD-004 (DOM-Traversing Signature Matching)**.
    *   Scans page for `[vouch-token]` attributes or linked C2PA images.
    *   Injects "✓ Verified" badges into the DOM.
*   **`background.js`**:
    *   Handles context menu actions ("Verify Image with Vouch").
    *   Manages local keyring state.

### 📝 Text Signing (`vouch.signer`)
**Class**: `Signer`
*   **Format**: JWS (JSON Web Signature) Compact Serialization (`header.payload.signature`).
*   **Header**: `{"alg": "EdDSA", "typ": "JWT"}`.
*   **Usage**: Used for signing usage covenants (PAD-012) and prompt attribution.

### 🔗 Shortlinks & Verification
**Domain**: `v.vouch-protocol.com` (and `vch.sh`)
*   **Logic**: Handled by **Cloudflare Worker** (`cloudflare-worker/`).
*   **Flow**:
    *   Shortlink `vch.sh/{id}` -> 301 Redirect -> `vouch-protocol.com/v/{id}`.
    *   Worker fetches verification data from KV store or on-chain registry.
    *   Renders a dynamic OpenGraph meta tag for social previews.

---

## 8. How to Update This Context

**At the end of every session, run `python scripts/scribe.py save` to generate an update prompt.**
