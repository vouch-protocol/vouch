# PAD-025: Edge-First Content Provenance Architecture

**Identifier:** PAD-025
**Title:** Edge-First Content Provenance via Client-Side WebAssembly and On-Device Machine Learning
**Publication Date:** February 28, 2026
**Prior Art Effective Date:** February 28, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Content Authentication / Privacy-Preserving Computing / Edge Computing / WebAssembly
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-014 (Vouch Sonic), PAD-023 (Content Policy Watermarking), PAD-012 (VouchCovenant)

---

## 1. Abstract

A system architecture for content provenance (audio watermarking, voice biometric enrollment, media signing) in which all computationally intensive operations (digital signal processing, machine learning inference, feature extraction, watermark embedding, and watermark detection) execute entirely on the client device within the user's web browser using WebAssembly (WASM) and on-device ML inference (ONNX Runtime Web). The server's role is reduced to authentication, metadata storage, audit logging, and cryptographic token signing.

This architecture ensures that raw media (audio recordings, voice samples, images, video) never leaves the user's device. Only non-reversible metadata (cryptographic hashes, watermark identifiers, mathematical feature vectors) is transmitted to the server. Even if the server is compromised, no raw media can be reconstructed from the stored data.

This disclosure covers the complete architectural pattern, the tiered fallback strategy, and the privacy properties that emerge from the separation of compute (client) and storage (server).

---

## 2. Problem Statement

### 2.1 Server-Centric Provenance Systems

Existing content provenance systems require users to upload raw media to a server for processing:
- Audio watermarking services require uploading the full audio file.
- Voice biometric systems require sending voice recordings to a cloud API.
- Media signing pipelines process files server-side before returning signed output.

This creates three problems:
1. **Privacy exposure:** Raw media traverses the network and resides on third-party servers.
2. **Latency:** Network round-trips add 200-500ms per operation.
3. **Cost:** Server-side DSP and ML inference require GPU or high-CPU instances.

### 2.2 The Audio Privacy Gap

Voice recordings are among the most sensitive biometric data. Current voice verification APIs (Azure Speaker Recognition, AWS Voice ID, Google Cloud Speech) require sending raw audio to cloud endpoints. This means:
- The cloud provider has access to the user's voice recordings.
- Voice data may be retained for model training (depending on provider terms).
- A breach of the cloud provider exposes raw biometric data.

### 2.3 Serverless Compute Constraints

Modern serverless platforms (Vercel, Cloudflare Workers, AWS Lambda) impose tight resource constraints:
- Bundle size limits (1-50 MB depending on platform).
- Execution time limits (10-60 seconds).
- No filesystem access on edge runtimes.
- No GPU or heavy CPU available.

These constraints make server-side audio processing impractical on serverless infrastructure.

---

## 3. Solution (The Invention)

### 3.1 Architecture Overview

The system separates concerns between client and server:

**Client (Browser / PWA / Mobile WebView):**
- WebAssembly module for DSP operations (watermark embed/detect, audio preprocessing)
- ONNX Runtime Web for ML inference (speaker embedding extraction)
- Web Audio API for microphone capture
- IndexedDB for caching ML models after first download
- All raw audio processing happens here and only here

**Server (Serverless / Node.js):**
- Authentication and license validation
- Metadata storage in key-value database (Redis, DynamoDB, etc.)
- Quota tracking and rate limiting per feature per tier
- Audit logging of provenance events
- Cryptographic token signing (Ed25519 Vouch-Tokens)

**Data flow for watermark embedding:**
1. User selects audio file in browser.
2. WASM module embeds watermark locally, producing watermarked audio and a watermark ID.
3. Browser sends ONLY {watermarkId, audioHash, payloadHash, did} to server.
4. Server stores metadata, issues signed Vouch-Token.
5. User downloads watermarked audio directly from browser memory.
6. Raw audio never touches the network.

**Data flow for voice enrollment:**
1. User records voice sample via Web Audio API.
2. On-device ONNX model (or WASM DSP fallback) extracts feature vector.
3. Browser sends ONLY the feature vector (e.g., 192-dim float array) to server.
4. Server stores vector, computes centroid average, updates enrollment record.
5. Raw voice recording is discarded in browser memory.
6. Voice recording never touches the network.

### 3.2 WASM Module Architecture

The WebAssembly module is compiled from Rust source using wasm-bindgen:

```
Source: Rust (shared DSP core)
    |
    v
wasm-pack build --target web
    |
    v
@vouch/sonic-wasm npm package (~250KB)
    |
    v
Dynamic import in browser (lazy-loaded on first use)
```

Exported functions:
- `embedWatermark(pcmData, did, timestamp)` -> watermarked PCM + metadata
- `detectWatermark(pcmData)` -> {detected, confidence, payloadHash}
- `extractVoiceFeatures(pcmData, sampleRate)` -> feature vector
- `cosineSimilarity(vectorA, vectorB)` -> similarity score

The WASM module uses only WASM-compatible dependencies:
- `rustfft` for FFT (no system FFTW dependency)
- `sha2` for hashing (pure Rust, no OpenSSL)
- `getrandom` with `js` feature for WASM-compatible randomness

### 3.3 On-Device ML Inference

For higher-accuracy voice embeddings, the system uses ONNX Runtime Web:

```
ECAPA-TDNN model (quantized INT8, ~3MB)
    |
    v
Cached in IndexedDB after first download
    |
    v
onnxruntime-web (WASM execution provider)
    |
    v
192-dimensional speaker embedding vector
```

The model is downloaded once and cached indefinitely. Subsequent visits load from IndexedDB with zero network cost. The WASM execution provider ensures the model runs on any browser without WebGL or WebGPU requirements.

### 3.4 Tiered Fallback Strategy

The system supports multiple client capabilities:

```
Tier 1 (Browser, primary):   WASM + ONNX Runtime Web
Tier 2 (CLI / API clients):  Server-side TypeScript DSP fallback
Tier 3 (Batch / enterprise): Python bridge with full codec support
```

Each tier produces compatible output (same watermark format, same feature vector schema). The server accepts results from any tier transparently.

### 3.5 Privacy Properties

The architecture provides the following privacy guarantees by construction:

1. **Data minimization:** Only non-reversible derivatives (hashes, feature vectors) leave the device.
2. **No reconstruction:** SHA-256 hashes and averaged feature vectors cannot be inverted to recover original audio.
3. **Server breach safety:** A complete database dump reveals only mathematical metadata, never raw media.
4. **Zero-knowledge verification:** The server can verify watermark presence (via hash lookup) without ever seeing the audio.
5. **Offline capability:** With cached WASM module and ONNX model, watermark detection and voice verification can run entirely offline.

---

## 4. Prior Art Differentiation

### 4.1 Existing Systems

| System | Architecture | Privacy | Latency |
|--------|-------------|---------|---------|
| Azure Speaker Recognition | Cloud API | Audio uploaded to Azure | 200-500ms |
| AWS Voice ID | Cloud API | Audio uploaded to AWS | 200-500ms |
| Audible Magic | Cloud API | Audio uploaded to server | 300-800ms |
| YouTube Content ID | Cloud processing | Full video uploaded | Minutes |
| This disclosure | Edge-first WASM/ONNX | Audio never leaves device | <100ms |

### 4.2 Novel Combinations

While WebAssembly, ONNX Runtime Web, and audio watermarking each exist independently, this disclosure describes their combination into a unified content provenance system where:
- Watermark embedding, detection, and voice biometric extraction all run client-side.
- The server is stateless with respect to media content.
- Multiple client tiers (WASM, TypeScript, Python) produce interoperable output.
- The architecture maps to serverless infrastructure with no additional compute cost.

### 4.3 Differences from PAD-014

PAD-014 describes the Vouch Sonic watermarking algorithm (spread-spectrum steganography). This disclosure describes the deployment architecture that runs PAD-014's algorithm on the client device, the privacy properties that result, and the server's reduced role as a metadata store and token issuer.

---

## 5. Technical Specifications

### 5.1 WASM Module Size Budget

| Component | Size |
|-----------|------|
| DSP core (FFT, correlation, windowing) | ~80KB |
| Crypto (SHA-256, Ed25519 stubs) | ~60KB |
| Voice feature extraction | ~40KB |
| wasm-bindgen glue | ~70KB |
| **Total** | **~250KB** |

### 5.2 ONNX Model Specifications

| Property | Value |
|----------|-------|
| Model | ECAPA-TDNN (quantized INT8) |
| Size | ~3MB |
| Input | Mel spectrogram (80 bands) |
| Output | 192-dimensional embedding vector |
| Execution provider | WASM (universal browser support) |
| Cache | IndexedDB (persistent across sessions) |

### 5.3 Server API Contract (Metadata Only)

**POST /sonic/register** (after client-side watermark embedding):
```json
{
  "watermarkId": "sonic-a1b2c3d4e5f67890",
  "audioHash": "sha256hex64chars",
  "payloadHash": "sha256hex64chars",
  "did": "did:key:z6Mk...",
  "duration": 180
}
```

**POST /voice-id/enroll** (after client-side feature extraction):
```json
{
  "embedding": [0.12, -0.34, 0.56, ...],
  "embeddingType": "ml_ecapa",
  "did": "did:key:z6Mk..."
}
```

No raw audio in either request.

### 5.4 Offline Mode

When network is unavailable:
1. WASM watermark embed/detect works fully offline.
2. Voice verification works offline if the user's own centroid embedding is cached locally.
3. Results are queued and synced to server when connectivity returns.

---

## 6. Use Cases

### 6.1 Journalist Field Recording
A journalist records interviews in a location with poor connectivity. The WASM module embeds Vouch Sonic watermarks into each recording locally. When connectivity returns, only watermark metadata is synced. The source audio remains on the journalist's device.

### 6.2 Podcaster Voice Protection
A podcaster enrolls their Voice ID using 3 samples recorded through the browser. The ONNX model extracts 192-dimensional embeddings locally. Only the mathematical vectors are stored server-side. If someone AI-clones the podcaster's voice, verification runs locally in the browser with the stored centroid.

### 6.3 Music Label Catalog Protection
A music label signs thousands of tracks with Vouch Sonic watermarks. Using the batch API (Tier 3 Python bridge), tracks are watermarked server-side. Using the web dashboard (Tier 1 WASM), individual artists can verify watermark presence in their released tracks without uploading audio.

### 6.4 Privacy-Regulated Industries
In healthcare or legal contexts where audio recordings cannot leave the organization's network, the edge-first architecture allows watermarking and verification within the browser. No external API calls carry raw audio. Compliance teams can audit the server database knowing it contains only metadata.

---

## 7. Conclusion

The Edge-First Content Provenance Architecture addresses the fundamental tension between content authentication (which requires processing media) and user privacy (which requires not transmitting media). By executing all DSP and ML operations on the client device via WebAssembly and ONNX Runtime Web, the system achieves sub-100ms latency, zero server compute cost for media processing, and a privacy guarantee that raw media never leaves the user's device. The server's minimal role (metadata storage + token signing) maps naturally to serverless infrastructure, eliminating the need for GPU instances or audio processing servers.

---

## 8. References

- WebAssembly Core Specification (W3C)
- ONNX Runtime Web (Microsoft)
- wasm-bindgen (Rust and WebAssembly Working Group)
- Vouch Protocol: PAD-014 (Vouch Sonic), PAD-023 (Content Policy Watermarking)
- W3C Decentralized Identifiers (DIDs) v1.0
- Web Audio API (W3C)
- IndexedDB API (W3C)
- ECAPA-TDNN: B. Desplanques et al., "ECAPA-TDNN: Emphasized Channel Attention, Propagation and Aggregation in TDNN Based Speaker Verification" (Interspeech 2020)

---

**License:** This disclosure is published under Creative Commons CC0 1.0 Universal (Public Domain Dedication). It is released as defensive prior art to prevent patent monopolization of the described techniques. Anyone is free to implement, modify, and extend this architecture without restriction.

**Prior Art Declaration:** This document establishes prior art effective February 28, 2026, under 35 U.S.C. Section 102(a)(1) and equivalent international provisions.
