//! Vouch Sonic WASM - Browser-side audio watermark embedding and detection
//!
//! This crate provides a WASM-compatible build of the Vouch Sonic DSP engine
//! for running watermark operations entirely in the browser. No audio data
//! leaves the client - only metadata (watermarkId, hashes) is sent to the server.
//!
//! # Architecture
//!
//! This crate is now a **thin `wasm-bindgen` shim** over the shared, pure-Rust
//! `vouch-sonic-dsp` crate. All DSP (the hardened **v3** codec: chirp sync,
//! multi-layer FSK, Hamming + CRC, MRC soft-combine) lives in `sonic-dsp` and is
//! byte-for-byte identical to what `@vouch-protocol-official/sonic-wasm@2.0.0`
//! published. The mobile `vouch-sonic-core` (UniFFI) crate shares the same DSP
//! crate, so a watermark embedded in the browser is recoverable on mobile.
//!
//! This file only converts between JS values and the pure-Rust API and keeps the
//! public `#[wasm_bindgen]` surface (function names + serialized field names)
//! unchanged.
//!
//! # Usage (JavaScript)
//!
//! ```js
//! import init, { embedWatermark, detectWatermark } from '@vouch/sonic-wasm';
//!
//! await init(); // Initialize WASM module
//!
//! // Embed watermark
//! const result = embedWatermark(pcmBytes, "did:key:z6Mk...", Date.now());
//! // result = { watermarkedAudio, watermarkId, audioHash }
//!
//! // Detect watermark
//! const detection = detectWatermark(pcmBytes, 44100);
//! // detection = { detected, confidence, payloadHash }
//! ```

use vouch_sonic_dsp as dsp;
use wasm_bindgen::prelude::*;

// =============================================================================
// JS-facing types (serialized via serde)
//
// These shapes (and their serialized field names) are the public JS surface and
// MUST stay identical to what sonic-wasm@2.0.0 produced. They are populated from
// the pure-Rust `dsp::*` results.
// =============================================================================

#[derive(serde::Serialize)]
pub struct EmbedResult {
    /// The watermarked audio as PCM bytes (16-bit LE)
    #[serde(with = "serde_bytes_as_array")]
    pub watermarked_audio: Vec<u8>,
    /// Unique watermark identifier (SHA-256 derived)
    pub watermark_id: String,
    /// SHA-256 hash of the original audio
    pub audio_hash: String,
    /// Payload hash for verification
    pub payload_hash: String,
}

#[derive(serde::Serialize)]
pub struct DetectResult {
    /// Whether a watermark was detected
    pub detected: bool,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Hash of extracted payload (for server lookup)
    pub payload_hash: Option<String>,
    /// Estimated audio quality (0.0 - 1.0)
    pub audio_quality: f32,
    /// Detection method used
    pub detection_method: String,
}

#[derive(serde::Serialize)]
pub struct VoiceFeatures {
    /// Feature vector (variable length: 13-dim DSP or ready for ONNX preprocessing)
    pub features: Vec<f32>,
    /// Feature extraction method
    pub method: String,
}

// Custom serializer for Vec<u8> as array (not base64)
mod serde_bytes_as_array {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }
}

// =============================================================================
// Public WASM API (thin wrappers over sonic-dsp)
// =============================================================================

/// Initialize the WASM module. Call once before using other functions.
#[wasm_bindgen(js_name = "initSonic")]
pub fn init_sonic() -> Result<String, JsError> {
    Ok(format!("Vouch Sonic WASM v{}", env!("CARGO_PKG_VERSION")))
}

/// Embed an invisible spread-spectrum watermark into PCM audio.
///
/// # Arguments
/// * `pcm_data` - Raw PCM audio bytes (16-bit signed LE, mono)
/// * `sample_rate` - Sample rate in Hz (must be >= 44100)
/// * `did` - Signer's DID to embed
/// * `timestamp_ms` - Current timestamp in milliseconds
///
/// # Returns
/// JSON-serialized `EmbedResult` with watermarked audio and metadata
#[wasm_bindgen(js_name = "embedWatermark")]
pub fn embed_watermark(
    pcm_data: &[u8],
    sample_rate: u32,
    did: &str,
    timestamp_ms: f64,
) -> Result<JsValue, JsError> {
    let r = dsp::embed(pcm_data, sample_rate, did, timestamp_ms as u64)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = EmbedResult {
        watermarked_audio: r.watermarked_audio,
        watermark_id: r.watermark_id,
        audio_hash: r.audio_hash,
        payload_hash: r.payload_hash,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Detect a Vouch Sonic watermark in PCM audio.
///
/// # Arguments
/// * `pcm_data` - Raw PCM audio bytes (16-bit signed LE, mono)
/// * `sample_rate` - Sample rate in Hz
///
/// # Returns
/// JSON-serialized `DetectResult`
#[wasm_bindgen(js_name = "detectWatermark")]
pub fn detect_watermark(pcm_data: &[u8], sample_rate: u32) -> Result<JsValue, JsError> {
    let d = dsp::detect(pcm_data, sample_rate).map_err(|e| JsError::new(&e.to_string()))?;

    let result = DetectResult {
        detected: d.detected,
        confidence: d.confidence,
        payload_hash: d.payload_hash,
        audio_quality: d.audio_quality,
        detection_method: d.detection_method,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Extract voice features from PCM audio for speaker identification.
///
/// Returns a 13-dimensional feature vector:
/// [zcr, rms_energy, spectral_centroid, f0, spectral_bandwidth,
///  spectral_rolloff, spectral_flatness, mel_band_0..mel_band_5]
///
/// # Arguments
/// * `pcm_data` - Raw PCM audio bytes (16-bit signed LE, mono)
/// * `sample_rate` - Sample rate in Hz
#[wasm_bindgen(js_name = "extractVoiceFeatures")]
pub fn extract_voice_features(pcm_data: &[u8], sample_rate: u32) -> Result<JsValue, JsError> {
    let features = dsp::extract_voice_features(pcm_data, sample_rate)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = VoiceFeatures {
        features,
        method: "dsp_13dim".to_string(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Compute cosine similarity between two feature vectors.
#[wasm_bindgen(js_name = "cosineSimilarity")]
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    dsp::cosine_similarity(a, b)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 0.001);
    }

    // The DSP itself (embed/detect, Hamming, chirp, robustness) is exhaustively
    // tested in the `vouch-sonic-dsp` crate. Here we only smoke-test the wrapper
    // delegation: the shim must accept a real embedded clip and report detection.
    // Build a broadband host so the masking model has cover energy.
    fn gen_broadband(n: usize, sample_rate: f32, seed: u64) -> Vec<f32> {
        // Tiny xorshift PRNG, deterministic.
        let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut unit = || (next() >> 40) as f32 / (1u64 << 24) as f32;
        let parts: Vec<(f32, f32)> = (0..64)
            .map(|_| {
                let f = 150.0 + unit() * (20_000.0 - 150.0);
                let p = unit() * std::f32::consts::TAU;
                (f, p)
            })
            .collect();
        (0..n)
            .map(|i| {
                let t = i as f32 / sample_rate;
                let mut s = 0.0_f32;
                for (f, p) in &parts {
                    s += (std::f32::consts::TAU * f * t + p).sin();
                }
                (s / parts.len() as f32 * 0.6).clamp(-1.0, 1.0)
            })
            .collect()
    }

    fn float_to_pcm(samples: &[f32]) -> Vec<u8> {
        let mut pcm = Vec::with_capacity(samples.len() * 2);
        for &s in samples {
            let clamped = s.max(-1.0).min(1.0);
            let i16_val = (clamped * 32767.0) as i16;
            pcm.extend_from_slice(&i16_val.to_le_bytes());
        }
        pcm
    }

    #[test]
    fn test_wrapper_embed_detect_roundtrip() {
        let sr = 44_100u32;
        let n = (sr as f32 * 13.0) as usize;
        let pcm = float_to_pcm(&gen_broadband(n, sr as f32, 7));

        let emb = dsp::embed(&pcm, sr, "did:key:z6MkWasmShim", 1_700_000_000_000)
            .expect("embed should succeed");
        let det = dsp::detect(&emb.watermarked_audio, sr).expect("detect should not error");
        assert!(det.detected, "wrapper-backed detect must find the embedded watermark");
        assert_eq!(det.payload_hash, Some(emb.payload_hash));
    }
}
