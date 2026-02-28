//! Vouch Sonic WASM - Browser-side audio watermark embedding and detection
//!
//! This crate provides a WASM-compatible build of the Vouch Sonic DSP engine
//! for running watermark operations entirely in the browser. No audio data
//! leaves the client - only metadata (watermarkId, hashes) is sent to the server.
//!
//! # Architecture
//!
//! Shared DSP core with the mobile `vouch-sonic-core` crate, but uses
//! `wasm-bindgen` instead of UniFFI for JavaScript interop.
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

use rustfft::{num_complex::Complex, FftPlanner};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

// =============================================================================
// Constants
// =============================================================================

/// Carrier frequency for bit=0 (Hz)
const CARRIER_FREQ_LOW: f32 = 17500.0;

/// Carrier frequency for bit=1 (Hz)
const CARRIER_FREQ_HIGH: f32 = 19500.0;

/// Duration of each bit chip in milliseconds
const CHIP_DURATION_MS: f32 = 50.0;

/// Watermark payload size in bits
const WATERMARK_BITS: usize = 128;

/// Barker-13 sync code for watermark start detection
const BARKER_13: [f32; 13] = [
    1.0, 1.0, 1.0, 1.0, 1.0, -1.0, -1.0, 1.0, 1.0, -1.0, 1.0, -1.0, 1.0,
];

/// Minimum samples needed for detection
const MIN_DETECTION_SAMPLES: usize = 2048;

/// Carrier amplitude relative to local RMS (-48 dB)
const CARRIER_DB_BELOW_RMS: f32 = -48.0;

/// Default detection confidence threshold
const DETECTION_THRESHOLD: f32 = 0.5;

// =============================================================================
// JS-facing types (serialized via serde)
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
// Public WASM API
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
    if sample_rate < 44100 {
        return Err(JsError::new("Sample rate must be >= 44100 Hz"));
    }
    if pcm_data.len() < MIN_DETECTION_SAMPLES * 2 {
        return Err(JsError::new("Audio too short for watermark embedding"));
    }

    // Generate watermark ID from DID + timestamp using SHA-256
    let watermark_id = generate_watermark_id(did, timestamp_ms as u64);
    let payload = derive_payload(&watermark_id);

    // Compute hash of original audio
    let audio_hash = sha256_hex(pcm_data);

    // Convert PCM bytes to float samples
    let samples = pcm_to_float(pcm_data);

    // Embed spread-spectrum watermark with adaptive amplitude + Barker sync
    let watermarked_samples = embed_payload(&samples, &payload, sample_rate as f32);

    // Convert back to PCM bytes
    let watermarked_pcm = float_to_pcm(&watermarked_samples);

    // Compute payload hash for server-side lookup
    let payload_hash = sha256_hex(&payload);

    let result = EmbedResult {
        watermarked_audio: watermarked_pcm,
        watermark_id,
        audio_hash,
        payload_hash,
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
    if pcm_data.len() < MIN_DETECTION_SAMPLES * 2 {
        return Err(JsError::new("Audio too short for watermark detection"));
    }

    let samples = pcm_to_float(pcm_data);
    let quality = estimate_audio_quality(&samples, sample_rate);

    // Step 1: Find Barker sync position
    let sync_pos = find_barker_sync(&samples, sample_rate as f32);

    let (detected, confidence, payload_hash, method) = if let Some(start) = sync_pos {
        // Step 2: Extract payload starting after sync
        let barker_samples =
            (BARKER_13.len() as f32 * CHIP_DURATION_MS / 1000.0 * sample_rate as f32) as usize;
        let payload_start = start + barker_samples;

        if let Some(payload) = extract_payload(&samples[payload_start..], sample_rate as f32) {
            let hash = sha256_hex(&payload);
            (true, 0.85_f32.max(confidence_from_correlation(&samples[payload_start..], &payload, sample_rate as f32)), Some(hash), "barker_sync")
        } else {
            (false, 0.0, None, "barker_sync_no_payload")
        }
    } else {
        // Fallback: try raw correlation without sync
        let (ss_detected, ss_conf) = detect_spread_spectrum(&samples, sample_rate as f32);
        if ss_detected {
            if let Some(payload) = extract_payload(&samples, sample_rate as f32) {
                let hash = sha256_hex(&payload);
                (true, ss_conf, Some(hash), "spread_spectrum")
            } else {
                (true, ss_conf * 0.5, None, "spread_spectrum_partial")
            }
        } else {
            (false, ss_conf, None, "none")
        }
    };

    let result = DetectResult {
        detected: detected && confidence > DETECTION_THRESHOLD,
        confidence,
        payload_hash,
        audio_quality: quality,
        detection_method: method.to_string(),
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
    if pcm_data.len() < 4096 {
        return Err(JsError::new("Audio too short for voice feature extraction"));
    }

    let samples = pcm_to_float(pcm_data);
    let features = compute_voice_features(&samples, sample_rate as f32);

    let result = VoiceFeatures {
        features,
        method: "dsp_13dim".to_string(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Compute cosine similarity between two feature vectors.
#[wasm_bindgen(js_name = "cosineSimilarity")]
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    dot / (norm_a.sqrt() * norm_b.sqrt() + 1e-10)
}

// =============================================================================
// Internal: Watermark ID Generation
// =============================================================================

fn generate_watermark_id(did: &str, timestamp_ms: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    hasher.update(b":");
    hasher.update(timestamp_ms.to_le_bytes());
    let hash = hasher.finalize();
    format!("sonic-{}", hex::encode(&hash[..8]))
}

fn derive_payload(watermark_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(watermark_id.as_bytes());
    let hash = hasher.finalize();
    hash[..WATERMARK_BITS / 8].to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(&hasher.finalize())
}

// Minimal hex encoding (avoid adding `hex` crate dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// =============================================================================
// Internal: PCM Conversion
// =============================================================================

fn pcm_to_float(pcm: &[u8]) -> Vec<f32> {
    pcm.chunks_exact(2)
        .map(|chunk| {
            let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
            sample as f32 / 32768.0
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

// =============================================================================
// Internal: Hann Window
// =============================================================================

fn hann_window(size: usize) -> Vec<f32> {
    (0..size)
        .map(|n| {
            0.5 * (1.0 - (2.0 * std::f32::consts::PI * n as f32 / (size - 1) as f32).cos())
        })
        .collect()
}

// =============================================================================
// Internal: Watermark Embedding (Spread-Spectrum with Barker Sync)
// =============================================================================

fn embed_payload(samples: &[f32], payload: &[u8], sample_rate: f32) -> Vec<f32> {
    let mut output = samples.to_vec();
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;

    // Compute local RMS for adaptive amplitude
    let rms = compute_rms(samples);
    let carrier_amplitude = if rms > 1e-6 {
        rms * 10.0_f32.powf(CARRIER_DB_BELOW_RMS / 20.0)
    } else {
        0.001 // Minimum amplitude for near-silent audio
    };

    let mut pos = 0;

    // Step 1: Embed Barker-13 sync preamble
    for &bit in &BARKER_13 {
        let freq = if bit > 0.0 {
            CARRIER_FREQ_HIGH
        } else {
            CARRIER_FREQ_LOW
        };
        for s in 0..samples_per_chip {
            let idx = pos + s;
            if idx >= output.len() {
                return output;
            }
            let t = s as f32 / sample_rate;
            let carrier = (2.0 * std::f32::consts::PI * freq * t).sin() * carrier_amplitude;
            output[idx] += carrier;
        }
        pos += samples_per_chip;
    }

    // Step 2: Embed payload bits
    for bit_idx in 0..WATERMARK_BITS {
        let byte_idx = bit_idx / 8;
        let bit_in_byte = bit_idx % 8;
        let bit_value = (payload[byte_idx] >> bit_in_byte) & 1;

        let freq = if bit_value == 1 {
            CARRIER_FREQ_HIGH
        } else {
            CARRIER_FREQ_LOW
        };

        for s in 0..samples_per_chip {
            let idx = pos + s;
            if idx >= output.len() {
                return output;
            }
            let t = s as f32 / sample_rate;
            let carrier = (2.0 * std::f32::consts::PI * freq * t).sin() * carrier_amplitude;
            output[idx] += carrier;
        }
        pos += samples_per_chip;
    }

    output
}

fn compute_rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f32 = samples.iter().map(|s| s * s).sum();
    (sum / samples.len() as f32).sqrt()
}

// =============================================================================
// Internal: Watermark Detection
// =============================================================================

fn find_barker_sync(samples: &[f32], sample_rate: f32) -> Option<usize> {
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let barker_total_samples = BARKER_13.len() * samples_per_chip;

    if samples.len() < barker_total_samples {
        return None;
    }

    let window = hann_window(samples_per_chip);
    let mut best_corr = 0.0_f32;
    let mut best_pos = 0_usize;

    // Slide through audio looking for Barker correlation peak
    let step = samples_per_chip / 4; // Quarter-chip resolution
    for start in (0..samples.len().saturating_sub(barker_total_samples)).step_by(step) {
        let mut correlation = 0.0_f32;

        for (i, &barker_bit) in BARKER_13.iter().enumerate() {
            let chip_start = start + i * samples_per_chip;
            let chip_end = (chip_start + samples_per_chip).min(samples.len());
            let chip = &samples[chip_start..chip_end];

            // Correlate with high and low carriers using Hann window
            let mut corr_high = 0.0_f32;
            let mut corr_low = 0.0_f32;
            for (s, &sample) in chip.iter().enumerate() {
                let w = if s < window.len() { window[s] } else { 0.0 };
                let t = s as f32 / sample_rate;
                corr_high += sample * w * (2.0 * std::f32::consts::PI * CARRIER_FREQ_HIGH * t).sin();
                corr_low += sample * w * (2.0 * std::f32::consts::PI * CARRIER_FREQ_LOW * t).sin();
            }

            // Expected: high carrier for +1, low carrier for -1
            let detected_bit = if corr_high > corr_low { 1.0 } else { -1.0 };
            correlation += detected_bit * barker_bit;
        }

        let normalized = correlation / BARKER_13.len() as f32;
        if normalized > best_corr {
            best_corr = normalized;
            best_pos = start;
        }
    }

    // Barker-13 has a peak-to-sidelobe ratio of 13:1
    if best_corr > 0.6 {
        Some(best_pos)
    } else {
        None
    }
}

fn extract_payload(samples: &[f32], sample_rate: f32) -> Option<Vec<u8>> {
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let required_samples = WATERMARK_BITS * samples_per_chip;

    if samples.len() < required_samples {
        return None;
    }

    let window = hann_window(samples_per_chip);
    let mut payload = vec![0u8; WATERMARK_BITS / 8];

    for bit_idx in 0..WATERMARK_BITS {
        let chip_start = bit_idx * samples_per_chip;
        let chip = &samples[chip_start..chip_start + samples_per_chip];

        // Correlate with both carriers using Hann window
        let mut corr_high = 0.0_f32;
        let mut corr_low = 0.0_f32;

        for (s, &sample) in chip.iter().enumerate() {
            let w = if s < window.len() { window[s] } else { 0.0 };
            let t = s as f32 / sample_rate;
            corr_high += sample * w * (2.0 * std::f32::consts::PI * CARRIER_FREQ_HIGH * t).sin();
            corr_low += sample * w * (2.0 * std::f32::consts::PI * CARRIER_FREQ_LOW * t).sin();
        }

        if corr_high > corr_low {
            let byte_idx = bit_idx / 8;
            let bit_in_byte = bit_idx % 8;
            payload[byte_idx] |= 1 << bit_in_byte;
        }
    }

    Some(payload)
}

fn detect_spread_spectrum(samples: &[f32], sample_rate: f32) -> (bool, f32) {
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    if samples.len() < samples_per_chip * 2 {
        return (false, 0.0);
    }

    // Compute energy in the carrier frequency bands using FFT
    let mut planner = FftPlanner::new();
    let fft_size = samples_per_chip.next_power_of_two();
    let fft = planner.plan_fft_forward(fft_size);

    let mut total_carrier_energy = 0.0_f32;
    let mut total_noise_energy = 0.0_f32;
    let num_frames = (samples.len() / samples_per_chip).min(20);

    let low_bin = (CARRIER_FREQ_LOW * fft_size as f32 / sample_rate) as usize;
    let high_bin = (CARRIER_FREQ_HIGH * fft_size as f32 / sample_rate) as usize;

    for frame_idx in 0..num_frames {
        let start = frame_idx * samples_per_chip;
        let end = (start + fft_size).min(samples.len());
        let frame = &samples[start..end];

        let mut buffer: Vec<Complex<f32>> = frame
            .iter()
            .map(|&s| Complex::new(s, 0.0))
            .collect();
        buffer.resize(fft_size, Complex::new(0.0, 0.0));

        fft.process(&mut buffer);

        // Energy in carrier bands (±2 bins)
        for bin in [low_bin, high_bin] {
            let range_start = bin.saturating_sub(2);
            let range_end = (bin + 3).min(fft_size / 2);
            for b in range_start..range_end {
                total_carrier_energy += buffer[b].norm_sqr();
            }
        }

        // Energy in non-carrier bands (noise floor)
        let noise_start = (low_bin.saturating_sub(50)).max(1);
        let noise_end = low_bin.saturating_sub(10);
        for b in noise_start..noise_end {
            total_noise_energy += buffer[b].norm_sqr();
        }
    }

    // Carrier-to-noise ratio indicates watermark presence
    let cnr = if total_noise_energy > 1e-10 {
        total_carrier_energy / total_noise_energy
    } else {
        0.0
    };

    let confidence = (cnr / 10.0).min(1.0);
    (confidence > DETECTION_THRESHOLD, confidence)
}

fn confidence_from_correlation(samples: &[f32], payload: &[u8], sample_rate: f32) -> f32 {
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let mut correct_bits = 0;

    for bit_idx in 0..WATERMARK_BITS.min(samples.len() / samples_per_chip) {
        let chip_start = bit_idx * samples_per_chip;
        if chip_start + samples_per_chip > samples.len() {
            break;
        }
        let chip = &samples[chip_start..chip_start + samples_per_chip];

        let mut corr_high = 0.0_f32;
        let mut corr_low = 0.0_f32;
        for (s, &sample) in chip.iter().enumerate() {
            let t = s as f32 / sample_rate;
            corr_high += sample * (2.0 * std::f32::consts::PI * CARRIER_FREQ_HIGH * t).sin();
            corr_low += sample * (2.0 * std::f32::consts::PI * CARRIER_FREQ_LOW * t).sin();
        }

        let detected_bit = if corr_high > corr_low { 1u8 } else { 0u8 };
        let expected_bit = (payload[bit_idx / 8] >> (bit_idx % 8)) & 1;
        if detected_bit == expected_bit {
            correct_bits += 1;
        }
    }

    correct_bits as f32 / WATERMARK_BITS as f32
}

// =============================================================================
// Internal: Audio Quality Estimation
// =============================================================================

fn estimate_audio_quality(samples: &[f32], sample_rate: u32) -> f32 {
    if samples.len() < 512 {
        return 0.5;
    }

    let mut planner = FftPlanner::new();
    let fft_size = 512_usize.min(samples.len()).next_power_of_two();
    let fft = planner.plan_fft_forward(fft_size);

    let mut buffer: Vec<Complex<f32>> = samples[..fft_size]
        .iter()
        .map(|&s| Complex::new(s, 0.0))
        .collect();
    fft.process(&mut buffer);

    let low_energy: f32 = buffer[..fft_size / 4].iter().map(|c| c.norm_sqr()).sum();
    let high_energy: f32 = buffer[fft_size / 4..fft_size / 2]
        .iter()
        .map(|c| c.norm_sqr())
        .sum();

    let ratio = high_energy / (low_energy + 1e-10);
    let _ = sample_rate; // Used for future bandwidth estimation
    (ratio.min(1.0) * 0.5 + 0.5).min(1.0)
}

// =============================================================================
// Internal: Voice Feature Extraction (13-dim DSP features)
// =============================================================================

fn compute_voice_features(samples: &[f32], sample_rate: f32) -> Vec<f32> {
    let frame_size = 1024_usize;
    let num_frames = (samples.len() / frame_size).min(30);

    if num_frames == 0 {
        return vec![0.0; 13];
    }

    // Feature 1: Zero-crossing rate
    let mut zero_crossings = 0;
    for i in 1..samples.len() {
        if (samples[i] >= 0.0) != (samples[i - 1] >= 0.0) {
            zero_crossings += 1;
        }
    }
    let zcr = zero_crossings as f32 / samples.len() as f32;

    // Feature 2: RMS energy
    let rms_energy = compute_rms(samples);

    // FFT-based features (averaged across frames)
    let mut planner = FftPlanner::new();
    let fft_size = frame_size.next_power_of_two();
    let fft = planner.plan_fft_forward(fft_size);
    let window = hann_window(frame_size);

    let mut total_centroid = 0.0_f32;
    let mut total_bandwidth = 0.0_f32;
    let mut total_rolloff = 0.0_f32;
    let mut total_flatness = 0.0_f32;
    let mut mel_bands = vec![0.0_f32; 6];

    for f in 0..num_frames {
        let frame_start = f * frame_size;
        let frame = &samples[frame_start..frame_start + frame_size];

        // Apply Hann window and FFT
        let mut buffer: Vec<Complex<f32>> = frame
            .iter()
            .zip(window.iter())
            .map(|(&s, &w)| Complex::new(s * w, 0.0))
            .collect();
        buffer.resize(fft_size, Complex::new(0.0, 0.0));
        fft.process(&mut buffer);

        let half = fft_size / 2;
        let magnitudes: Vec<f32> = buffer[..half].iter().map(|c| c.norm_sqr().sqrt()).collect();
        let mag_sum: f32 = magnitudes.iter().sum();

        if mag_sum < 1e-10 {
            continue;
        }

        // Spectral centroid
        let centroid: f32 = magnitudes
            .iter()
            .enumerate()
            .map(|(k, &m)| (k as f32 * sample_rate / fft_size as f32) * m)
            .sum::<f32>()
            / mag_sum;
        total_centroid += centroid;

        // Spectral bandwidth
        let bandwidth: f32 = magnitudes
            .iter()
            .enumerate()
            .map(|(k, &m)| {
                let freq = k as f32 * sample_rate / fft_size as f32;
                m * (freq - centroid).powi(2)
            })
            .sum::<f32>()
            / mag_sum;
        total_bandwidth += bandwidth.sqrt();

        // Spectral rolloff (frequency below which 85% of energy is concentrated)
        let energy_threshold = mag_sum * 0.85;
        let mut cumulative = 0.0_f32;
        let mut rolloff_bin = half - 1;
        for (k, &m) in magnitudes.iter().enumerate() {
            cumulative += m;
            if cumulative >= energy_threshold {
                rolloff_bin = k;
                break;
            }
        }
        total_rolloff += rolloff_bin as f32 * sample_rate / fft_size as f32;

        // Spectral flatness (geometric mean / arithmetic mean of spectrum)
        let log_sum: f32 = magnitudes
            .iter()
            .filter(|&&m| m > 1e-10)
            .map(|m| m.ln())
            .sum();
        let nonzero_count = magnitudes.iter().filter(|&&m| m > 1e-10).count() as f32;
        let geometric_mean = if nonzero_count > 0.0 {
            (log_sum / nonzero_count).exp()
        } else {
            0.0
        };
        let arithmetic_mean = mag_sum / half as f32;
        total_flatness += geometric_mean / (arithmetic_mean + 1e-10);

        // Mel-scale band energies (6 bands spanning 0-8000 Hz)
        let mel_boundaries = [0.0, 200.0, 500.0, 1000.0, 2000.0, 4000.0, 8000.0];
        for band in 0..6 {
            let low_bin = (mel_boundaries[band] * fft_size as f32 / sample_rate) as usize;
            let high_bin =
                ((mel_boundaries[band + 1] * fft_size as f32 / sample_rate) as usize).min(half);
            let band_energy: f32 = magnitudes[low_bin..high_bin]
                .iter()
                .map(|m| m * m)
                .sum();
            mel_bands[band] += (band_energy + 1e-10).ln();
        }
    }

    let n = num_frames as f32;

    // Feature 3: F0 estimation via autocorrelation
    let f0 = estimate_f0(samples, sample_rate);

    vec![
        zcr,                          // 0: Zero-crossing rate
        rms_energy,                   // 1: RMS energy
        total_centroid / n,           // 2: Avg spectral centroid
        f0,                           // 3: Fundamental frequency
        total_bandwidth / n,          // 4: Avg spectral bandwidth
        total_rolloff / n,            // 5: Avg spectral rolloff
        total_flatness / n,           // 6: Avg spectral flatness
        mel_bands[0] / n,            // 7: Mel band 0-200 Hz
        mel_bands[1] / n,            // 8: Mel band 200-500 Hz
        mel_bands[2] / n,            // 9: Mel band 500-1000 Hz
        mel_bands[3] / n,            // 10: Mel band 1000-2000 Hz
        mel_bands[4] / n,            // 11: Mel band 2000-4000 Hz
        mel_bands[5] / n,            // 12: Mel band 4000-8000 Hz
    ]
}

fn estimate_f0(samples: &[f32], sample_rate: f32) -> f32 {
    let min_lag = (sample_rate / 400.0) as usize; // Max F0 = 400 Hz
    let max_lag = (sample_rate / 60.0) as usize; // Min F0 = 60 Hz
    let frame_size = samples.len().min(4096);

    if frame_size < max_lag * 2 {
        return 0.0;
    }

    // Autocorrelation at lag 0 for normalization
    let r0: f32 = samples[..frame_size].iter().map(|s| s * s).sum();
    if r0 < 1e-10 {
        return 0.0;
    }

    let mut best_corr = -1.0_f32;
    let mut best_lag = min_lag;

    for lag in min_lag..max_lag.min(frame_size / 2) {
        let mut corr = 0.0_f32;
        for i in 0..frame_size - lag {
            corr += samples[i] * samples[i + lag];
        }
        // Normalize by r(0)
        let normalized = corr / r0;
        if normalized > best_corr {
            best_corr = normalized;
            best_lag = lag;
        }
    }

    if best_corr > 0.3 {
        sample_rate / best_lag as f32
    } else {
        0.0 // No clear fundamental frequency
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watermark_id_deterministic() {
        let id1 = generate_watermark_id("did:key:z6MkTest", 1000000);
        let id2 = generate_watermark_id("did:key:z6MkTest", 1000000);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("sonic-"));
    }

    #[test]
    fn test_watermark_id_unique() {
        let id1 = generate_watermark_id("did:key:z6MkTest", 1000000);
        let id2 = generate_watermark_id("did:key:z6MkTest", 1000001);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_pcm_roundtrip() {
        let samples = vec![0.5_f32, -0.5, 0.0, 1.0, -1.0];
        let pcm = float_to_pcm(&samples);
        let recovered = pcm_to_float(&pcm);
        for (a, b) in samples.iter().zip(recovered.iter()) {
            assert!((a - b).abs() < 0.001);
        }
    }

    #[test]
    fn test_embed_detect_roundtrip() {
        let sample_rate = 44100.0_f32;
        let duration_sec = 3.0;
        let num_samples = (sample_rate * duration_sec) as usize;

        // Generate test audio (440 Hz sine wave)
        let samples: Vec<f32> = (0..num_samples)
            .map(|i| (2.0 * std::f32::consts::PI * 440.0 * i as f32 / sample_rate).sin() * 0.5)
            .collect();

        let payload = derive_payload("sonic-test123");
        let watermarked = embed_payload(&samples, &payload, sample_rate);

        // Verify watermark is embedded (audio should differ)
        let diff: f32 = samples
            .iter()
            .zip(watermarked.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();
        assert!(diff > 0.0, "Watermark should modify audio");

        // Detect Barker sync
        let sync_pos = find_barker_sync(&watermarked, sample_rate);
        assert!(sync_pos.is_some(), "Should find Barker sync");

        // Extract payload after sync
        let barker_samples =
            (BARKER_13.len() as f32 * CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
        let payload_start = sync_pos.unwrap() + barker_samples;
        let extracted = extract_payload(&watermarked[payload_start..], sample_rate);
        assert!(extracted.is_some(), "Should extract payload");
        assert_eq!(extracted.unwrap(), payload, "Payload should match");
    }

    #[test]
    fn test_hann_window() {
        let window = hann_window(4);
        assert!((window[0] - 0.0).abs() < 0.01);
        assert!((window[2] - 0.0).abs() < 0.01);
        assert!(window[1] > 0.5);
    }

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

    #[test]
    fn test_voice_features_length() {
        let sample_rate = 16000.0;
        let num_samples = 32000; // 2 seconds
        let samples: Vec<f32> = (0..num_samples)
            .map(|i| (2.0 * std::f32::consts::PI * 200.0 * i as f32 / sample_rate).sin() * 0.3)
            .collect();

        let features = compute_voice_features(&samples, sample_rate);
        assert_eq!(features.len(), 13);
    }

    #[test]
    fn test_rms() {
        let silence = vec![0.0_f32; 100];
        assert!(compute_rms(&silence) < 1e-6);

        let tone: Vec<f32> = (0..1000)
            .map(|i| (2.0 * std::f32::consts::PI * i as f32 / 100.0).sin())
            .collect();
        let rms = compute_rms(&tone);
        assert!((rms - 0.707).abs() < 0.01); // RMS of sine = 1/sqrt(2)
    }
}
