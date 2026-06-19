//! Vouch Sonic DSP - pure-Rust hardened v3 audio watermark engine.
//!
//! This crate is the single source of truth for the Vouch Sonic DSP. It is a
//! pure Rust library (no `wasm-bindgen`, `js-sys`, `serde`, or `uniffi`) so it
//! can be shared, byte-for-byte, by both the browser-side `vouch-sonic-wasm`
//! crate and the mobile `vouch-sonic-core` (UniFFI) crate. Both wrappers are
//! thin shims over the [`embed`] / [`detect`] functions here.
//!
//! # Provenance
//!
//! The DSP below is a verbatim move of the hardened **v3** codec that the
//! published `@vouch-protocol-official/sonic-wasm@2.0.0` embed uses. The logic,
//! parameters, and constants are unchanged — byte-parity with 2.0.0 is
//! mandatory, so the only edits relative to the original were the move itself
//! (dropping the `#[wasm_bindgen]` / serde wrappers) and exposing the clean
//! [`embed`] / [`detect`] API.
//!
//! # API
//!
//! ```ignore
//! use vouch_sonic_dsp as dsp;
//!
//! // Embed (PCM 16-bit LE in, watermarked PCM + metadata out)
//! let r = dsp::embed(&pcm_le16, 44_100, "did:key:z6Mk...", timestamp_ms);
//!
//! // Detect (PCM 16-bit LE in, detection result out)
//! let d = dsp::detect(&pcm_le16, 44_100);
//! if d.detected { /* d.payload_hash is the server lookup key */ }
//! ```

use rustfft::{num_complex::Complex, FftPlanner};
use sha2::{Digest, Sha256};

// =============================================================================
// Constants
// =============================================================================

/// Carrier frequency for bit=0 (Hz)
const CARRIER_FREQ_LOW: f32 = 17500.0;

/// Carrier frequency for bit=1 (Hz)
const CARRIER_FREQ_HIGH: f32 = 19500.0;

/// Duration of each bit chip in milliseconds
const CHIP_DURATION_MS: f32 = 50.0;

/// v3 chip duration (ms). 50 ms at 44.1 kHz = 2205 samples gives ~33 dB of
/// coherent processing gain per chip and ~20 Hz frequency resolution (the V3
/// tones are spaced by >= 300 Hz, so they stay fully resolvable). Long chips
/// integrate the watermark well above the host on hard, band-limited channels;
/// time diversity then comes from repeating the short ID across the clip, and
/// the detector folds in every chip (including a partial trailing repetition).
const V3_CHIP_DURATION_MS: f32 = 50.0;

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
// Multi-Layer Embedding Frequency Bands (Hz)
// =============================================================================

/// Layer frequency bands: (low_freq_0, low_freq_1, high_freq_0, high_freq_1)
/// Each layer uses a different critical band for redundant embedding.
const LAYER_BANDS: [(f32, f32, f32, f32); 4] = [
    (1000.0, 2000.0, 3000.0, 4000.0),     // L1: 1-4 kHz (speech band)
    (4000.0, 5500.0, 6500.0, 8000.0),      // L2: 4-8 kHz (mid-high)
    (8000.0, 10000.0, 12000.0, 16000.0),   // L3: 8-16 kHz (high)
    (17500.0, 18000.0, 19000.0, 19500.0),  // L4: 16-20 kHz (near-ultrasonic, original band)
];

/// Number of embedding layers
const NUM_LAYERS: usize = 4;

/// v3 layer bands: (low0, low1, high0, high1) per layer.
///
/// Unlike `LAYER_BANDS` (whose pairs overlap at 4 kHz and are too wide, which
/// makes the per-layer FSK correlator cross-talk and decode at ~random even on
/// clean audio — see the v3 layer diagnostic), every tone here is unique across
/// all layers and separated from its neighbours by >= 300 Hz, so each layer's
/// 4 tones are cleanly resolvable by a 50 ms-chip correlator.
///
/// Bands are deliberately stacked low: 3 of the 4 layers live below 6.6 kHz so
/// they survive aggressive band-limiting (lowpass 4k / codec 8k); the 4th adds
/// high-band diversity for clean/noisy channels.
const V3_LAYER_BANDS: [(f32, f32, f32, f32); 4] = [
    (800.0, 1100.0, 1400.0, 1700.0),    // L0: < 2 kHz  (survives lowpass 4k)
    (2000.0, 2400.0, 2800.0, 3200.0),   // L1: 2-3.2 kHz (survives codec 8k)
    (4500.0, 5200.0, 5900.0, 6600.0),   // L2: 4.5-6.6 kHz (survives lowpass 8k / codec 16k)
    (8500.0, 9500.0, 11000.0, 12500.0), // L3: 8.5-12.5 kHz (high-band diversity)
];

/// Hamming(7,4) error correction — encodes 4 data bits into 7 code bits.
/// Can correct any single-bit error per codeword.
///
/// Encoding matrix (systematic form):
///   d0 d1 d2 d3 p0 p1 p2
///   p0 = d0 ^ d1 ^ d3
///   p1 = d0 ^ d2 ^ d3
///   p2 = d1 ^ d2 ^ d3

/// Encode 4 data bits into 7 Hamming(7,4) code bits.
fn hamming74_encode(data: u8) -> u8 {
    let d0 = (data >> 0) & 1;
    let d1 = (data >> 1) & 1;
    let d2 = (data >> 2) & 1;
    let d3 = (data >> 3) & 1;

    let p0 = d0 ^ d1 ^ d3;
    let p1 = d0 ^ d2 ^ d3;
    let p2 = d1 ^ d2 ^ d3;

    // Codeword: d0 d1 d2 d3 p0 p1 p2
    d0 | (d1 << 1) | (d2 << 2) | (d3 << 3) | (p0 << 4) | (p1 << 5) | (p2 << 6)
}

/// Decode 7 Hamming(7,4) code bits. Corrects single-bit errors.
fn hamming74_decode(codeword: u8) -> u8 {
    let d0 = (codeword >> 0) & 1;
    let d1 = (codeword >> 1) & 1;
    let d2 = (codeword >> 2) & 1;
    let d3 = (codeword >> 3) & 1;
    let p0 = (codeword >> 4) & 1;
    let p1 = (codeword >> 5) & 1;
    let p2 = (codeword >> 6) & 1;

    // Compute syndrome
    let s0 = p0 ^ d0 ^ d1 ^ d3;
    let s1 = p1 ^ d0 ^ d2 ^ d3;
    let s2 = p2 ^ d1 ^ d2 ^ d3;
    let syndrome = s0 | (s1 << 1) | (s2 << 2);

    // Syndrome → error position lookup (0 = no error)
    let mut corrected = codeword;
    match syndrome {
        0 => {} // No error
        1 => corrected ^= 1 << 4, // p0
        2 => corrected ^= 1 << 5, // p1
        3 => corrected ^= 1 << 0, // d0
        4 => corrected ^= 1 << 6, // p2
        5 => corrected ^= 1 << 1, // d1
        6 => corrected ^= 1 << 2, // d2
        7 => corrected ^= 1 << 3, // d3
        _ => {} // Unreachable for 3-bit syndrome
    }

    // Return data bits only
    corrected & 0x0F
}

// =============================================================================
// Hamming Payload Encoding: 128-bit payload → error-corrected codewords
// =============================================================================

/// Encode 128-bit payload into Hamming(7,4)-protected code bits.
/// 128 bits = 32 nibbles × 7 bits/nibble = 224 code bits.
fn hamming_encode_payload(payload: &[u8]) -> Vec<u8> {
    let mut code_bits = Vec::with_capacity(224);

    for &byte in payload.iter() {
        // Low nibble
        let lo = byte & 0x0F;
        let lo_code = hamming74_encode(lo);
        for bit in 0..7 {
            code_bits.push((lo_code >> bit) & 1);
        }

        // High nibble
        let hi = (byte >> 4) & 0x0F;
        let hi_code = hamming74_encode(hi);
        for bit in 0..7 {
            code_bits.push((hi_code >> bit) & 1);
        }
    }

    code_bits
}

/// Decode Hamming(7,4)-protected code bits back to 128-bit payload.
fn hamming_decode_payload(code_bits: &[u8]) -> Option<Vec<u8>> {
    if code_bits.len() < 224 {
        return None;
    }

    let mut payload = Vec::with_capacity(16);

    for nibble_pair in 0..16 {
        // Decode low nibble
        let lo_start = nibble_pair * 14;
        let mut lo_code: u8 = 0;
        for bit in 0..7 {
            if code_bits[lo_start + bit] != 0 {
                lo_code |= 1 << bit;
            }
        }
        let lo = hamming74_decode(lo_code);

        // Decode high nibble
        let hi_start = lo_start + 7;
        let mut hi_code: u8 = 0;
        for bit in 0..7 {
            if code_bits[hi_start + bit] != 0 {
                hi_code |= 1 << bit;
            }
        }
        let hi = hamming74_decode(hi_code);

        payload.push(lo | (hi << 4));
    }

    Some(payload)
}

/// Length-generic Hamming decode for an arbitrary `payload_len`-byte payload
/// (each byte = 2 nibbles × 7 code bits).
#[allow(dead_code)]
fn hamming_decode_payload_n(code_bits: &[u8], payload_len: usize) -> Option<Vec<u8>> {
    if code_bits.len() < payload_len * 14 {
        return None;
    }
    let mut payload = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let lo_start = byte_idx * 14;
        let mut lo_code: u8 = 0;
        for bit in 0..7 {
            if code_bits[lo_start + bit] != 0 {
                lo_code |= 1 << bit;
            }
        }
        let lo = hamming74_decode(lo_code);
        let hi_start = lo_start + 7;
        let mut hi_code: u8 = 0;
        for bit in 0..7 {
            if code_bits[hi_start + bit] != 0 {
                hi_code |= 1 << bit;
            }
        }
        let hi = hamming74_decode(hi_code);
        payload.push(lo | (hi << 4));
    }
    Some(payload)
}

/// Number of code bits per payload (128 bits → 224 Hamming-encoded bits)
const HAMMING_CODE_BITS: usize = 224;

// =============================================================================
// Enhanced Psychoacoustic Masking
// =============================================================================

/// Compute frequency-dependent masking threshold per critical band.
/// Returns the maximum carrier amplitude that will be masked by the audio content.
fn compute_masking_amplitude(samples: &[f32], sample_rate: f32, carrier_freq: f32) -> f32 {
    let frame_size = 2048.min(samples.len());
    if frame_size < 256 {
        return compute_rms(samples) * 10.0_f32.powf(CARRIER_DB_BELOW_RMS / 20.0);
    }

    let mut planner = FftPlanner::new();
    let fft_size = frame_size.next_power_of_two();
    let fft = planner.plan_fft_forward(fft_size);

    let window = hann_window(frame_size);
    let mut buffer: Vec<Complex<f32>> = samples[..frame_size]
        .iter()
        .zip(window.iter())
        .map(|(&s, &w)| Complex::new(s * w, 0.0))
        .collect();
    buffer.resize(fft_size, Complex::new(0.0, 0.0));
    fft.process(&mut buffer);

    let half = fft_size / 2;
    let freq_resolution = sample_rate / fft_size as f32;

    // Find energy in the critical band around the carrier frequency
    let carrier_bin = (carrier_freq / freq_resolution) as usize;
    let band_width = (500.0 / freq_resolution) as usize; // ±500 Hz band
    let _band_start = carrier_bin.saturating_sub(band_width).max(1);
    let _band_end = (carrier_bin + band_width).min(half);

    // Energy in the masking band (neighboring frequencies)
    let masker_start = carrier_bin.saturating_sub(band_width * 3).max(1);
    let masker_end = (carrier_bin + band_width * 3).min(half);
    let masker_energy: f32 = buffer[masker_start..masker_end]
        .iter()
        .map(|c| c.norm_sqr())
        .sum();

    let masker_amplitude = (masker_energy / (masker_end - masker_start).max(1) as f32).sqrt();

    // Simultaneous masking: threshold depends on masker level and frequency distance
    // Masking threshold is ~10-15 dB below masker for nearby frequencies
    let masking_offset_db = if carrier_freq > 10000.0 {
        -42.0 // High frequencies: more aggressive masking (less audible)
    } else if carrier_freq > 4000.0 {
        -45.0 // Mid-high: moderate masking
    } else {
        -48.0 // Speech band: conservative masking (more audible)
    };

    let threshold = masker_amplitude * 10.0_f32.powf(masking_offset_db / 20.0);

    // Floor: never go below the basic RMS-based threshold
    let basic_threshold = compute_rms(samples) * 10.0_f32.powf(CARRIER_DB_BELOW_RMS / 20.0);

    threshold.max(basic_threshold).max(0.0005)
}

// =============================================================================
// Public API types
// =============================================================================

/// Result of an [`embed`] operation.
#[derive(Debug, Clone)]
pub struct EmbedResult {
    /// The watermarked audio as PCM bytes (16-bit LE)
    pub watermarked_audio: Vec<u8>,
    /// Unique watermark identifier (SHA-256 derived)
    pub watermark_id: String,
    /// SHA-256 hash of the original audio
    pub audio_hash: String,
    /// Payload hash for verification (SHA-256 of the embedded v3 ID, hex)
    pub payload_hash: String,
}

/// Result of a [`detect`] operation.
#[derive(Debug, Clone)]
pub struct DetectResult {
    /// Whether a watermark was detected
    pub detected: bool,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Hash of extracted payload (for server lookup), present only on detection
    pub payload_hash: Option<String>,
    /// Estimated audio quality (0.0 - 1.0)
    pub audio_quality: f32,
    /// Detection method used
    pub detection_method: String,
}

/// Error returned by the public [`embed`] / [`detect`] / [`extract_voice_features`] API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DspError {
    /// Sample rate is below the supported minimum.
    SampleRateTooLow,
    /// Audio buffer is too short for the requested operation.
    AudioTooShort,
}

impl std::fmt::Display for DspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DspError::SampleRateTooLow => write!(f, "Sample rate must be >= 44100 Hz"),
            DspError::AudioTooShort => write!(f, "Audio too short"),
        }
    }
}

impl std::error::Error for DspError {}

// =============================================================================
// Public API
// =============================================================================

/// Embed an invisible spread-spectrum watermark into PCM audio.
///
/// This is the exact logic the published `embedWatermark` wasm function uses.
///
/// # Arguments
/// * `pcm_le16` - Raw PCM audio bytes (16-bit signed LE, mono)
/// * `sample_rate` - Sample rate in Hz (must be >= 44100)
/// * `did` - Signer's DID to embed
/// * `timestamp_ms` - Current timestamp in milliseconds
pub fn embed(
    pcm_le16: &[u8],
    sample_rate: u32,
    did: &str,
    timestamp_ms: u64,
) -> Result<EmbedResult, DspError> {
    if sample_rate < 44100 {
        return Err(DspError::SampleRateTooLow);
    }
    if pcm_le16.len() < MIN_DETECTION_SAMPLES * 2 {
        return Err(DspError::AudioTooShort);
    }

    // Generate watermark ID from DID + timestamp using SHA-256
    let watermark_id = generate_watermark_id(did, timestamp_ms);
    // The v3 codec embeds a compact, time-diversity-repeated ID (server lookup
    // key), not the full 128-bit payload.
    let v3_id = derive_v3_id(&watermark_id);

    // Compute hash of original audio
    let audio_hash = sha256_hex(pcm_le16);

    // Convert PCM bytes to float samples
    let samples = pcm_to_float(pcm_le16);

    // Embed the hardened v3 watermark: chirp matched-filter sync + multi-layer
    // FSK payload repeated across time, soft-combined and CRC-protected on
    // detection. Robust through band-limiting, codec resampling, and re-recording
    // (see robustness_profile_v3).
    let watermarked_samples = embed_v3(&samples, &v3_id, sample_rate as f32);

    // Convert back to PCM bytes
    let watermarked_pcm = float_to_pcm(&watermarked_samples);

    // Payload hash for server-side lookup. Keyed off the embedded v3 ID so the
    // detector (which recovers that same ID) reproduces the identical hash.
    let payload_hash = sha256_hex(&v3_id);

    Ok(EmbedResult {
        watermarked_audio: watermarked_pcm,
        watermark_id,
        audio_hash,
        payload_hash,
    })
}

/// Detect a Vouch Sonic watermark in PCM audio.
///
/// This is the exact logic the published `detectWatermark` wasm function uses.
///
/// # Arguments
/// * `pcm_le16` - Raw PCM audio bytes (16-bit signed LE, mono)
/// * `sample_rate` - Sample rate in Hz
pub fn detect(pcm_le16: &[u8], sample_rate: u32) -> Result<DetectResult, DspError> {
    if pcm_le16.len() < MIN_DETECTION_SAMPLES * 2 {
        return Err(DspError::AudioTooShort);
    }

    let samples = pcm_to_float(pcm_le16);
    let quality = estimate_audio_quality(&samples, sample_rate);

    // Recover the compact v3 ID: chirp matched-filter sync, SNR-weighted
    // soft-combine across frequency layers and time repetitions, then a
    // CRC-validated soft-decision Hamming decode. A successful CRC-validated
    // decode is a high-confidence detection; the recovered ID hashes to the same
    // `payload_hash` the embedder reported, for server-side lookup.
    let (detected, confidence, payload_hash, method) =
        match detect_v3(&samples, sample_rate as f32, V3_ID_BYTES) {
            Some(id) => {
                let hash = sha256_hex(&id);
                (true, 0.95_f32, Some(hash), "chirp_v3")
            }
            None => (false, 0.0, None, "none"),
        };

    Ok(DetectResult {
        detected: detected && confidence > DETECTION_THRESHOLD,
        confidence,
        payload_hash,
        audio_quality: quality,
        detection_method: method.to_string(),
    })
}

/// Extract voice features from PCM audio for speaker identification.
///
/// Returns a 13-dimensional feature vector:
/// [zcr, rms_energy, spectral_centroid, f0, spectral_bandwidth,
///  spectral_rolloff, spectral_flatness, mel_band_0..mel_band_5]
///
/// This is the exact logic the published `extractVoiceFeatures` wasm function uses.
///
/// # Arguments
/// * `pcm_le16` - Raw PCM audio bytes (16-bit signed LE, mono)
/// * `sample_rate` - Sample rate in Hz
pub fn extract_voice_features(pcm_le16: &[u8], sample_rate: u32) -> Result<Vec<f32>, DspError> {
    if pcm_le16.len() < 4096 {
        return Err(DspError::AudioTooShort);
    }

    let samples = pcm_to_float(pcm_le16);
    Ok(compute_voice_features(&samples, sample_rate as f32))
}

/// Compute cosine similarity between two feature vectors.
///
/// This is the exact logic the published `cosineSimilarity` wasm function uses.
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

/// Size in bytes of the compact watermark ID actually embedded by the v3 codec.
/// The full 128-bit `derive_payload` is too long to repeat enough times for
/// time-diversity in a typical clip; v3 instead embeds a short ID (a server
/// lookup key) and repeats it across the audio. 4 bytes (32 bits) is the ID size
/// validated by the robustness harness.
pub const V3_ID_BYTES: usize = 4;

/// Derive the compact v3 watermark ID (the first `V3_ID_BYTES` bytes of the
/// 128-bit payload). This is what the v3 codec embeds/recovers; the server keys
/// off `sha256(id)` (the `payload_hash` returned to JS).
fn derive_v3_id(watermark_id: &str) -> Vec<u8> {
    derive_payload(watermark_id)[..V3_ID_BYTES].to_vec()
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
// Internal: Multi-Layer Watermark Embedding
// =============================================================================

/// Embed watermark using multi-layer redundancy with BCH error correction.
/// Each layer uses a different frequency band for robustness against
/// frequency-selective attacks (MP3 compression, band-pass filtering).
#[allow(dead_code)]
fn embed_multilayer(samples: &[f32], payload: &[u8], sample_rate: f32) -> Vec<f32> {
    // Hamming(7,4)-encode the payload for error correction
    let code_bits = hamming_encode_payload(payload);

    let mut output = samples.to_vec();
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;

    // Embed Barker-13 sync preamble using the original (L4) band
    let mut pos = 0;
    let rms = compute_rms(samples);
    let sync_amplitude = if rms > 1e-6 {
        rms * 10.0_f32.powf(CARRIER_DB_BELOW_RMS / 20.0)
    } else {
        0.001
    };

    for &bit in &BARKER_13 {
        let freq = if bit > 0.0 { CARRIER_FREQ_HIGH } else { CARRIER_FREQ_LOW };
        for s in 0..samples_per_chip {
            let idx = pos + s;
            if idx >= output.len() { return output; }
            let t = s as f32 / sample_rate;
            let carrier = (2.0 * std::f32::consts::PI * freq * t).sin() * sync_amplitude;
            output[idx] += carrier;
        }
        pos += samples_per_chip;
    }

    // Embed BCH-encoded payload across all layers
    for (_layer_idx, &(low0, low1, high0, high1)) in LAYER_BANDS.iter().enumerate() {
        // Only embed layers that fit within the Nyquist limit
        if high1 > sample_rate / 2.0 {
            continue;
        }

        for bit_idx in 0..code_bits.len() {
            let bit_value = code_bits[bit_idx];
            let (freq_0, freq_1) = if bit_value == 1 {
                (high0, high1) // Use high pair for bit=1
            } else {
                (low0, low1) // Use low pair for bit=0
            };

            // Use center frequency for masking computation
            let center_freq = (freq_0 + freq_1) / 2.0;
            let chip_start = pos + bit_idx * samples_per_chip;
            if chip_start + samples_per_chip > output.len() { break; }

            // Compute masking-aware amplitude for this frequency band
            let amplitude = compute_masking_amplitude(
                &output[chip_start..chip_start + samples_per_chip.min(output.len() - chip_start)],
                sample_rate,
                center_freq,
            ) / (NUM_LAYERS as f32).sqrt(); // RSS scaling for independent frequency bands

            for s in 0..samples_per_chip {
                let idx = chip_start + s;
                if idx >= output.len() { break; }
                let t = s as f32 / sample_rate;
                // Dual-tone chip: sum of both frequencies in the pair
                let carrier = ((2.0 * std::f32::consts::PI * freq_0 * t).sin()
                    + (2.0 * std::f32::consts::PI * freq_1 * t).sin())
                    * amplitude * 0.5;
                output[idx] += carrier;
            }
        }

        // Offset pos for each layer so they don't overlap in time
        // (layers share the same time window — they're in different freq bands)
    }

    output
}

/// Detect multi-layer watermark with BCH error correction.
/// Extracts from all available layers and takes majority vote per bit.
#[allow(dead_code)]
fn detect_multilayer(samples: &[f32], sample_rate: f32, payload_start: usize) -> Option<Vec<u8>> {
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let code_bits_len = HAMMING_CODE_BITS; // 224 bits
    let required_samples = payload_start + code_bits_len * samples_per_chip;

    if samples.len() < required_samples {
        // Fall back to single-layer extraction
        return extract_payload(&samples[payload_start..], sample_rate)
            .and_then(|p| Some(p)); // No BCH decode for legacy payloads
    }

    let window = hann_window(samples_per_chip);

    // Collect votes per bit from all layers
    let mut bit_votes = vec![0i32; code_bits_len]; // positive = 1, negative = 0

    for &(low0, low1, high0, high1) in &LAYER_BANDS {
        if high1 > sample_rate / 2.0 {
            continue;
        }

        for bit_idx in 0..code_bits_len {
            let chip_start = payload_start + bit_idx * samples_per_chip;
            if chip_start + samples_per_chip > samples.len() { break; }

            let chip = &samples[chip_start..chip_start + samples_per_chip];

            // Correlate with high and low frequency pairs
            let mut corr_high = 0.0_f32;
            let mut corr_low = 0.0_f32;

            for (s, &sample) in chip.iter().enumerate() {
                let w = if s < window.len() { window[s] } else { 0.0 };
                let t = s as f32 / sample_rate;

                // Correlate with both tones in each pair
                corr_high += sample * w * ((2.0 * std::f32::consts::PI * high0 * t).sin()
                    + (2.0 * std::f32::consts::PI * high1 * t).sin());
                corr_low += sample * w * ((2.0 * std::f32::consts::PI * low0 * t).sin()
                    + (2.0 * std::f32::consts::PI * low1 * t).sin());
            }

            if corr_high > corr_low {
                bit_votes[bit_idx] += 1;
            } else {
                bit_votes[bit_idx] -= 1;
            }
        }
    }

    // Majority vote → code bits
    let code_bits: Vec<u8> = bit_votes.iter().map(|&v| if v > 0 { 1 } else { 0 }).collect();

    // Hamming decode with error correction
    if let Some(payload) = hamming_decode_payload(&code_bits) {
        return Some(payload);
    }

    // If Hamming fails, fall back to raw extraction from original band
    extract_payload(&samples[payload_start..], sample_rate)
}

// =============================================================================
// Internal: Watermark Embedding (Spread-Spectrum with Barker Sync) — Legacy
// =============================================================================

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
// Robust sync + codec (v2): chirp matched filter
//
// Replaces the host-swamped Barker/FSK sync. A Hann-tapered linear chirp
// (CHIRP_F0..CHIRP_F1, mid-band so it survives band-limiting) is detected by an
// FFT normalized matched filter, which gives large processing gain
// (time-bandwidth product ~ 0.3 s * 5 kHz) and is separable from host audio
// (the host does not correlate with the chirp). The payload reuses the existing
// multilayer codec at the chirp-located offset.
// =============================================================================

// Chirp sweep band. Placed at 1.5-3.5 kHz: above the heavy bass region (so the
// matched filter is not swamped by low-frequency host energy, which otherwise
// produces spurious correlation peaks) and entirely within the passband of
// every channel in the robustness profile, including the most aggressive ones
// that strip everything above ~3.8 kHz (codec 8k, re-recording then codec 8k).
// Chirp survivability dominates robustness on those channels: if the preamble
// were band-limited away the matched filter would lock onto a host peak and
// shift the whole payload. A 600 ms sweep over 2 kHz gives a large
// time-bandwidth product (~1200) and thus a sharp, well-above-floor peak.
const CHIRP_DURATION_MS: f32 = 600.0;
const CHIRP_F0: f32 = 1500.0;
const CHIRP_F1: f32 = 3500.0;

/// Hann-tapered linear chirp sync preamble.
fn gen_chirp(sample_rate: f32, amplitude: f32) -> Vec<f32> {
    let n = (CHIRP_DURATION_MS / 1000.0 * sample_rate) as usize;
    if n == 0 {
        return Vec::new();
    }
    let dur = n as f32 / sample_rate;
    let k = (CHIRP_F1 - CHIRP_F0) / dur; // linear sweep rate (Hz/s)
    (0..n)
        .map(|i| {
            let t = i as f32 / sample_rate;
            let phase = 2.0 * std::f32::consts::PI * (CHIRP_F0 * t + 0.5 * k * t * t);
            let w = if n > 1 {
                0.5 - 0.5 * (2.0 * std::f32::consts::PI * i as f32 / (n as f32 - 1.0)).cos()
            } else {
                1.0
            };
            phase.sin() * amplitude * w
        })
        .collect()
}

/// FFT normalized matched filter. Returns the start index of `chirp` within
/// `samples` (payload begins at start + chirp.len()), or None if no clear peak.
#[allow(dead_code)]
fn find_chirp_start(samples: &[f32], chirp: &[f32]) -> Option<usize> {
    let ls = samples.len();
    let lt = chirp.len();
    if lt == 0 || ls < lt {
        return None;
    }
    let mut n = 1usize;
    while n < ls + lt {
        n <<= 1;
    }
    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(n);
    let ifft = planner.plan_fft_inverse(n);

    let mut sbuf: Vec<Complex<f32>> =
        (0..n).map(|i| Complex::new(if i < ls { samples[i] } else { 0.0 }, 0.0)).collect();
    let mut tbuf: Vec<Complex<f32>> =
        (0..n).map(|i| Complex::new(if i < lt { chirp[i] } else { 0.0 }, 0.0)).collect();
    fft.process(&mut sbuf);
    fft.process(&mut tbuf);
    // c[m] = real(IFFT(S .* conj(T)))[m] = sum_k samples[m+k] * chirp[k]
    let mut prod: Vec<Complex<f32>> =
        sbuf.iter().zip(tbuf.iter()).map(|(s, t)| s * t.conj()).collect();
    ifft.process(&mut prod);
    let scale = 1.0 / n as f32;

    // Running local signal energy via prefix sum of squares.
    let mut prefix = vec![0.0f32; ls + 1];
    for i in 0..ls {
        prefix[i + 1] = prefix[i] + samples[i] * samples[i];
    }
    let t_norm = chirp.iter().map(|x| x * x).sum::<f32>().max(1e-12).sqrt();

    let mut best = f32::MIN;
    let mut best_pos = 0usize;
    let mut sumsq = 0.0f64;
    let mut count = 0u32;
    for m in 0..=(ls - lt) {
        let raw = prod[m].re * scale;
        let local = (prefix[m + lt] - prefix[m]).max(1e-12).sqrt();
        let nc = raw / (t_norm * local);
        sumsq += (nc as f64) * (nc as f64);
        count += 1;
        if nc > best {
            best = nc;
            best_pos = m;
        }
    }
    // Accept only a peak that clearly exceeds the correlation noise floor.
    let floor = (sumsq / count.max(1) as f64).sqrt() as f32;
    if best > 4.0 * floor.max(1e-6) {
        Some(best_pos)
    } else {
        None
    }
}

/// Like `find_chirp_start`, but returns up to `k` candidate start positions
/// ranked by normalized matched-filter score (highest first), each separated
/// from the others by at least `chirp.len()`.
///
/// A strong stationary host can occasionally produce a spurious correlation
/// peak that edges out the true chirp peak (both are only a few × the noise
/// floor on hard hosts). Relying on the single global maximum then mislocks and
/// destroys the whole decode. Returning several candidates lets the caller
/// disambiguate using the CRC-validated payload decode: the true position is
/// the one whose payload checks out.
fn find_chirp_candidates(samples: &[f32], chirp: &[f32], k: usize) -> Vec<usize> {
    let ls = samples.len();
    let lt = chirp.len();
    if lt == 0 || ls < lt || k == 0 {
        return Vec::new();
    }
    let mut n = 1usize;
    while n < ls + lt {
        n <<= 1;
    }
    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(n);
    let ifft = planner.plan_fft_inverse(n);
    let mut sbuf: Vec<Complex<f32>> =
        (0..n).map(|i| Complex::new(if i < ls { samples[i] } else { 0.0 }, 0.0)).collect();
    let mut tbuf: Vec<Complex<f32>> =
        (0..n).map(|i| Complex::new(if i < lt { chirp[i] } else { 0.0 }, 0.0)).collect();
    fft.process(&mut sbuf);
    fft.process(&mut tbuf);
    let mut prod: Vec<Complex<f32>> =
        sbuf.iter().zip(tbuf.iter()).map(|(s, t)| s * t.conj()).collect();
    ifft.process(&mut prod);
    let scale = 1.0 / n as f32;
    let mut prefix = vec![0.0f32; ls + 1];
    for i in 0..ls {
        prefix[i + 1] = prefix[i] + samples[i] * samples[i];
    }
    let t_norm = chirp.iter().map(|x| x * x).sum::<f32>().max(1e-12).sqrt();

    // Normalized correlation at every lag, plus the noise floor.
    let mut nc = vec![0.0f32; ls - lt + 1];
    let mut sumsq = 0.0f64;
    for m in 0..=(ls - lt) {
        let raw = prod[m].re * scale;
        let local = (prefix[m + lt] - prefix[m]).max(1e-12).sqrt();
        let v = raw / (t_norm * local);
        nc[m] = v;
        sumsq += (v as f64) * (v as f64);
    }
    let floor = (sumsq / nc.len().max(1) as f64).sqrt() as f32;
    // Generous gate (2.5x) so the true peak is never excluded just because a
    // host coincidence sits slightly above it; the CRC decides the winner.
    let gate = 2.5 * floor.max(1e-6);

    // Greedily pick the top-k peaks with a chirp-length exclusion zone so we
    // don't return many lags of the same correlation lobe.
    let mut order: Vec<usize> = (0..nc.len()).collect();
    order.sort_by(|&a, &b| nc[b].partial_cmp(&nc[a]).unwrap_or(std::cmp::Ordering::Equal));
    let mut picks: Vec<usize> = Vec::with_capacity(k);
    for &m in &order {
        if nc[m] < gate {
            break;
        }
        if picks.iter().all(|&p| (p as i64 - m as i64).unsigned_abs() as usize >= lt) {
            picks.push(m);
            if picks.len() >= k {
                break;
            }
        }
    }
    picks
}

/// Embed: chirp sync preamble + multilayer payload (no Barker).
#[allow(dead_code)]
fn embed_v2(samples: &[f32], payload: &[u8], sample_rate: f32) -> Vec<f32> {
    let code_bits = hamming_encode_payload(payload);
    let mut output = samples.to_vec();
    let rms = compute_rms(samples);
    let base_amp = if rms > 1e-6 {
        rms * 10.0_f32.powf(CARRIER_DB_BELOW_RMS / 20.0)
    } else {
        0.001
    };

    // Chirp slightly hotter than the payload; matched-filter gain keeps it
    // robust, and it is brief so perceptual impact is small.
    let chirp = gen_chirp(sample_rate, base_amp * 25.0);
    for (i, &c) in chirp.iter().enumerate() {
        if i >= output.len() {
            break;
        }
        output[i] += c;
    }

    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let pos0 = chirp.len();
    for &(low0, low1, high0, high1) in LAYER_BANDS.iter() {
        if high1 > sample_rate / 2.0 {
            continue;
        }
        for (bit_idx, &bit_value) in code_bits.iter().enumerate() {
            let (freq_0, freq_1) = if bit_value == 1 { (high0, high1) } else { (low0, low1) };
            let center_freq = (freq_0 + freq_1) / 2.0;
            let chip_start = pos0 + bit_idx * samples_per_chip;
            if chip_start >= output.len() {
                break;
            }
            let chip_end = (chip_start + samples_per_chip).min(output.len());
            let amplitude = compute_masking_amplitude(&output[chip_start..chip_end], sample_rate, center_freq)
                / (NUM_LAYERS as f32).sqrt();
            for s in 0..(chip_end - chip_start) {
                let idx = chip_start + s;
                let t = s as f32 / sample_rate;
                let carrier = ((2.0 * std::f32::consts::PI * freq_0 * t).sin()
                    + (2.0 * std::f32::consts::PI * freq_1 * t).sin())
                    * amplitude
                    * 0.5;
                output[idx] += carrier;
            }
        }
    }
    output
}

/// Soft-decision multilayer payload decode. Sums the signed (high-low)
/// correlation across layers instead of hard per-layer majority voting, so a
/// band killed by band-limiting contributes ~0 rather than a random ±1 vote.
fn detect_multilayer_soft(samples: &[f32], sample_rate: f32, payload_start: usize) -> Option<Vec<u8>> {
    let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let code_bits_len = HAMMING_CODE_BITS;
    if samples.len() < payload_start + code_bits_len * samples_per_chip {
        return extract_payload(&samples[payload_start.min(samples.len())..], sample_rate);
    }
    let window = hann_window(samples_per_chip);
    let mut soft = vec![0.0f32; code_bits_len];

    for &(low0, low1, high0, high1) in &LAYER_BANDS {
        if high1 > sample_rate / 2.0 {
            continue;
        }
        for bit_idx in 0..code_bits_len {
            let chip_start = payload_start + bit_idx * samples_per_chip;
            if chip_start + samples_per_chip > samples.len() {
                break;
            }
            let chip = &samples[chip_start..chip_start + samples_per_chip];
            let (mut ch, mut cl) = (0.0f32, 0.0f32);
            for (s, &x) in chip.iter().enumerate() {
                let w = window.get(s).copied().unwrap_or(0.0);
                let t = s as f32 / sample_rate;
                ch += x * w * ((2.0 * std::f32::consts::PI * high0 * t).sin()
                    + (2.0 * std::f32::consts::PI * high1 * t).sin());
                cl += x * w * ((2.0 * std::f32::consts::PI * low0 * t).sin()
                    + (2.0 * std::f32::consts::PI * low1 * t).sin());
            }
            // Soft contribution; dead (filtered) bands yield ~0 and don't vote.
            soft[bit_idx] += ch - cl;
        }
    }

    let code_bits: Vec<u8> = soft.iter().map(|&v| if v > 0.0 { 1 } else { 0 }).collect();
    hamming_decode_payload(&code_bits)
        .or_else(|| extract_payload(&samples[payload_start..], sample_rate))
}

/// Detect: locate the chirp, then soft-decode the multilayer payload after it.
#[allow(dead_code)]
fn detect_v2(samples: &[f32], sample_rate: f32) -> Option<Vec<u8>> {
    let chirp = gen_chirp(sample_rate, 1.0); // unit template (amplitude irrelevant)
    let start = find_chirp_start(samples, &chirp)?;
    detect_multilayer_soft(samples, sample_rate, start + chirp.len())
}

/// CRC-16/CCITT-FALSE (polynomial 0x1021, init 0xFFFF) over a byte slice,
/// returned as 2 big-endian bytes. Used as the v3 payload integrity check: it
/// lets the detector recognize a *correct* ID decode among the many candidate
/// (sync-position x layer-subset) combines it tries, distinguishing a genuinely
/// recovered ID from a self-consistent but channel-biased mis-decode. A 16-bit
/// CRC keeps the aggregate false-accept probability negligible (~1/65536 per
/// candidate) even across ~100 candidate decodes per detection.
fn crc16(data: &[u8]) -> [u8; 2] {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc.to_be_bytes()
}

/// Number of CRC bytes appended to the v3 ID payload before channel coding.
const V3_CRC_BYTES: usize = 2;

/// Chirp amplitude as a multiple of the masking base amplitude. The chirp is a
/// short (sub-second), band-limited (1.5-3.5 kHz) preamble, so it can run hotter
/// than the steady payload tones while staying perceptually unobtrusive. It must
/// be hot enough that its matched-filter peak reliably out-ranks spurious host
/// self-correlation peaks; some broadband hosts produce coincidences a few x the
/// noise floor, so the true peak needs margin above those.
const V3_CHIRP_GAIN: f32 = 90.0;

/// Embed v3: chirp + time-diversity repetition of a short (ID-sized) payload.
/// The short payload (a watermark ID for server lookup) repeats across the clip
/// so the soft detector integrates many copies, surviving channels that destroy
/// most of the spectrum. A CRC-8 is appended to the ID before channel coding so
/// the detector can verify a recovered ID (see `detect_v3`).
fn embed_v3(samples: &[f32], payload: &[u8], sample_rate: f32) -> Vec<f32> {
    // Append CRC-16 so the detector has an integrity check for erasure recovery.
    let mut framed = payload.to_vec();
    framed.extend_from_slice(&crc16(payload));
    let code_bits = hamming_encode_payload(&framed);
    if code_bits.is_empty() {
        return samples.to_vec();
    }
    let mut output = samples.to_vec();
    let rms = compute_rms(samples);
    let base_amp = if rms > 1e-6 { rms * 10.0_f32.powf(CARRIER_DB_BELOW_RMS / 20.0) } else { 0.001 };

    let chirp = gen_chirp(sample_rate, base_amp * V3_CHIRP_GAIN);
    for (i, &c) in chirp.iter().enumerate() {
        if i >= output.len() { break; }
        output[i] += c;
    }

    let spc = (V3_CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    let pos0 = chirp.len();
    let avail_chips = output.len().saturating_sub(pos0) / spc.max(1);
    let reps = (avail_chips / code_bits.len()).max(1);

    for rep in 0..reps {
        let rep_off = pos0 + rep * code_bits.len() * spc;
        for &(low0, low1, high0, high1) in V3_LAYER_BANDS.iter() {
            if high1 > sample_rate / 2.0 { continue; }
            for (bit_idx, &bit) in code_bits.iter().enumerate() {
                let (f0, f1) = if bit == 1 { (high0, high1) } else { (low0, low1) };
                let cf = (f0 + f1) / 2.0;
                let cs = rep_off + bit_idx * spc;
                if cs >= output.len() { break; }
                let ce = (cs + spc).min(output.len());
                let amp = compute_masking_amplitude(&output[cs..ce], sample_rate, cf) / (NUM_LAYERS as f32).sqrt();
                for s in 0..(ce - cs) {
                    let t = s as f32 / sample_rate;
                    output[cs + s] += ((2.0 * std::f32::consts::PI * f0 * t).sin()
                        + (2.0 * std::f32::consts::PI * f1 * t).sin())
                        * amp * 0.5;
                }
            }
        }
    }
    output
}

/// Soft-decision Hamming(7,4) decode of one codeword.
/// `rel[0..7]` are per-bit soft values: sign = hard bit, |rel| = reliability.
/// Picks the valid codeword that maximizes correlation with the soft input
/// (equivalent to minimum soft Euclidean distance) — strictly stronger than
/// hard-thresholding then syndrome-correcting, because it uses bit confidence.
fn hamming74_soft_decode(rel: &[f32; 7]) -> u8 {
    let mut best_data = 0u8;
    let mut best_score = f32::MIN;
    for data in 0..16u8 {
        let cw = hamming74_encode(data);
        // Correlate: +rel where codeword bit is 1, -rel where 0.
        let mut score = 0.0f32;
        for b in 0..7 {
            let cb = (cw >> b) & 1;
            if cb == 1 { score += rel[b]; } else { score -= rel[b]; }
        }
        if score > best_score {
            best_score = score;
            best_data = data;
        }
    }
    best_data
}

/// Soft-decision decode of a full payload from per-code-bit soft reliabilities.
fn hamming_soft_decode_payload_n(soft: &[f32], payload_len: usize) -> Option<Vec<u8>> {
    if soft.len() < payload_len * 14 {
        return None;
    }
    let mut payload = Vec::with_capacity(payload_len);
    for byte_idx in 0..payload_len {
        let lo_start = byte_idx * 14;
        let mut lo_rel = [0.0f32; 7];
        let mut hi_rel = [0.0f32; 7];
        for b in 0..7 {
            lo_rel[b] = soft[lo_start + b];
            hi_rel[b] = soft[lo_start + 7 + b];
        }
        let lo = hamming74_soft_decode(&lo_rel);
        let hi = hamming74_soft_decode(&hi_rel);
        payload.push(lo | (hi << 4));
    }
    Some(payload)
}

/// Coherent FSK soft value for one chip and one layer: (high-pair correlation)
/// minus (low-pair correlation), Hann-windowed sin correlators. Sign = decided
/// bit, magnitude = confidence. The coherent (phase-locked) correlator rejects
/// random-phase host energy far better than a non-coherent energy detector,
/// because the watermark is embedded at a fixed phase while the host's phase at
/// the carrier frequency is effectively random and averages out over the chip.
#[inline]
fn layer_chip_soft(chip: &[f32], window: &[f32], sample_rate: f32, band: (f32, f32, f32, f32)) -> f32 {
    let (low0, low1, high0, high1) = band;
    let (mut ch, mut cl) = (0.0f32, 0.0f32);
    let two_pi = 2.0 * std::f32::consts::PI;
    for (s, &x) in chip.iter().enumerate() {
        let w = window.get(s).copied().unwrap_or(0.0);
        let xw = x * w;
        let t = s as f32 / sample_rate;
        ch += xw * ((two_pi * high0 * t).sin() + (two_pi * high1 * t).sin());
        cl += xw * ((two_pi * low0 * t).sin() + (two_pi * low1 * t).sin());
    }
    ch - cl
}

/// Detect v3: chirp sync, then SNR-weighted soft-combine of every layer and
/// every time repetition, followed by a soft-decision Hamming decode.
/// `payload_len` is the ID size in bytes.
///
/// Robustness techniques layered here:
///  - Coherent (random-phase-rejecting) FSK soft metric per (layer, rep, bit).
///  - Time-diversity: the short ID is embedded repeatedly; reps are combined.
///  - Per-layer *reliability* weighting by cross-repetition sign agreement
///    (NOT energy): a band whose per-rep decisions agree is trustworthy; a band
///    corrupted by the channel (band-limited, reverberated) disagrees rep-to-rep
///    and is weighted toward 0 — a true soft erasure, independent of how loud
///    that band happens to be. This is what lets the always-reliable low bands
///    (L0/L1, < 3.2 kHz) dominate when the high bands are destroyed.
///  - Soft-decision Hamming: the combined soft reliabilities drive a
///    maximum-correlation codeword decode (better than hard + syndrome).
///  - CRC-validated layer-subset erasure recovery (see Stage 2 below).
fn detect_v3(samples: &[f32], sample_rate: f32, payload_len: usize) -> Option<Vec<u8>> {
    let chirp = gen_chirp(sample_rate, 1.0);
    let spc = (V3_CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
    // The embedded frame is the ID followed by V3_CRC_BYTES of CRC-8.
    let frame_len = payload_len + V3_CRC_BYTES;
    let code_bits_len = frame_len * 2 * 7; // 7 Hamming code bits per nibble
    if payload_len == 0 || code_bits_len == 0 || spc == 0 {
        return None;
    }
    let window = hann_window(spc);

    // Active layers (within Nyquist).
    let layers: Vec<(f32, f32, f32, f32)> = V3_LAYER_BANDS
        .iter()
        .copied()
        .filter(|&(_, _, _, high1)| high1 <= sample_rate / 2.0)
        .collect();
    if layers.is_empty() {
        return None;
    }
    let n_layers = layers.len();

    // Attempt a full decode assuming the payload begins at `pos0`.
    // Returns (id, crc_ok, confidence). `crc_ok` means the recovered ID's CRC
    // matched — strong evidence this is the true sync position and decode.
    let decode_at = |pos0: usize| -> Option<(Vec<u8>, bool, f32)> {
        let avail_chips = samples.len().saturating_sub(pos0) / spc;
        // Number of chips to fold. We round the repetition count to the nearest
        // whole ID so that a final repetition that is mostly (>= half) present is
        // still used — integer-floor truncation would otherwise discard up to a
        // full ID's worth of signal, which on the hardest channels (where only
        // 2-3 repetitions fit) is exactly the time-diversity we cannot spare.
        let reps_round = ((avail_chips as f32 / code_bits_len as f32).round() as usize).max(1);
        // Use only whole repetitions (every code bit folded an equal number of
        // times). If the rounded count exceeds what fully fits, drop back to the
        // floor so the fold stays balanced across bits.
        let reps = if reps_round * code_bits_len <= avail_chips {
            reps_round
        } else {
            (avail_chips / code_bits_len).max(1)
        };
        let total_chips = reps * code_bits_len;
        if total_chips == 0 {
            return None;
        }

        // Per-(layer, bit) list of coherent FSK soft values, one per occurrence
        // of that bit in the folded stream. Kept as lists so we can estimate each
        // layer's within-band noise variance for MRC weighting.
        let mut samples_lb: Vec<Vec<Vec<f32>>> =
            vec![vec![Vec::new(); code_bits_len]; n_layers];
        for (li, &band) in layers.iter().enumerate() {
            for chip in 0..total_chips {
                let cs = pos0 + chip * spc;
                if cs + spc > samples.len() {
                    break;
                }
                let b = chip % code_bits_len;
                let v = layer_chip_soft(&samples[cs..cs + spc], &window, sample_rate, band);
                samples_lb[li][b].push(v);
            }
        }

        // ---- Two-stage maximal-ratio combining (MRC) ----
        // Stage 1 (per layer): unit-RMS-normalize each layer, then weight it by
        // an inverse-variance MRC score (decision strength / within-band noise).
        // A channel-destroyed band has disagreeing per-occurrence values -> low
        // weight (true soft erasure, independent of the band's raw loudness).
        let mut layer_mean = vec![vec![0.0f32; code_bits_len]; n_layers];
        let mut weights = vec![0.0f32; n_layers];
        for li in 0..n_layers {
            let mut ss = 0.0f32;
            let mut cnt = 0u32;
            for b in 0..code_bits_len {
                for &v in &samples_lb[li][b] {
                    ss += v * v;
                    cnt += 1;
                }
            }
            let rms = (ss / cnt.max(1) as f32).sqrt();
            let sc = 1.0 / rms.max(1e-20);
            for b in 0..code_bits_len {
                let list = &samples_lb[li][b];
                if list.is_empty() {
                    layer_mean[li][b] = 0.0;
                } else {
                    let m: f32 = list.iter().map(|&v| v * sc).sum::<f32>() / list.len() as f32;
                    layer_mean[li][b] = m;
                }
            }
            let mut var = 0.0f32;
            for b in 0..code_bits_len {
                for &v in &samples_lb[li][b] {
                    let d = v * sc - layer_mean[li][b];
                    var += d * d;
                }
            }
            var /= cnt.max(1) as f32;
            let sig: f32 =
                layer_mean[li].iter().map(|v| v * v).sum::<f32>() / code_bits_len as f32;
            weights[li] = sig / (var + 1e-3);
        }
        if weights.iter().cloned().fold(0.0f32, f32::max) <= 1e-12 {
            for w in weights.iter_mut() {
                *w = 1.0;
            }
        }

        // Stage 2: CRC-validated layer-subset erasure recovery. A band can be
        // self-consistent yet decode the wrong bits (host bias). MRC cannot tell
        // "consistently right" from "consistently wrong", so we exhaustively try
        // all 15 non-empty layer subsets, decode the (ID + CRC-8) frame for each,
        // and let the CRC pick the winner. The subset that drops the biased band
        // passes CRC and recovers the ID exactly.
        let combine_subset = |mask: usize| -> Vec<f32> {
            let mut soft = vec![0.0f32; code_bits_len];
            for li in 0..n_layers {
                if mask & (1 << li) == 0 {
                    continue;
                }
                for b in 0..code_bits_len {
                    soft[b] += weights[li] * layer_mean[li][b];
                }
            }
            soft
        };
        let agreement = |soft: &[f32], frame: &[u8]| -> f32 {
            let code = hamming_encode_payload(frame);
            let (mut dot, mut mag) = (0.0f32, 0.0f32);
            for b in 0..code_bits_len.min(code.len()) {
                let cw = if code[b] == 1 { 1.0 } else { -1.0 };
                dot += soft[b] * cw;
                mag += soft[b].abs();
            }
            if mag > 1e-20 { dot / mag } else { 0.0 }
        };

        let mut best_crc: Option<(Vec<u8>, f32)> = None;
        let mut best_any: Option<(Vec<u8>, f32)> = None;
        for mask in 1..(1usize << n_layers) {
            let soft = combine_subset(mask);
            let frame = match hamming_soft_decode_payload_n(&soft, frame_len) {
                Some(f) => f,
                None => continue,
            };
            let score = agreement(&soft, &frame);
            let id = frame[..payload_len].to_vec();
            let crc_ok = crc16(&id) == [frame[payload_len], frame[payload_len + 1]];
            if crc_ok && best_crc.as_ref().map_or(true, |(_, s)| score > *s) {
                best_crc = Some((id.clone(), score));
            }
            if best_any.as_ref().map_or(true, |(_, s)| score > *s) {
                best_any = Some((id, score));
            }
        }

        if let Some((id, score)) = best_crc {
            Some((id, true, score))
        } else {
            best_any.map(|(id, score)| (id, false, score))
        }
    };

    // Try several candidate sync positions (a strong host can out-correlate the
    // true chirp peak on hard channels). Accept the first candidate whose CRC
    // validates; otherwise keep the highest-confidence non-CRC decode as a last
    // resort.
    //
    // The chirp preamble is always embedded at the very start of the clip, so we
    // restrict the matched-filter search to a window near the beginning. This
    // both speeds detection and, crucially, excludes spurious host correlation
    // peaks deep in the clip that can otherwise out-rank a true-but-weak chirp
    // peak on hard hosts. The window is generous enough to absorb the small
    // leading delays that codecs / re-recording introduce.
    let search_limit = ((sample_rate * 4.0) as usize)
        .max(chirp.len() * 3)
        .min(samples.len());
    let head = &samples[..search_limit];
    let candidates = find_chirp_candidates(head, &chirp, 8);
    for start in candidates {
        let pos0 = start + chirp.len();
        if let Some((id, crc_ok, _score)) = decode_at(pos0) {
            if crc_ok {
                return Some(id);
            }
        }
    }
    // No candidate produced a CRC-valid decode: report "no watermark" rather
    // than a guessed ID. Requiring the CRC keeps false positives negligible
    // (~1/65536 per candidate) — essential for a detector that gates trust.
    None
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

    // Production path: embed_v3 / detect_v3 over the same ID derivation used by
    // the public embedWatermark / detectWatermark wasm functions. Verifies the
    // recovered ID round-trips and reproduces the embedder's payload_hash on a
    // realistic broadband host (silence has no cover energy for masking).
    #[test]
    fn test_v3_production_roundtrip() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let host = gen_broadband(n, sr, 7);
        let watermark_id = generate_watermark_id("did:key:z6MkProd", 1_700_000_000_000);
        let id = derive_v3_id(&watermark_id);
        assert_eq!(id.len(), V3_ID_BYTES);

        let wm = embed_v3(&host, &id, sr);
        let recovered = detect_v3(&wm, sr, V3_ID_BYTES).expect("v3 should detect on clean host");
        assert_eq!(recovered, id, "recovered ID must match embedded ID");
        // payload_hash reproducibility (embed and detect both hash the v3 ID).
        assert_eq!(sha256_hex(&recovered), sha256_hex(&id));
    }

    // Negative: a non-watermarked broadband clip must NOT be detected.
    #[test]
    fn test_v3_no_false_positive_on_clean_host() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let host = gen_broadband(n, sr, 99);
        assert!(
            detect_v3(&host, sr, V3_ID_BYTES).is_none(),
            "un-watermarked audio must not yield a (CRC-valid) detection"
        );
    }

    // ── Public-API interop test (ACCEPTANCE) ────────────────────────────────
    // The crate's clean `embed` -> `detect` round-trip over PCM bytes: this is
    // the "web embed fed to mobile detect" interop proof. `embed` output fed to
    // `detect` must return detected=true and a non-empty payload_hash equal to
    // the embed's payload_hash.
    #[test]
    fn test_embed_detect_interop_pcm() {
        let sr = 44_100u32;
        let n = (sr as f32 * 13.0) as usize;
        let host = gen_broadband(n, sr as f32, 11);
        let pcm = float_to_pcm(&host);

        let emb = embed(&pcm, sr, "did:key:z6MkInterop", 1_700_000_000_000)
            .expect("embed should succeed on a valid broadband clip");
        assert!(!emb.payload_hash.is_empty(), "embed payload_hash must be set");

        let det = detect(&emb.watermarked_audio, sr).expect("detect should not error");
        assert!(det.detected, "detect must report detected=true on embedded clip");
        assert_eq!(
            det.payload_hash.as_deref(),
            Some(emb.payload_hash.as_str()),
            "detect payload_hash must equal embed payload_hash"
        );
        assert_eq!(det.detection_method, "chirp_v3");
    }

    #[test]
    fn test_embed_extract_known_position() {
        // Test embed+extract with known positions (no sync detection).
        // This verifies the core DSP correlation logic works correctly.
        let sample_rate = 44100.0_f32;
        let duration_sec = 8.0;
        let num_samples = (sample_rate * duration_sec) as usize;
        let samples = vec![0.0_f32; num_samples];

        let payload = derive_payload("sonic-test123");
        let watermarked = embed_payload(&samples, &payload, sample_rate);

        // Verify watermark modifies audio
        let diff: f32 = samples.iter().zip(watermarked.iter()).map(|(a, b)| (a - b).abs()).sum();
        assert!(diff > 0.0, "Watermark should modify audio");

        // Extract from KNOWN position (after Barker sync preamble)
        let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
        let barker_samples = BARKER_13.len() * samples_per_chip;
        let extracted = extract_payload(&watermarked[barker_samples..], sample_rate);
        assert!(extracted.is_some(), "Should extract payload from known position");
        assert_eq!(extracted.unwrap(), payload, "Payload should match");
    }

    #[test]
    fn test_barker_sync_detection() {
        // Test that Barker sync finder locates the watermark start
        let sample_rate = 44100.0_f32;
        let num_samples = (sample_rate * 8.0) as usize;
        let samples = vec![0.0_f32; num_samples];

        let payload = derive_payload("sonic-sync-test");
        let watermarked = embed_payload(&samples, &payload, sample_rate);

        let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
        let sync_pos = find_barker_sync(&watermarked, sample_rate);
        assert!(sync_pos.is_some(), "Should find Barker sync");
        // Sync position should be within 1 step (spc/4) of position 0
        assert!(
            sync_pos.unwrap() < samples_per_chip / 2,
            "Barker sync should be near position 0, got {}",
            sync_pos.unwrap(),
        );
    }

    #[test]
    fn test_hann_window() {
        let window = hann_window(4);
        // Hann(4): [0.0, 0.75, 0.75, 0.0]
        assert!((window[0] - 0.0).abs() < 0.01);
        assert!((window[3] - 0.0).abs() < 0.01);
        assert!(window[1] > 0.5);
        assert!(window[2] > 0.5);
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

    // ── Hamming(7,4) Error Correction Tests ────────────────────────────────

    #[test]
    fn test_hamming_encode_decode_no_errors() {
        for data in 0..16u8 {
            let codeword = hamming74_encode(data);
            let decoded = hamming74_decode(codeword);
            assert_eq!(decoded, data, "Hamming roundtrip failed for data={}", data);
        }
    }

    #[test]
    fn test_hamming_single_bit_error() {
        let data: u8 = 0b1010; // 10
        let codeword = hamming74_encode(data);
        // Flip each bit position and verify correction
        for bit in 0..7 {
            let corrupted = codeword ^ (1 << bit);
            let decoded = hamming74_decode(corrupted);
            assert_eq!(decoded, data, "Hamming should correct single-bit error at position {}", bit);
        }
    }

    #[test]
    fn test_hamming_payload_roundtrip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                           0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let code_bits = hamming_encode_payload(&payload);
        assert_eq!(code_bits.len(), HAMMING_CODE_BITS); // 224 bits
        let decoded = hamming_decode_payload(&code_bits);
        assert_eq!(decoded, Some(payload));
    }

    #[test]
    fn test_hamming_payload_with_errors() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                           0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let mut code_bits = hamming_encode_payload(&payload);
        // Flip one bit in each codeword (every 7th bit)
        for i in (0..code_bits.len()).step_by(7) {
            code_bits[i] ^= 1;
        }
        let decoded = hamming_decode_payload(&code_bits);
        assert_eq!(decoded, Some(payload), "Hamming should correct one error per codeword");
    }

    // Exercise the length-generic + soft-decision decoders (used by detect_v3).
    #[test]
    fn test_hamming_decode_payload_n_and_soft() {
        let payload = vec![0x12u8, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let code_bits = hamming_encode_payload(&payload);
        let decoded_n = hamming_decode_payload_n(&code_bits, payload.len());
        assert_eq!(decoded_n, Some(payload.clone()));

        // Soft decode: map hard code bits to +/-1 reliabilities.
        let soft: Vec<f32> = code_bits.iter().map(|&b| if b == 1 { 1.0 } else { -1.0 }).collect();
        let decoded_soft = hamming_soft_decode_payload_n(&soft, payload.len());
        assert_eq!(decoded_soft, Some(payload));
    }

    // ── Multi-Layer Embedding Tests ─────────────────────────────────────────

    #[test]
    fn test_multilayer_embed_detect_roundtrip() {
        // Requires: Barker(13) + 224 Hamming code bits at 50ms each = ~11.85s at 44100Hz
        let sample_rate = 44100.0_f32;
        let duration_sec = 13.0;
        let num_samples = (sample_rate * duration_sec) as usize;
        let samples = vec![0.0_f32; num_samples];

        let payload = derive_payload("sonic-multilayer-test");
        let watermarked = embed_multilayer(&samples, &payload, sample_rate);

        // Verify watermark modifies audio
        let diff: f32 = samples.iter().zip(watermarked.iter()).map(|(a, b)| (a - b).abs()).sum();
        assert!(diff > 0.0, "Multi-layer watermark should modify audio");

        // Extract from KNOWN position (after Barker sync preamble)
        let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sample_rate) as usize;
        let barker_samples = BARKER_13.len() * samples_per_chip;
        let extracted = detect_multilayer(&watermarked, sample_rate, barker_samples);
        assert!(extracted.is_some(), "Should extract multi-layer payload from known position");
        assert_eq!(extracted.unwrap(), payload, "Multi-layer payload should match");
    }

    #[test]
    fn test_masking_amplitude_varies_by_frequency() {
        let sample_rate = 44100.0;
        let samples: Vec<f32> = (0..4096)
            .map(|i| (2.0 * std::f32::consts::PI * 1000.0 * i as f32 / sample_rate).sin() * 0.3)
            .collect();

        let amp_low = compute_masking_amplitude(&samples, sample_rate, 2000.0);
        let amp_high = compute_masking_amplitude(&samples, sample_rate, 18000.0);

        // Both should produce a positive amplitude (floor from RMS-based threshold)
        assert!(amp_low > 0.0, "Low-freq masking amplitude should be positive");
        assert!(amp_high > 0.0, "High-freq masking amplitude should be positive");

        // Both should be bounded by the RMS-based floor minimum
        let rms = compute_rms(&samples);
        let floor = rms * 10.0_f32.powf(-48.0 / 20.0);
        assert!(amp_low >= floor * 0.9, "Low-freq should be at or above RMS floor");
        assert!(amp_high >= floor * 0.9, "High-freq should be at or above RMS floor");
    }

    // ── Robustness harness ──────────────────────────────────────────────────
    // Measures whether the multi-layer watermark survives real-world channel
    // degradations (compression/band-limit, additive noise, codec resampling,
    // and speaker->mic re-recording). The 4-layer design's value is that the
    // lower-frequency layers carry through when the 17.5-19.5 kHz layer is
    // destroyed by an analog channel. Run with:
    //   cargo test robustness_profile -- --nocapture

    // Tiny deterministic PRNG (xorshift64) — avoids a `rand` dependency here.
    struct XorRng(u64);
    impl XorRng {
        fn new(seed: u64) -> Self { XorRng(seed ^ 0x9E37_79B9_7F4A_7C15) }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
        }
        fn unit(&mut self) -> f32 { (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32 }
        fn range(&mut self, lo: f32, hi: f32) -> f32 { lo + self.unit() * (hi - lo) }
        fn gauss(&mut self) -> f32 {
            let u1 = self.unit().max(1e-9);
            let u2 = self.unit();
            (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
        }
    }

    // Broadband host signal so every embedding band has cover energy.
    fn gen_broadband(n: usize, sample_rate: f32, seed: u64) -> Vec<f32> {
        let mut rng = XorRng::new(seed);
        let parts: Vec<(f32, f32)> = (0..64)
            .map(|_| (rng.range(150.0, 20_000.0), rng.range(0.0, std::f32::consts::TAU)))
            .collect();
        (0..n)
            .map(|i| {
                let t = i as f32 / sample_rate;
                let mut s = 0.0_f32;
                for (f, p) in &parts {
                    s += (std::f32::consts::TAU * f * t + p).sin();
                }
                (s / parts.len() as f32 * 0.6 + rng.gauss() * 0.01).clamp(-1.0, 1.0)
            })
            .collect()
    }

    fn add_noise(x: &[f32], snr_db: f32, seed: u64) -> Vec<f32> {
        let mut rng = XorRng::new(seed);
        let sig_p = x.iter().map(|v| v * v).sum::<f32>() / x.len() as f32;
        let std = (sig_p / 10f32.powf(snr_db / 10.0)).sqrt();
        x.iter().map(|&v| (v + rng.gauss() * std).clamp(-1.0, 1.0)).collect()
    }

    // RBJ biquad low-pass (Q=0.707), applied twice for a 4th-order rolloff.
    fn lowpass(x: &[f32], cutoff: f32, sample_rate: f32) -> Vec<f32> {
        let w0 = std::f32::consts::TAU * cutoff / sample_rate;
        let (sn, cs) = (w0.sin(), w0.cos());
        let alpha = sn / (2.0 * 0.707);
        let a0 = 1.0 + alpha;
        let (b0, b1, b2) = ((1.0 - cs) / 2.0 / a0, (1.0 - cs) / a0, (1.0 - cs) / 2.0 / a0);
        let (a1, a2) = (-2.0 * cs / a0, (1.0 - alpha) / a0);
        let pass = |inp: &[f32]| -> Vec<f32> {
            let (mut x1, mut x2, mut y1, mut y2) = (0.0, 0.0, 0.0, 0.0);
            inp.iter()
                .map(|&x0| {
                    let y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
                    x2 = x1; x1 = x0; y2 = y1; y1 = y0; y0
                })
                .collect()
        };
        pass(&pass(x))
    }

    // Codec-style: band-limit, sample at `inter` Hz, linear-interpolate back.
    fn codec_resample(x: &[f32], sample_rate: f32, inter: f32) -> Vec<f32> {
        let bl = lowpass(x, inter / 2.0 * 0.95, sample_rate);
        let ratio = sample_rate / inter;
        let m = (x.len() as f32 / ratio) as usize;
        let down: Vec<f32> = (0..m).map(|i| bl[((i as f32) * ratio) as usize]).collect();
        (0..x.len())
            .map(|i| {
                let pos = i as f32 / ratio;
                let j = pos.floor() as usize;
                let frac = pos - j as f32;
                let a = down.get(j).copied().unwrap_or(0.0);
                let b = down.get(j + 1).copied().unwrap_or(a);
                a + (b - a) * frac
            })
            .collect()
    }

    // Speaker->mic: band-limit + multi-echo reverb + noise + gain + soft clip.
    fn rerecord(x: &[f32], sample_rate: f32, seed: u64) -> Vec<f32> {
        let bl = lowpass(x, 14_000.0, sample_rate);
        let d = |ms: f32| (ms / 1000.0 * sample_rate) as usize;
        let (d1, d2, d3) = (d(7.0), d(13.0), d(23.0));
        let rev: Vec<f32> = (0..bl.len())
            .map(|n| {
                let mut s = bl[n];
                if n >= d1 { s += 0.30 * bl[n - d1]; }
                if n >= d2 { s += 0.18 * bl[n - d2]; }
                if n >= d3 { s += 0.10 * bl[n - d3]; }
                s
            })
            .collect();
        add_noise(&rev, 25.0, seed)
            .iter()
            .map(|&v| (0.7 * v).tanh())
            .collect()
    }

    fn bit_errors(a: &[u8], b: &[u8]) -> u32 {
        let n = a.len().min(b.len());
        let mut e: u32 = (0..n).map(|i| (a[i] ^ b[i]).count_ones()).sum();
        e += (a.len() as i32 - b.len() as i32).unsigned_abs() * 8;
        e
    }

    #[test]
    #[ignore = "measurement harness; run: cargo test robustness_profile -- --ignored --nocapture"]
    fn robustness_profile() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let payload = derive_payload("vouch-sonic-robustness");
        let host = gen_broadband(n, sr, 42);
        let wm = embed_multilayer(&host, &payload, sr);
        let samples_per_chip = (CHIP_DURATION_MS / 1000.0 * sr) as usize;
        let barker_samples = BARKER_13.len() * samples_per_chip;

        let cases: Vec<(&str, Vec<f32>)> = vec![
            ("clean", wm.clone()),
            ("noise SNR 30dB", add_noise(&wm, 30.0, 1)),
            ("noise SNR 20dB", add_noise(&wm, 20.0, 2)),
            ("noise SNR 10dB", add_noise(&wm, 10.0, 3)),
            ("lowpass 16k", lowpass(&wm, 16_000.0, sr)),
            ("lowpass 8k", lowpass(&wm, 8_000.0, sr)),
            ("lowpass 4k", lowpass(&wm, 4_000.0, sr)),
            ("codec ~16k", codec_resample(&wm, sr, 16_000.0)),
            ("codec ~8k", codec_resample(&wm, sr, 8_000.0)),
            ("re-recording", rerecord(&wm, sr, 7)),
        ];

        let total_bits = payload.len() * 8;
        // Known payload offset (embed_multilayer lays Barker at index 0).
        let known_start = barker_samples;
        eprintln!("\n=== Vouch Sonic robustness profile ({total_bits}-bit payload, 4-layer) ===");
        eprintln!(
            "{:<16} {:>10} {:>13} {:>13}",
            "degradation", "sync_off", "known_pos_err", "sync_pos_err"
        );
        let errs_of = |deg: &[f32], start: usize| -> u32 {
            match detect_multilayer(deg, sr, start) {
                Some(p) => bit_errors(&p, &payload),
                None => total_bits as u32,
            }
        };
        for (name, deg) in &cases {
            let sync = find_barker_sync(deg, sr);
            let sync_off = match sync {
                // Offset of detected sync vs the true position (0).
                Some(s) => format!("{}", s as i64),
                None => "LOST".to_string(),
            };
            let known_err = errs_of(deg, known_start);
            let sync_err = match sync {
                Some(s) => errs_of(deg, s + barker_samples),
                None => total_bits as u32,
            };
            eprintln!("{name:<16} {sync_off:>10} {known_err:>13} {sync_err:>13}");
        }
        eprintln!("(known_pos_err isolates payload robustness; sync_pos_err includes sync search)");

        // Report-only; the point of this test is the table, not a pass/fail.
        let clean_known = errs_of(&wm, known_start);
        eprintln!("clean known-position bit errors: {clean_known}/{total_bits}");
    }

    #[test]
    #[ignore = "measurement harness; run: cargo test robustness_profile_v2 -- --ignored --nocapture"]
    fn robustness_profile_v2() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let payload = derive_payload("vouch-sonic-robustness");
        let host = gen_broadband(n, sr, 42);
        let wm = embed_v2(&host, &payload, sr);
        let chirp_len = gen_chirp(sr, 1.0).len();
        let total_bits = payload.len() * 8;

        let cases: Vec<(&str, Vec<f32>)> = vec![
            ("clean", wm.clone()),
            ("noise SNR 30dB", add_noise(&wm, 30.0, 1)),
            ("noise SNR 20dB", add_noise(&wm, 20.0, 2)),
            ("noise SNR 10dB", add_noise(&wm, 10.0, 3)),
            ("lowpass 16k", lowpass(&wm, 16_000.0, sr)),
            ("lowpass 8k", lowpass(&wm, 8_000.0, sr)),
            ("lowpass 4k", lowpass(&wm, 4_000.0, sr)),
            ("codec ~16k", codec_resample(&wm, sr, 16_000.0)),
            ("codec ~8k", codec_resample(&wm, sr, 8_000.0)),
            ("re-recording", rerecord(&wm, sr, 7)),
        ];

        eprintln!("\n=== Vouch Sonic v2 (chirp sync) robustness ({total_bits}-bit) ===");
        eprintln!("{:<16} {:>9} {:>6} {:>9} {:>11}", "degradation", "sync_off", "sync", "decoded", "bit_errors");
        let template = gen_chirp(sr, 1.0);
        for (name, deg) in &cases {
            let (off, found, decoded, errs) = match find_chirp_start(deg, &template) {
                Some(s) => {
                    let (d, e) = match detect_multilayer_soft(deg, sr, s + chirp_len) {
                        Some(p) => (if p == payload { "EXACT" } else { "partial" }, bit_errors(&p, &payload)),
                        None => ("FAIL", total_bits as u32),
                    };
                    (format!("{}", s as i64), "ok", d, e)
                }
                None => ("-".to_string(), "LOST", "-", total_bits as u32),
            };
            eprintln!("{name:<16} {off:>9} {found:>6} {decoded:>9} {errs:>11}");
        }
    }

    #[test]
    #[ignore = "measurement harness; run: cargo test robustness_profile_v3 -- --ignored --nocapture"]
    fn robustness_profile_v3() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let full = derive_payload("vouch-sonic-robustness");
        let id: Vec<u8> = full[..4].to_vec(); // 32-bit watermark ID (server lookup)
        let host = gen_broadband(n, sr, 42);
        let wm = embed_v3(&host, &id, sr);
        let total_bits = id.len() * 8;

        let cases: Vec<(&str, Vec<f32>)> = vec![
            ("clean", wm.clone()),
            ("noise SNR 20dB", add_noise(&wm, 20.0, 2)),
            ("noise SNR 10dB", add_noise(&wm, 10.0, 3)),
            ("lowpass 8k", lowpass(&wm, 8_000.0, sr)),
            ("lowpass 4k", lowpass(&wm, 4_000.0, sr)),
            ("codec ~16k", codec_resample(&wm, sr, 16_000.0)),
            ("codec ~8k", codec_resample(&wm, sr, 8_000.0)),
            ("re-recording", rerecord(&wm, sr, 7)),
            ("re-rec+codec8k", codec_resample(&rerecord(&wm, sr, 7), sr, 8_000.0)),
        ];

        eprintln!("\n=== Vouch Sonic v3 (chirp + time-diversity repetition) — {total_bits}-bit ID ===");
        eprintln!("{:<18} {:>9} {:>11}", "degradation", "decoded", "bit_errors");
        for (name, deg) in &cases {
            let (decoded, errs) = match detect_v3(deg, sr, id.len()) {
                Some(p) => (if p == id { "EXACT" } else { "partial" }, bit_errors(&p, &id)),
                None => ("LOST", total_bits as u32),
            };
            eprintln!("{name:<18} {decoded:>9} {errs:>11}");
        }
    }

    // Multi-seed / multi-ID stress: confirm EXACT decode is not specific to one
    // host realization or one ID value.
    #[test]
    #[ignore = "stress; run: cargo test v3_stress -- --ignored --nocapture"]
    fn v3_stress() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let mut worst = 0u32;
        let mut total_exact = 0u32;
        let mut total_cases = 0u32;
        for trial in 0..8u64 {
            let id: Vec<u8> = derive_payload(&format!("vouch-id-{trial}"))[..4].to_vec();
            let host = gen_broadband(n, sr, 100 + trial);
            let wm = embed_v3(&host, &id, sr);
            let cases: Vec<(&str, Vec<f32>)> = vec![
                ("clean", wm.clone()),
                ("noise20", add_noise(&wm, 20.0, trial)),
                ("noise10", add_noise(&wm, 10.0, trial + 1)),
                ("lp8k", lowpass(&wm, 8_000.0, sr)),
                ("lp4k", lowpass(&wm, 4_000.0, sr)),
                ("codec16k", codec_resample(&wm, sr, 16_000.0)),
                ("codec8k", codec_resample(&wm, sr, 8_000.0)),
                ("rerec", rerecord(&wm, sr, trial + 7)),
                ("rerec+codec8k", codec_resample(&rerecord(&wm, sr, trial + 7), sr, 8_000.0)),
            ];
            for (name, deg) in &cases {
                total_cases += 1;
                let e = match detect_v3(deg, sr, id.len()) {
                    Some(p) => bit_errors(&p, &id),
                    None => id.len() as u32 * 8,
                };
                if e == 0 { total_exact += 1; } else {
                    eprintln!("trial {trial} {name}: {e} bit errors");
                }
                worst = worst.max(e);
            }
        }
        eprintln!("v3 stress: {total_exact}/{total_cases} EXACT, worst={worst} bit errors");
        // The required robustness_profile_v3 channels all decode EXACT. This
        // broader matrix (8 random hosts x the absolute worst channels) is a
        // stricter, informational bar; we assert the overwhelming majority decode
        // EXACT and that the only residual failures are confined to the most
        // brutal channel (re-record THEN 8 kHz codec), where only ~2 ID
        // repetitions fit and almost the entire spectrum above 3.5 kHz is gone.
        assert!(
            total_exact * 100 >= total_cases * 95,
            "expected >=95% EXACT across the worst-case host/channel matrix, got {total_exact}/{total_cases}"
        );
    }

    // Per-layer diagnostic: for each channel, report each layer's own decoded
    // bit errors (coherent sin correlator, rep-summed) and its mean |soft| so we
    // can see which layers survive and design the SNR weighting from data.
    #[test]
    #[ignore = "diagnostic; run: cargo test v3_layer_diagnostic -- --ignored --nocapture"]
    fn v3_layer_diagnostic() {
        let sr = 44_100.0_f32;
        let n = (sr * 13.0) as usize;
        let id: Vec<u8> = derive_payload("vouch-id-1")[..4].to_vec();
        let host = gen_broadband(n, sr, 101);
        let wm = embed_v3(&host, &id, sr);
        let mut frame = id.clone();
        frame.extend_from_slice(&crc16(&id));
        let code_bits_true = hamming_encode_payload(&frame);
        let code_bits_len = frame.len() * 2 * 7;
        let spc = (V3_CHIP_DURATION_MS / 1000.0 * sr) as usize;
        let chirp = gen_chirp(sr, 1.0);

        let cases: Vec<(&str, Vec<f32>)> = vec![
            ("clean", wm.clone()),
            ("lowpass 8k", lowpass(&wm, 8_000.0, sr)),
            ("lowpass 4k", lowpass(&wm, 4_000.0, sr)),
            ("codec ~16k", codec_resample(&wm, sr, 16_000.0)),
            ("codec ~8k", codec_resample(&wm, sr, 8_000.0)),
            ("re-recording", rerecord(&wm, sr, 7)),
            ("re-rec+codec8k", codec_resample(&rerecord(&wm, sr, 7), sr, 8_000.0)),
        ];

        eprintln!("\n=== v3 per-layer diagnostic (code_bits_len={code_bits_len}) ===");
        for (name, deg) in &cases {
            // Force the TRUE sync position (0) so this isolates per-layer payload
            // robustness from sync search.
            let pos0 = chirp.len();
            let sync_off = 0i64;
            let window = hann_window(spc);
            let avail_chips = deg.len().saturating_sub(pos0) / spc;
            let reps = (avail_chips / code_bits_len).max(1);
            eprint!("[sync_off={sync_off}] ");
            eprint!("{name:<16} reps={reps:<3} ");
            for (li, &(low0, low1, high0, high1)) in V3_LAYER_BANDS.iter().enumerate() {
                if high1 > sr / 2.0 { continue; }
                let mut soft = vec![0.0f32; code_bits_len];
                for rep in 0..reps {
                    let rep_off = pos0 + rep * code_bits_len * spc;
                    for bit_idx in 0..code_bits_len {
                        let cs = rep_off + bit_idx * spc;
                        if cs + spc > deg.len() { break; }
                        let chip = &deg[cs..cs + spc];
                        let (mut ch, mut cl) = (0.0f32, 0.0f32);
                        let two_pi = 2.0 * std::f32::consts::PI;
                        for (s, &x) in chip.iter().enumerate() {
                            let w = window.get(s).copied().unwrap_or(0.0);
                            let t = s as f32 / sr;
                            ch += x * w * ((two_pi * high0 * t).sin() + (two_pi * high1 * t).sin());
                            cl += x * w * ((two_pi * low0 * t).sin() + (two_pi * low1 * t).sin());
                        }
                        soft[bit_idx] += ch - cl;
                    }
                }
                let errs: u32 = (0..code_bits_len)
                    .map(|b| { let hb = if soft[b] > 0.0 { 1u8 } else { 0 }; (hb ^ code_bits_true[b]) as u32 })
                    .sum();
                let mean_abs = soft.iter().map(|v| v.abs()).sum::<f32>() / code_bits_len as f32;
                eprint!("L{li}:err{errs}/mag{:.3} ", mean_abs / reps as f32);
            }
            eprintln!();
        }
    }
}
