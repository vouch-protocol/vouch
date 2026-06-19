//! Vouch Sonic Core - Real-time Audio Watermark Detection
//!
//! This crate provides the native Rust implementation of the Vouch Sonic
//! protocol for detecting cryptographic watermarks in audio streams.
//!
//! # Architecture
//!
//! The library is designed to run in a native thread on mobile devices,
//! processing audio buffers in real-time and emitting detection events
//! to the UI layer via callbacks.
//!
//! # FFI
//!
//! UniFFI generates type-safe bindings for:
//! - Swift (iOS)
//! - Kotlin (Android)
//!
//! # Example
//!
//! ```rust,ignore
//! use vouch_sonic_core::*;
//!
//! let config = SonicConfig::default();
//! let listener = SonicListener::new(config)?;
//!
//! // Process a buffer
//! let result = listener.process_samples(&audio_samples)?;
//! if result.detected {
//!     println!("Watermark found! Signer: {:?}", result.signer_did);
//! }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
use vouch_sonic_dsp as dsp;

// =============================================================================
// UniFFI Scaffolding
// =============================================================================

uniffi::include_scaffolding!("vouch_sonic_core");

// =============================================================================
// Constants
// =============================================================================

/// Minimum audio samples required for detection
const MIN_SAMPLES: usize = 1024;

/// Default sample rate
const DEFAULT_SAMPLE_RATE: u32 = 16000;

/// Default frame size in milliseconds
const DEFAULT_FRAME_SIZE_MS: u32 = 50;

/// Default detection threshold
const DEFAULT_THRESHOLD: f32 = 0.5;

/// Default spreading factor
const DEFAULT_SPREADING_FACTOR: u32 = 100;

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug, Error, Clone)]
pub enum SonicError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Audio initialization failed: {0}")]
    AudioInitFailed(String),

    #[error("Processing failed: {0}")]
    ProcessingFailed(String),

    #[error("Buffer too short: need at least {0} samples")]
    BufferTooShort(usize),

    #[error("Invalid sample rate: {0}")]
    InvalidSampleRate(u32),

    #[error("Listener already running")]
    ListenerAlreadyRunning,

    #[error("Listener not running")]
    ListenerNotRunning,

    #[error("Internal error: {0}")]
    InternalError(String),
}

// Implement uniffi compatible error conversion
impl From<SonicError> for uniffi::UnexpectedUniFFICallbackError {
    fn from(err: SonicError) -> Self {
        uniffi::UnexpectedUniFFICallbackError::new(err.to_string())
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the Sonic Listener
#[derive(Debug, Clone)]
pub struct SonicConfig {
    /// Target sample rate in Hz (default: 16000)
    pub sample_rate: u32,
    
    /// Frame size in milliseconds (default: 50)
    pub frame_size_ms: u32,
    
    /// Detection confidence threshold (default: 0.5)
    pub detection_threshold: f32,
    
    /// Spread spectrum spreading factor (default: 100)
    pub spreading_factor: u32,
    
    /// Enable chirp synchronization markers (default: true)
    pub enable_chirp_sync: bool,
}

impl Default for SonicConfig {
    fn default() -> Self {
        Self {
            sample_rate: DEFAULT_SAMPLE_RATE,
            frame_size_ms: DEFAULT_FRAME_SIZE_MS,
            detection_threshold: DEFAULT_THRESHOLD,
            spreading_factor: DEFAULT_SPREADING_FACTOR,
            enable_chirp_sync: true,
        }
    }
}

impl SonicConfig {
    /// Validate the configuration
    fn validate(&self) -> Result<(), SonicError> {
        if self.sample_rate < 8000 || self.sample_rate > 96000 {
            return Err(SonicError::InvalidSampleRate(self.sample_rate));
        }
        if self.frame_size_ms < 10 || self.frame_size_ms > 1000 {
            return Err(SonicError::InvalidConfig(
                "frame_size_ms must be between 10 and 1000".into(),
            ));
        }
        if self.detection_threshold < 0.0 || self.detection_threshold > 1.0 {
            return Err(SonicError::InvalidConfig(
                "detection_threshold must be between 0.0 and 1.0".into(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// Watermark Result
// =============================================================================

/// Result of watermark detection
#[derive(Debug, Clone, Default)]
pub struct WatermarkResult {
    /// Whether a watermark was detected
    pub detected: bool,
    
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
    
    /// Signer's DID if extracted
    pub signer_did: Option<String>,
    
    /// Unix timestamp when signed
    pub timestamp: Option<u64>,
    
    /// Hash of the extracted payload
    pub payload_hash: Option<String>,
    
    /// Covenant data as JSON string
    pub covenant_json: Option<String>,
    
    /// Estimated audio quality (0.0 - 1.0)
    pub audio_quality: f32,
    
    /// Detection method used
    pub detection_method: String,
}

impl WatermarkResult {
    /// Create a "not detected" result
    fn not_detected() -> Self {
        Self {
            detected: false,
            confidence: 0.0,
            detection_method: "none".into(),
            audio_quality: 1.0,
            ..Default::default()
        }
    }

    /// Map a `vouch-sonic-dsp` detection result into the FFI `WatermarkResult`.
    ///
    /// The v3 codec recovers a compact watermark **ID** (and its `payload_hash`
    /// = SHA-256 of that ID), which is the server lookup key. The signer DID,
    /// signing timestamp, and covenant are resolved server-side from that hash,
    /// so they remain `None` here.
    fn from_dsp(d: dsp::DetectResult) -> Self {
        Self {
            detected: d.detected,
            confidence: d.confidence,
            signer_did: None,
            timestamp: None,
            payload_hash: d.payload_hash,
            covenant_json: None,
            audio_quality: d.audio_quality,
            detection_method: d.detection_method,
        }
    }
}

// =============================================================================
// Listener State
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerState {
    Idle,
    Listening,
    Processing,
    Error,
}

impl Default for ListenerState {
    fn default() -> Self {
        Self::Idle
    }
}

// =============================================================================
// Callback Interface
// =============================================================================

/// Callback interface for watermark detection events
pub trait WatermarkCallback: Send + Sync {
    /// Called when a watermark is detected
    fn on_watermark_detected(&self, result: WatermarkResult);
    
    /// Called when audio level changes (for UI meter)
    fn on_audio_level_changed(&self, level_db: f32);
    
    /// Called on error
    fn on_error(&self, message: String);
    
    /// Called when listener state changes
    fn on_state_changed(&self, state: ListenerState);
}

// =============================================================================
// Detection helper
// =============================================================================

/// Convert float samples (mono, -1.0..1.0) to 16-bit LE PCM bytes — the input
/// format the shared `vouch-sonic-dsp` codec expects.
fn samples_to_pcm_le16(samples: &[f32]) -> Vec<u8> {
    let mut pcm = Vec::with_capacity(samples.len() * 2);
    for &s in samples {
        let clamped = s.max(-1.0).min(1.0);
        let i16_val = (clamped * 32767.0) as i16;
        pcm.extend_from_slice(&i16_val.to_le_bytes());
    }
    pcm
}

// =============================================================================
// Sonic Listener
// =============================================================================

/// Main listener object exposed via FFI
pub struct SonicListener {
    config: RwLock<SonicConfig>,
    state: RwLock<ListenerState>,
    is_running: AtomicBool,
    callback: RwLock<Option<Arc<dyn WatermarkCallback>>>,
}

impl SonicListener {
    /// Create a new SonicListener with the given configuration
    pub fn new(config: SonicConfig) -> Result<Self, SonicError> {
        config.validate()?;

        Ok(Self {
            config: RwLock::new(config),
            state: RwLock::new(ListenerState::Idle),
            is_running: AtomicBool::new(false),
            callback: RwLock::new(None),
        })
    }

    /// Start listening for watermarks
    pub fn start_listening(
        self: &Arc<Self>,
        callback: Box<dyn WatermarkCallback>,
    ) -> Result<(), SonicError> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(SonicError::ListenerAlreadyRunning);
        }

        // Foreign callback arrives as Box (uniffi 0.28 callback interface); keep as Arc.
        let callback: Arc<dyn WatermarkCallback> = Arc::from(callback);
        *self.callback.write() = Some(callback.clone());
        
        // Update state
        self.is_running.store(true, Ordering::SeqCst);
        *self.state.write() = ListenerState::Listening;
        
        // Notify state change
        callback.on_state_changed(ListenerState::Listening);
        
        // Note: In a real implementation, we would start an audio capture thread here
        // For mobile, the audio capture is typically handled by the platform (Swift/Kotlin)
        // and buffers are passed to process_buffer/process_samples
        
        log::info!("SonicListener started");
        Ok(())
    }

    /// Stop listening
    pub fn stop_listening(&self) -> Result<(), SonicError> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Err(SonicError::ListenerNotRunning);
        }

        self.is_running.store(false, Ordering::SeqCst);
        *self.state.write() = ListenerState::Idle;
        
        // Notify callback
        if let Some(callback) = self.callback.read().as_ref() {
            callback.on_state_changed(ListenerState::Idle);
        }
        
        log::info!("SonicListener stopped");
        Ok(())
    }

    /// Process PCM audio buffer (16-bit signed, little-endian).
    ///
    /// Runs the real shared `vouch-sonic-dsp` v3 detector (chirp matched-filter
    /// sync + multi-layer FSK + CRC-validated soft decode) over the buffer.
    pub fn process_buffer(&self, pcm_data: &[u8]) -> Result<WatermarkResult, SonicError> {
        if pcm_data.len() < MIN_SAMPLES * 2 {
            return Err(SonicError::BufferTooShort(MIN_SAMPLES * 2));
        }

        *self.state.write() = ListenerState::Processing;

        // Emit audio level for UI (RMS over the decoded samples).
        let level_db = {
            let mut sumsq = 0.0f64;
            let mut count = 0usize;
            for chunk in pcm_data.chunks_exact(2) {
                let s = i16::from_le_bytes([chunk[0], chunk[1]]) as f32 / 32768.0;
                sumsq += (s * s) as f64;
                count += 1;
            }
            let rms = if count > 0 { (sumsq / count as f64).sqrt() as f32 } else { 0.0 };
            20.0 * rms.max(1e-10).log10()
        };
        if let Some(callback) = self.callback.read().as_ref() {
            callback.on_audio_level_changed(level_db);
        }

        let sample_rate = self.config.read().sample_rate;
        let result = self.detect_pcm(pcm_data, sample_rate);

        if result.detected {
            self.emit_detection(&result);
        }

        *self.state.write() = if self.is_running.load(Ordering::SeqCst) {
            ListenerState::Listening
        } else {
            ListenerState::Idle
        };

        Ok(result)
    }

    /// Process float samples directly.
    ///
    /// Converts to 16-bit LE PCM and runs the real shared v3 detector.
    pub fn process_samples(&self, samples: &[f32]) -> Result<WatermarkResult, SonicError> {
        if samples.len() < MIN_SAMPLES {
            return Err(SonicError::BufferTooShort(MIN_SAMPLES));
        }

        *self.state.write() = ListenerState::Processing;

        // Calculate audio level for UI
        let rms: f32 = (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt();
        let level_db = 20.0 * rms.max(1e-10).log10();

        // Emit audio level
        if let Some(callback) = self.callback.read().as_ref() {
            callback.on_audio_level_changed(level_db);
        }

        let sample_rate = self.config.read().sample_rate;
        let pcm = samples_to_pcm_le16(samples);
        let result = self.detect_pcm(&pcm, sample_rate);

        // Emit detection if found
        if result.detected {
            self.emit_detection(&result);
        }

        *self.state.write() = if self.is_running.load(Ordering::SeqCst) {
            ListenerState::Listening
        } else {
            ListenerState::Idle
        };

        Ok(result)
    }

    /// Run the shared DSP v3 detector over 16-bit LE PCM and map to the FFI
    /// `WatermarkResult`. A clip shorter than the DSP minimum (or any DSP-level
    /// error) maps to a clean "not detected" result rather than an FFI error,
    /// since real-time callers feed short rolling buffers.
    fn detect_pcm(&self, pcm_data: &[u8], sample_rate: u32) -> WatermarkResult {
        match dsp::detect(pcm_data, sample_rate) {
            Ok(d) => WatermarkResult::from_dsp(d),
            Err(_) => WatermarkResult::not_detected(),
        }
    }

    /// Emit watermark detected event to callback
    fn emit_detection(&self, result: &WatermarkResult) {
        if let Some(callback) = self.callback.read().as_ref() {
            callback.on_watermark_detected(result.clone());
        }
    }

    /// Get current state
    pub fn get_state(&self) -> ListenerState {
        *self.state.read()
    }

    /// Check if currently listening
    pub fn is_listening(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Get current configuration
    pub fn get_config(&self) -> SonicConfig {
        self.config.read().clone()
    }

    /// Update detection threshold at runtime
    pub fn set_detection_threshold(&self, threshold: f32) {
        if threshold >= 0.0 && threshold <= 1.0 {
            self.config.write().detection_threshold = threshold;
        }
    }
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Result of signature verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub signer_did: Option<String>,
    pub error_message: Option<String>,
}

/// Verifier for Ed25519 signatures
pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify Ed25519 signature
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> VerificationResult {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Parse public key
        let pk = match public_key.try_into() {
            Ok(bytes) => match VerifyingKey::from_bytes(&bytes) {
                Ok(key) => key,
                Err(e) => {
                    return VerificationResult {
                        valid: false,
                        signer_did: None,
                        error_message: Some(format!("Invalid public key: {}", e)),
                    }
                }
            },
            Err(_) => {
                return VerificationResult {
                    valid: false,
                    signer_did: None,
                    error_message: Some("Public key must be 32 bytes".into()),
                }
            }
        };

        // Parse signature
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(e) => {
                return VerificationResult {
                    valid: false,
                    signer_did: None,
                    error_message: Some(format!("Invalid signature: {}", e)),
                }
            }
        };

        // Verify
        match pk.verify(message, &sig) {
            Ok(()) => {
                // Compute DID from public key
                let did = format!(
                    "did:key:z6Mk{}",
                    bs58::encode(public_key).into_string()
                );
                
                VerificationResult {
                    valid: true,
                    signer_did: Some(did),
                    error_message: None,
                }
            }
            Err(e) => VerificationResult {
                valid: false,
                signer_did: None,
                error_message: Some(format!("Signature verification failed: {}", e)),
            },
        }
    }

    /// Verify payload from watermark result
    pub fn verify_watermark_payload(&self, result: WatermarkResult) -> VerificationResult {
        // In a real implementation, we would:
        // 1. Extract signature from payload
        // 2. Extract public key from DID
        // 3. Verify signature over content hash
        
        // For now, return mock verification
        if result.detected {
            VerificationResult {
                valid: true,
                signer_did: result.signer_did,
                error_message: None,
            }
        } else {
            VerificationResult {
                valid: false,
                signer_did: None,
                error_message: Some("No watermark detected".into()),
            }
        }
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self
    }
}

// =============================================================================
// Module Functions
// =============================================================================

/// Get library version
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

/// Quick detection function (without creating listener)
pub fn detect_watermark(audio_data: &[u8], sample_rate: u32) -> WatermarkResult {
    // Create temporary config and engine
    let config = SonicConfig {
        sample_rate,
        ..Default::default()
    };
    
    if let Err(_) = config.validate() {
        return WatermarkResult::not_detected();
    }
    
    let listener = match SonicListener::new(config) {
        Ok(l) => l,
        Err(_) => return WatermarkResult::not_detected(),
    };
    
    match listener.process_buffer(audio_data) {
        Ok(result) => result,
        Err(_) => WatermarkResult::not_detected(),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[derive(Default)]
    struct TestCallback {
        detections: AtomicU32,
        levels: AtomicU32,
    }

    impl WatermarkCallback for TestCallback {
        fn on_watermark_detected(&self, _result: WatermarkResult) {
            self.detections.fetch_add(1, Ordering::SeqCst);
        }

        fn on_audio_level_changed(&self, _level_db: f32) {
            self.levels.fetch_add(1, Ordering::SeqCst);
        }

        fn on_error(&self, _message: String) {}
        fn on_state_changed(&self, _state: ListenerState) {}
    }

    #[test]
    fn test_config_default() {
        let config = SonicConfig::default();
        assert_eq!(config.sample_rate, 16000);
        assert_eq!(config.frame_size_ms, 50);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_sample_rate() {
        let config = SonicConfig {
            sample_rate: 100, // Too low
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_listener_creation() {
        let config = SonicConfig::default();
        let listener = SonicListener::new(config);
        assert!(listener.is_ok());
    }

    #[test]
    fn test_listener_start_stop() {
        let config = SonicConfig::default();
        // `start_listening` takes `self: &Arc<Self>` (uniffi callback interface),
        // so the listener must be held in an Arc; the callback is passed boxed.
        let listener = Arc::new(SonicListener::new(config).unwrap());

        assert!(listener.start_listening(Box::new(TestCallback::default())).is_ok());
        assert!(listener.is_listening());

        assert!(listener.stop_listening().is_ok());
        assert!(!listener.is_listening());
    }

    #[test]
    fn test_process_samples() {
        let config = SonicConfig::default();
        let listener = SonicListener::new(config).unwrap();
        
        // Generate test audio (silence)
        let samples: Vec<f32> = vec![0.0; 2048];
        
        let result = listener.process_samples(&samples);
        assert!(result.is_ok());
        assert!(!result.unwrap().detected);
    }

    // Deterministic broadband host so the v3 masking model has cover energy in
    // every embedding band (silence gives the watermark nothing to hide under).
    fn gen_broadband(n: usize, sample_rate: f32, seed: u64) -> Vec<f32> {
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

    // ACCEPTANCE: the FFI `detect_watermark` on a real v3-embedded clip must
    // report detected=true with a payload_hash (no longer a mock). The clip is
    // produced by the shared `dsp::embed` — i.e. the same bytes a browser embed
    // would emit — and the recovered payload_hash must equal the embed's.
    #[test]
    fn test_detect_watermark_real_embedded_clip() {
        let sr = 44_100u32;
        let n = (sr as f32 * 13.0) as usize;
        let pcm = samples_to_pcm_le16(&gen_broadband(n, sr as f32, 7));

        let emb = dsp::embed(&pcm, sr, "did:key:z6MkMobileDetect", 1_700_000_000_000)
            .expect("embed should succeed on a valid broadband clip");

        let result = detect_watermark(&emb.watermarked_audio, sr);
        assert!(result.detected, "real v3 detect must find the embedded watermark");
        assert_eq!(
            result.payload_hash.as_deref(),
            Some(emb.payload_hash.as_str()),
            "recovered payload_hash must equal the embed payload_hash"
        );
        assert_eq!(result.detection_method, "chirp_v3");
        // The mock path is gone: signer_did / timestamp / covenant resolve
        // server-side from payload_hash, so they are absent here.
        assert!(result.signer_did.is_none());
        assert!(result.covenant_json.is_none());
    }

    // A non-watermarked clip must NOT be detected (negative / false-positive
    // guard, now that detection is real and CRC-gated).
    #[test]
    fn test_detect_watermark_clean_clip_negative() {
        let sr = 44_100u32;
        let n = (sr as f32 * 13.0) as usize;
        let pcm = samples_to_pcm_le16(&gen_broadband(n, sr as f32, 99));
        let result = detect_watermark(&pcm, sr);
        assert!(!result.detected, "un-watermarked audio must not be detected");
    }

    #[test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_signature_verifier() {
        let verifier = SignatureVerifier::new();
        
        // Test with invalid data
        let result = verifier.verify_signature(
            b"test message",
            &[0u8; 64],
            &[0u8; 32],
        );
        assert!(!result.valid);
    }
}
