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
use rustfft::{num_complex::Complex, FftPlanner};
use sha2::{Digest, Sha256};
use thiserror::Error;

// =============================================================================
// UniFFI Scaffolding
// =============================================================================

uniffi::include_scaffolding!("vouch_sonic_core");

// =============================================================================
// Constants
// =============================================================================

/// Vouch Sonic watermark magic bytes (for mock detection)
const WATERMARK_MAGIC: [u8; 4] = [0x56, 0x53, 0x4E, 0x43]; // "VSNC"

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

/// Mock DID for testing
const MOCK_SIGNER_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faEnNg2dFg857faEnNg";

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
        uniffi::UnexpectedUniFFICallbackError::from_reason(err.to_string())
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

    /// Calculate samples per frame
    fn samples_per_frame(&self) -> usize {
        (self.sample_rate * self.frame_size_ms / 1000) as usize
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

    /// Create a detected result with mock data (for FFI testing)
    fn mock_detected(confidence: f32) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();

        Self {
            detected: true,
            confidence,
            signer_did: Some(MOCK_SIGNER_DID.into()),
            timestamp,
            payload_hash: Some("a1b2c3d4e5f67890".into()),
            covenant_json: Some(r#"{"ai_training":false,"voice_cloning":false}"#.into()),
            audio_quality: 0.95,
            detection_method: "mock".into(),
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
// DSP Engine (Core Processing)
// =============================================================================

/// Digital Signal Processing engine for watermark detection
struct DspEngine {
    config: SonicConfig,
    fft_planner: FftPlanner<f32>,
    pn_sequence: Vec<f32>,
    frame_buffer: Vec<f32>,
}

impl DspEngine {
    fn new(config: &SonicConfig) -> Self {
        // Generate pseudo-random noise sequence for correlation
        let pn_sequence = Self::generate_pn_sequence(config.spreading_factor as usize);
        
        Self {
            config: config.clone(),
            fft_planner: FftPlanner::new(),
            pn_sequence,
            frame_buffer: Vec::with_capacity(config.samples_per_frame()),
        }
    }

    /// Generate pseudo-random noise sequence (deterministic from seed)
    fn generate_pn_sequence(length: usize) -> Vec<f32> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xVOUCH5ON1C); // Fixed seed
        
        (0..length)
            .map(|_| if rng.gen::<bool>() { 1.0 } else { -1.0 })
            .collect()
    }

    /// Compute FFT of audio samples
    fn compute_fft(&mut self, samples: &[f32]) -> Vec<Complex<f32>> {
        let len = samples.len().next_power_of_two();
        let fft = self.fft_planner.plan_fft_forward(len);
        
        let mut buffer: Vec<Complex<f32>> = samples
            .iter()
            .map(|&s| Complex::new(s, 0.0))
            .collect();
        
        // Pad to power of 2
        buffer.resize(len, Complex::new(0.0, 0.0));
        
        fft.process(&mut buffer);
        buffer
    }

    /// Estimate audio quality based on spectral analysis
    fn estimate_quality(&mut self, samples: &[f32]) -> f32 {
        if samples.len() < 256 {
            return 0.5;
        }
        
        // Simple quality estimation based on high-frequency content
        let spectrum = self.compute_fft(samples);
        let len = spectrum.len();
        
        // Ratio of energy in upper half vs lower half
        let low_energy: f32 = spectrum[..len / 4]
            .iter()
            .map(|c| c.norm_sqr())
            .sum();
        let high_energy: f32 = spectrum[len / 4..len / 2]
            .iter()
            .map(|c| c.norm_sqr())
            .sum();
        
        // Good quality audio has balanced spectrum
        let ratio = high_energy / (low_energy + 1e-10);
        (ratio.min(1.0) * 0.5 + 0.5).min(1.0)
    }

    /// Detect spread spectrum watermark using correlation
    fn detect_spread_spectrum(&mut self, samples: &[f32]) -> (bool, f32) {
        if samples.len() < self.pn_sequence.len() {
            return (false, 0.0);
        }
        
        // Cross-correlation with PN sequence
        let mut max_correlation: f32 = 0.0;
        let step = self.pn_sequence.len();
        
        for start in (0..samples.len() - step).step_by(step / 2) {
            let chunk = &samples[start..start + step.min(samples.len() - start)];
            
            let correlation: f32 = chunk
                .iter()
                .zip(self.pn_sequence.iter())
                .map(|(a, b)| a * b)
                .sum::<f32>()
                .abs() / step as f32;
            
            max_correlation = max_correlation.max(correlation);
        }
        
        // Normalize to 0-1 range
        let confidence = (max_correlation * 10.0).min(1.0);
        let detected = confidence > self.config.detection_threshold;
        
        (detected, confidence)
    }

    /// Detect chirp synchronization markers
    fn detect_chirp_sync(&mut self, samples: &[f32]) -> bool {
        if !self.config.enable_chirp_sync || samples.len() < 512 {
            return false;
        }
        
        // Simple chirp detection via instantaneous frequency analysis
        let spectrum = self.compute_fft(&samples[..512.min(samples.len())]);
        
        // Look for characteristic chirp pattern (rising frequency)
        let mut prev_peak_bin = 0;
        let mut rising_count = 0;
        
        for chunk_start in (0..spectrum.len() / 2).step_by(16) {
            let chunk = &spectrum[chunk_start..chunk_start + 16.min(spectrum.len() / 2 - chunk_start)];
            
            let peak_bin = chunk
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.norm_sqr().partial_cmp(&b.norm_sqr()).unwrap())
                .map(|(i, _)| i + chunk_start)
                .unwrap_or(0);
            
            if peak_bin > prev_peak_bin {
                rising_count += 1;
            }
            prev_peak_bin = peak_bin;
        }
        
        // Need consistent rising pattern for chirp
        rising_count > 3
    }

    /// Process audio samples and detect watermark
    fn process(&mut self, samples: &[f32]) -> WatermarkResult {
        if samples.len() < MIN_SAMPLES {
            return WatermarkResult::not_detected();
        }
        
        // Estimate audio quality
        let quality = self.estimate_quality(samples);
        
        // Try spread spectrum detection
        let (ss_detected, ss_confidence) = self.detect_spread_spectrum(samples);
        
        // Try chirp sync detection
        let chirp_detected = self.detect_chirp_sync(samples);
        
        // Combine detection results
        let detected = ss_detected || chirp_detected;
        let confidence = if chirp_detected {
            ss_confidence.max(0.7)  // Chirp detection boosts confidence
        } else {
            ss_confidence
        };
        
        if detected && confidence > self.config.detection_threshold {
            // For now, return mock data when detected
            // Real implementation would extract payload from watermark
            let mut result = WatermarkResult::mock_detected(confidence);
            result.audio_quality = quality;
            result.detection_method = if chirp_detected {
                "chirp_sync".into()
            } else {
                "spread_spectrum".into()
            };
            result
        } else {
            WatermarkResult {
                detected: false,
                confidence,
                audio_quality: quality,
                detection_method: "spread_spectrum".into(),
                ..Default::default()
            }
        }
    }
}

// =============================================================================
// Mock Detector (for FFI testing)
// =============================================================================

/// Mock detector that looks for specific patterns in audio
struct MockDetector;

impl MockDetector {
    /// Detect mock watermark by looking for magic bytes in PCM data
    fn detect_in_bytes(data: &[u8]) -> WatermarkResult {
        // Look for magic bytes
        if data.len() >= 4 {
            for i in 0..data.len() - 4 {
                if data[i..i + 4] == WATERMARK_MAGIC {
                    return WatermarkResult::mock_detected(0.99);
                }
            }
        }
        
        // Also detect based on high-frequency energy pattern
        // (simulates finding spread spectrum watermark)
        if data.len() >= 1024 {
            let high_byte_count = data[512..].iter().filter(|&&b| b > 200).count();
            let ratio = high_byte_count as f32 / (data.len() - 512) as f32;
            
            if ratio > 0.1 {
                return WatermarkResult::mock_detected(ratio.min(0.95));
            }
        }
        
        WatermarkResult::not_detected()
    }

    /// Detect in float samples by analyzing energy pattern
    fn detect_in_samples(samples: &[f32]) -> WatermarkResult {
        if samples.len() < MIN_SAMPLES {
            return WatermarkResult::not_detected();
        }
        
        // Look for characteristic high-frequency pattern
        let mut high_energy = 0.0f32;
        let mut total_energy = 0.0f32;
        
        for window in samples.windows(2) {
            let diff = (window[1] - window[0]).abs();
            high_energy += diff * diff;
            total_energy += window[0] * window[0];
        }
        
        let ratio = high_energy / (total_energy + 1e-10);
        
        // High ratio indicates high-frequency watermark
        if ratio > 0.3 {
            WatermarkResult::mock_detected((ratio * 2.0).min(0.95))
        } else {
            WatermarkResult::not_detected()
        }
    }
}

// =============================================================================
// Sonic Listener
// =============================================================================

/// Main listener object exposed via FFI
pub struct SonicListener {
    config: RwLock<SonicConfig>,
    state: RwLock<ListenerState>,
    is_running: AtomicBool,
    dsp_engine: RwLock<DspEngine>,
    callback: RwLock<Option<Arc<dyn WatermarkCallback>>>,
}

impl SonicListener {
    /// Create a new SonicListener with the given configuration
    pub fn new(config: SonicConfig) -> Result<Arc<Self>, SonicError> {
        config.validate()?;
        
        let dsp_engine = DspEngine::new(&config);
        
        Ok(Arc::new(Self {
            config: RwLock::new(config),
            state: RwLock::new(ListenerState::Idle),
            is_running: AtomicBool::new(false),
            dsp_engine: RwLock::new(dsp_engine),
            callback: RwLock::new(None),
        }))
    }

    /// Start listening for watermarks
    pub fn start_listening(
        self: &Arc<Self>,
        callback: Arc<dyn WatermarkCallback>,
    ) -> Result<(), SonicError> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(SonicError::ListenerAlreadyRunning);
        }

        // Store callback
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

    /// Process PCM audio buffer (16-bit signed, little-endian)
    pub fn process_buffer(&self, pcm_data: &[u8]) -> Result<WatermarkResult, SonicError> {
        if pcm_data.len() < MIN_SAMPLES * 2 {
            return Err(SonicError::BufferTooShort(MIN_SAMPLES * 2));
        }

        *self.state.write() = ListenerState::Processing;

        // Also run mock detector for magic byte detection
        let mock_result = MockDetector::detect_in_bytes(pcm_data);
        if mock_result.detected {
            self.emit_detection(&mock_result);
            return Ok(mock_result);
        }

        // Convert PCM bytes to float samples
        let samples: Vec<f32> = pcm_data
            .chunks_exact(2)
            .map(|chunk| {
                let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
                sample as f32 / 32768.0
            })
            .collect();

        self.process_samples(&samples)
    }

    /// Process float samples directly
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

        // Run mock detector first (for testing)
        let mock_result = MockDetector::detect_in_samples(samples);
        if mock_result.detected {
            self.emit_detection(&mock_result);
            return Ok(mock_result);
        }

        // Run DSP engine
        let result = self.dsp_engine.write().process(samples);
        
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
            self.dsp_engine.write().config.detection_threshold = threshold;
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
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
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

    struct TestCallback {
        detections: AtomicU32,
        levels: AtomicU32,
    }

    impl TestCallback {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                detections: AtomicU32::new(0),
                levels: AtomicU32::new(0),
            })
        }
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
        let listener = SonicListener::new(config).unwrap();
        let callback = TestCallback::new();
        
        assert!(listener.start_listening(callback.clone()).is_ok());
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

    #[test]
    fn test_mock_detection_magic_bytes() {
        // Create audio with magic bytes
        let mut data: Vec<u8> = vec![0u8; 2048];
        data[100..104].copy_from_slice(&WATERMARK_MAGIC);
        
        let result = MockDetector::detect_in_bytes(&data);
        assert!(result.detected);
        assert!(result.confidence > 0.9);
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
