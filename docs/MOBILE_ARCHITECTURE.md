# Vouch Mobile App Architecture

**Document:** MOBILE_ARCHITECTURE.md  
**Version:** 1.0  
**Date:** January 20, 2026  
**Author:** Ramprasad Anandam Gaddam  

---

## 1. Executive Summary

This document specifies the technical architecture for the **Vouch Verifier** mobile application, a cross-platform (iOS/Android) app that functions as:

1. **"Shazam for Deepfakes"**: Real-time audio watermark detection using the Vouch Sonic protocol
2. **Remote Signer**: Hardware-secured signing for desktop Vouch Bridge via QR-linked secure channel
3. **Identity Vault**: Device-local key management using Secure Enclave/Keystore

The architecture prioritizes:
- **Performance**: Native Rust core for real-time signal processing
- **Security**: Hardware-backed key storage, biometric authentication
- **User Experience**: Seamless desktop-mobile integration

---

## 2. Tech Stack Recommendation

### 2.1 Framework Selection: React Native + Rust

| Consideration | React Native + Rust | Flutter + Rust | Native Swift/Kotlin |
|---------------|---------------------|----------------|---------------------|
| **UI Development Speed** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| **Native Performance** | ⭐⭐⭐⭐ (via Rust FFI) | ⭐⭐⭐⭐ (via Rust FFI) | ⭐⭐⭐⭐⭐ |
| **Audio Processing** | ⭐⭐⭐⭐⭐ (Rust core) | ⭐⭐⭐⭐⭐ (Rust core) | ⭐⭐⭐⭐ |
| **Secure Enclave Access** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Ecosystem/Libraries** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Maintenance** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ (2 codebases) |

**Recommendation: React Native with Expo + Rust Native Modules**

**Rationale:**
- React Native provides excellent cross-platform UI with native feel
- Expo's new architecture (TurboModules) enables efficient native module integration
- Rust core handles performance-critical audio processing off the JS thread
- uniffi-rs generates type-safe bindings for both iOS (Swift) and Android (Kotlin)
- Strong ecosystem for WebSocket, QR scanning, and biometrics

### 2.2 Complete Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                         │
│                    React Native + Expo                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Home/Scan  │  │   Verify    │  │    Settings/Identity    │  │
│  │   Screen    │  │   Screen    │  │        Screen           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                       BRIDGE LAYER                              │
│                TurboModules / JSI Bindings                      │
│  ┌───────────────────┐  ┌──────────────────────────────────┐    │
│  │  VouchSonicModule │  │     VouchSecurityModule          │    │
│  │   (Audio FFI)     │  │  (Secure Enclave/Keystore FFI)   │    │
│  └───────────────────┘  └──────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                      NATIVE CORE LAYER                          │
│                        Rust (uniffi-rs)                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ vouch_sonic_ffi │  │  vouch_crypto   │  │ vouch_protocol  │  │
│  │ (DSP/Watermark) │  │  (Ed25519/ECDH) │  │  (Bridge Comm)  │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      PLATFORM LAYER                             │
│  ┌─────────────────────────┐  ┌────────────────────────────┐    │
│  │      iOS Platform       │  │     Android Platform       │    │
│  │  • Secure Enclave       │  │  • Android Keystore        │    │
│  │  • AVAudioEngine        │  │  • AudioRecord (AAudio)    │    │
│  │  • LocalAuthentication  │  │  • BiometricPrompt         │    │
│  └─────────────────────────┘  └────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Architecture

### 3.1 Vouch Sonic Engine (Rust Core)

The heart of the app: real-time audio watermark detection running native.

```rust
// vouch_sonic_ffi/src/lib.rs

use uniffi::*;

/// Configuration for the Sonic Listener
#[derive(uniffi::Record)]
pub struct SonicConfig {
    pub sample_rate: u32,           // Default: 16000
    pub frame_size_ms: u32,         // Default: 50ms
    pub detection_threshold: f32,   // Default: 0.5
    pub spreading_factor: u32,      // Default: 100
}

/// Result from watermark detection
#[derive(uniffi::Record)]
pub struct WatermarkPayload {
    pub detected: bool,
    pub confidence: f32,
    pub signer_did: Option<String>,
    pub timestamp: Option<u64>,
    pub covenant: Option<String>,
    pub audio_hash: String,
}

/// Error types
#[derive(uniffi::Error, Debug)]
pub enum SonicError {
    AudioInitFailed { message: String },
    ProcessingFailed { message: String },
    InvalidConfig { message: String },
}

/// Callback trait for detection events
#[uniffi::export(callback_interface)]
pub trait WatermarkCallback: Send + Sync {
    fn on_watermark_detected(&self, payload: WatermarkPayload);
    fn on_detection_error(&self, error: String);
    fn on_audio_level_changed(&self, level_db: f32);
}

/// The Sonic Listener - runs in native thread
#[derive(uniffi::Object)]
pub struct SonicListener {
    config: SonicConfig,
    is_running: std::sync::atomic::AtomicBool,
    // Internal DSP state
}

#[uniffi::export]
impl SonicListener {
    #[uniffi::constructor]
    pub fn new(config: SonicConfig) -> Result<Self, SonicError> {
        Ok(Self {
            config,
            is_running: std::sync::atomic::AtomicBool::new(false),
        })
    }
    
    /// Start listening for watermarks
    pub fn start(&self, callback: Box<dyn WatermarkCallback>) -> Result<(), SonicError>;
    
    /// Stop listening
    pub fn stop(&self) -> Result<(), SonicError>;
    
    /// Process a single audio buffer (for testing)
    pub fn process_buffer(&self, samples: Vec<f32>) -> Result<WatermarkPayload, SonicError>;
    
    /// Check if currently listening
    pub fn is_listening(&self) -> bool;
}
```

**DSP Pipeline (Rust internals):**

```
Audio Input → Resample (16kHz) → Frame Buffer (50ms)
    ↓
FFT Analysis → Chirp Sync Detection → PN Correlation
    ↓
Bit Extraction → ECC Decode → Signature Verify
    ↓
Callback: onWatermarkDetected(payload)
```

### 3.2 Identity Vault (Secure Key Management)

Hardware-backed key storage using Secure Enclave (iOS) / Keystore (Android).

```typescript
// src/native/VouchSecurityModule.ts

export interface KeyPair {
  publicKey: string;        // Base64 encoded
  keyId: string;            // UUID for reference
  createdAt: number;        // Unix timestamp
  algorithm: 'Ed25519' | 'P256';
}

export interface SignatureRequest {
  keyId: string;
  dataHash: string;         // SHA-256 of data to sign
  purpose: string;          // Display to user
  requireBiometric: boolean;
}

export interface VouchSecurityModule {
  /**
   * Generate a new Ed25519 keypair in Secure Enclave/Keystore.
   * Private key NEVER leaves the hardware security module.
   */
  generateKeyPair(): Promise<KeyPair>;
  
  /**
   * Sign data hash using hardware-secured private key.
   * Prompts for FaceID/TouchID/Fingerprint if required.
   */
  sign(request: SignatureRequest): Promise<string>;  // Base64 signature
  
  /**
   * Get public key for export/sharing.
   */
  getPublicKey(keyId: string): Promise<string>;
  
  /**
   * Delete a keypair (cannot be recovered).
   */
  deleteKeyPair(keyId: string): Promise<void>;
  
  /**
   * Check if biometric authentication is available.
   */
  isBiometricAvailable(): Promise<{
    available: boolean;
    biometryType: 'FaceID' | 'TouchID' | 'Fingerprint' | 'None';
  }>;
  
  /**
   * Get DID document for the device identity.
   */
  getDeviceDID(): Promise<string>;
}
```

**Platform Implementation:**

| Feature | iOS Implementation | Android Implementation |
|---------|-------------------|------------------------|
| Key Storage | Secure Enclave via `kSecAttrAccessGroup` | Android Keystore with `setIsStrongBoxBacked(true)` |
| Key Generation | `SecKeyCreateRandomKey` with `.privateKeyUsage` | `KeyPairGenerator` with `PURPOSE_SIGN` |
| Signing | `SecKeyCreateSignature` | `Signature.getInstance("Ed25519")` |
| Biometrics | `LAContext` with `evaluatePolicy` | `BiometricPrompt` with `CryptoObject` |
| Key Protection | `.biometryCurrentSet` + `.userPresence` | `setUserAuthenticationRequired(true)` |

### 3.3 Remote Bridge Protocol

Desktop ↔ Mobile secure communication for remote signing.

```
┌─────────────────┐                              ┌─────────────────┐
│  Desktop Bridge │                              │   Mobile App    │
│  (Port 21000)   │                              │ (Vouch Verifier)│
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  1. Generate session QR code                   │
         │  ┌─────────────────────────────────┐           │
         │  │ {                               │           │
         │  │   "bridge_id": "xxx",           │           │
         │  │   "session_nonce": "yyy",       │           │
         │  │   "ws_endpoint": "wss://...",   │           │
         │  │   "public_key": "zzz"           │           │
         │  │ }                               │           │
         │  └─────────────────────────────────┘           │
         │                                                │
         │←────────── 2. Mobile scans QR ─────────────────│
         │                                                │
         │←─── 3. WebSocket TLS connect ──────────────────│
         │     (Mutual authentication via DID exchange)   │
         │                                                │
         │←─── 4. ECDH key exchange ──────────────────────│
         │     (Session encryption established)           │
         │                                                │
         │                                                │
         ├──────────────────────────────────────────────►│
         │  5. Sign Request                               │
         │  {                                             │
         │    "type": "sign_request",                     │
         │    "hash": "sha256:abc...",                    │
         │    "content_preview": "Signing: photo.jpg",    │
         │    "covenant": {...},                          │
         │    "request_id": "req_123"                     │
         │  }                                             │
         │                                                │
         │                 6. Phone shows FaceID prompt   │
         │                    "Sign 'photo.jpg'?"         │
         │                                                │
         │←────────────────────────────────────────────────
         │  7. Sign Response                              │
         │  {                                             │
         │    "type": "sign_response",                    │
         │    "request_id": "req_123",                    │
         │    "signature": "base64...",                   │
         │    "public_key": "base64...",                  │
         │    "approved": true                            │
         │  }                                             │
         │                                                │
```

**Protocol Messages (TypeScript types):**

```typescript
// Bridge Protocol Messages

interface BridgeHandshake {
  type: 'handshake';
  version: '1.0';
  device_did: string;
  public_key: string;      // For ECDH
  capabilities: string[];  // ['sign', 'verify', 'sonic']
}

interface SignRequest {
  type: 'sign_request';
  request_id: string;
  hash: string;            // sha256:hex
  content_preview: string; // Human-readable description
  content_type: string;    // MIME type
  file_name?: string;
  covenant?: VouchCovenant;
  timeout_ms: number;      // Request expires after
}

interface SignResponse {
  type: 'sign_response';
  request_id: string;
  approved: boolean;
  signature?: string;      // Base64 Ed25519 signature
  public_key?: string;     // Signer's public key
  error?: string;
}

interface PingPong {
  type: 'ping' | 'pong';
  timestamp: number;
}

interface SessionEnd {
  type: 'session_end';
  reason: 'user_disconnect' | 'timeout' | 'error';
}
```

---

## 4. Data Flow Diagrams

### 4.1 Sonic Detection Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                         MOBILE DEVICE                            │
│                                                                  │
│  ┌─────────────┐    ┌──────────────────────────────────────────┐ │
│  │ Microphone  │───►│           RUST NATIVE THREAD             │ │
│  │ (16kHz)     │    │                                          │ │
│  └─────────────┘    │  1. Audio Buffer Accumulator             │ │
│                     │         ↓                                │ │
│                     │  2. FFT (50ms frames)                    │ │
│                     │         ↓                                │ │
│                     │  3. Chirp Sync Marker Detection          │ │
│                     │         ↓                                │ │
│                     │  4. PN Sequence Correlation              │ │
│                     │         ↓                                │ │
│                     │  5. Bit Extraction + ECC                 │ │
│                     │         ↓                                │ │
│                     │  6. Payload Decode (JSON)                │ │
│                     │         ↓                                │ │
│                     │  7. Ed25519 Signature Verify             │ │
│                     └──────────────────────────────────────────┘ │
│                                │                                 │
│                                ▼                                 │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │                    REACT NATIVE (JS Thread)                  ││
│  │                                                              ││
│  │  onWatermarkDetected(payload) → Update UI State             ││
│  │                                                              ││
│  │  ┌────────────────────────────────────────────────────────┐  ││
│  │  │                    RESULT MODAL                        │  ││
│  │  │                                                        │  ││
│  │  │    ✅ VERIFIED AUDIO                                   │  ││
│  │  │                                                        │  ││
│  │  │    Signed by: did:key:z6Mk...                          │  ││
│  │  │    Date: 2026-01-20 06:45:00                           │  ││
│  │  │    Confidence: 98.2%                                   │  ││
│  │  │                                                        │  ││
│  │  │    📜 Covenant: AI Training DENIED                     │  ││
│  │  │                                                        │  ││
│  │  └────────────────────────────────────────────────────────┘  ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Remote Signing Flow

```
┌─────────────────────────────┐         ┌─────────────────────────────┐
│      DESKTOP (macOS)        │         │      MOBILE (iPhone)        │
│                             │         │                             │
│  vouch-bridge daemon        │         │  Vouch Verifier App         │
│                             │         │                             │
│  ┌───────────────────────┐  │         │  ┌───────────────────────┐  │
│  │ User: vouch sign x.jpg│  │         │  │   Paired Mode Active  │  │
│  └───────────┬───────────┘  │         │  │    🔗 Connected       │  │
│              │              │         │  └───────────────────────┘  │
│              ▼              │         │                             │
│  ┌───────────────────────┐  │   WSS   │  ┌───────────────────────┐  │
│  │ Sign Request Created  │──┼────────►│──│ Push Notification +   │  │
│  │                       │  │         │  │ In-app Alert          │  │
│  │ Waiting for mobile... │  │         │  └───────────┬───────────┘  │
│  └───────────────────────┘  │         │              │              │
│                             │         │              ▼              │
│                             │         │  ┌───────────────────────┐  │
│                             │         │  │   SIGNING REQUEST     │  │
│                             │         │  │                       │  │
│                             │         │  │  📄 photo.jpg         │  │
│                             │         │  │  Size: 2.3 MB         │  │
│                             │         │  │                       │  │
│                             │         │  │  [Decline] [Approve]  │  │
│                             │         │  └───────────┬───────────┘  │
│                             │         │              │              │
│                             │         │              ▼ (Approve)    │
│                             │         │  ┌───────────────────────┐  │
│                             │         │  │       FACE ID         │  │
│                             │         │  │                       │  │
│                             │         │  │     [Biometric]       │  │
│                             │         │  └───────────┬───────────┘  │
│                             │         │              │              │
│                             │         │              ▼ (Success)    │
│  ┌───────────────────────┐  │   WSS   │  ┌───────────────────────┐  │
│  │ Signature Received!   │◄─┼─────────┼──│ Sign with Secure     │  │
│  │                       │  │         │  │ Enclave Private Key  │  │
│  │ ✅ x_signed.jpg saved │  │         │  │                       │  │
│  └───────────────────────┘  │         │  │ signature → Desktop  │  │
│                             │         │  └───────────────────────┘  │
└─────────────────────────────┘         └─────────────────────────────┘
```

---

## 5. Security Considerations

### 5.1 Key Security

| Threat | Mitigation |
|--------|------------|
| Key extraction | Hardware-backed storage (Secure Enclave/StrongBox) |
| Unauthorized signing | Biometric authentication required for every sign operation |
| Key cloning | Private keys are non-exportable by design |
| Device loss | Remote wipe via MDM + key is protected by device unlock |
| Man-in-the-middle | TLS 1.3 + ECDH session encryption + DID verification |

### 5.2 Bridge Security

| Threat | Mitigation |
|--------|------------|
| QR code interception | Session nonce + short expiry (5 minutes) |
| Replay attacks | Request IDs + timestamps + nonce |
| Session hijacking | Mutual DID authentication + session binding |
| Malicious requests | Human-readable preview + consent UI |
| Channel eavesdropping | End-to-end encryption with ECDH-derived keys |

### 5.3 Audio Security

| Threat | Mitigation |
|--------|------------|
| Fake watermark injection | Cryptographic signature verification |
| Watermark removal | Alerts user if audio quality suggests tampering |
| Privacy (mic access) | Clear permission requests + indicator when listening |
| Background recording | Only processes for watermark, doesn't store audio |

### 5.4 Secure Storage Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVICE STORAGE MODEL                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HARDWARE SECURITY MODULE (Secure Enclave / StrongBox)          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Ed25519 Private Key (NEVER LEAVES HERE)                  │  │
│  │  • Generated inside hardware                              │  │
│  │  • Operations performed inside hardware                   │  │
│  │  • Bound to device passcode + biometric                   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ENCRYPTED KEYCHAIN / KEYSTORE                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  • Public Key (for sharing)                               │  │
│  │  • DID Document (cached)                                  │  │
│  │  • Paired Bridges list (bridge_id, timestamp)             │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  APP SANDBOX (Encrypted at rest)                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  • Verification history (last 100)                        │  │
│  │  • App settings (non-sensitive)                           │  │
│  │  • Cached manifests (for offline verify)                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Screen Specifications

### 6.1 Home Screen (Sonic Listener)

```
┌─────────────────────────────────────┐
│ ← Vouch Verifier           ⚙️  🔗   │
├─────────────────────────────────────┤
│                                     │
│            ┌─────────┐              │
│            │         │              │
│            │  🎤📊   │              │
│            │         │              │
│            │ -42 dB  │              │
│            └─────────┘              │
│                                     │
│        [ 🔴 Stop Listening ]        │
│                                     │
│   ─────────────────────────────     │
│                                     │
│   RECENT VERIFICATIONS              │
│                                     │
│   ┌─────────────────────────────┐   │
│   │ ✅ Podcast Ep.42            │   │
│   │    10 min ago • 98% match   │   │
│   └─────────────────────────────┘   │
│                                     │
│   ┌─────────────────────────────┐   │
│   │ ⚠️ Unknown Audio            │   │
│   │    1 hour ago • No watermark│   │
│   └─────────────────────────────┘   │
│                                     │
├─────────────────────────────────────┤
│  🎤 Listen    📄 Verify    👤 ID   │
└─────────────────────────────────────┘
```

### 6.2 Remote Bridge Pairing

```
┌─────────────────────────────────────┐
│ ← Pair with Desktop                 │
├─────────────────────────────────────┤
│                                     │
│   Scan the QR code shown by         │
│   Vouch Bridge on your computer     │
│                                     │
│   ┌─────────────────────────────┐   │
│   │                             │   │
│   │      [ CAMERA VIEWFINDER ]  │   │
│   │                             │   │
│   │         ┌───────┐           │   │
│   │         │ ░░░░░ │           │   │
│   │         │ ░░░░░ │           │   │
│   │         │ ░░░░░ │           │   │
│   │         └───────┘           │   │
│   │                             │   │
│   └─────────────────────────────┘   │
│                                     │
│   🔒 This creates a secure link     │
│   between your phone and computer.  │
│                                     │
│   PAIRED DEVICES                    │
│   ┌─────────────────────────────┐   │
│   │ 💻 MacBook Pro              │   │
│   │    Paired Jan 20 • Active   │   │
│   │              [ Disconnect ] │   │
│   └─────────────────────────────┘   │
│                                     │
└─────────────────────────────────────┘
```

### 6.3 Signing Request Modal

```
┌─────────────────────────────────────┐
│                                     │
│   ┌─────────────────────────────┐   │
│   │                             │   │
│   │     💻 MacBook Pro          │   │
│   │     wants you to sign       │   │
│   │                             │   │
│   │   ┌───────────────────────┐ │   │
│   │   │  📄  contract.pdf     │ │   │
│   │   │                       │ │   │
│   │   │  Size: 245 KB         │ │   │
│   │   │  Hash: a1b2c3d4...    │ │   │
│   │   └───────────────────────┘ │   │
│   │                             │   │
│   │   📜 COVENANT               │   │
│   │   • AI Training: DENY       │   │
│   │   • Derivatives: ALLOW      │   │
│   │                             │   │
│   └─────────────────────────────┘   │
│                                     │
│   ┌─────────────┐ ┌─────────────┐   │
│   │   Decline   │ │   Approve   │   │
│   │             │ │   (FaceID)  │   │
│   └─────────────┘ └─────────────┘   │
│                                     │
└─────────────────────────────────────┘
```

---

## 7. Project Structure

```
vouch-mobile/
├── app/                           # React Native / Expo app
│   ├── src/
│   │   ├── screens/
│   │   │   ├── HomeScreen.tsx
│   │   │   ├── VerifyScreen.tsx
│   │   │   ├── PairScreen.tsx
│   │   │   └── IdentityScreen.tsx
│   │   ├── components/
│   │   │   ├── SonicIndicator.tsx
│   │   │   ├── WatermarkResult.tsx
│   │   │   ├── SignRequestModal.tsx
│   │   │   └── QRScanner.tsx
│   │   ├── hooks/
│   │   │   ├── useSonicListener.ts
│   │   │   ├── useBridgeConnection.ts
│   │   │   └── useIdentity.ts
│   │   ├── native/
│   │   │   ├── VouchSonicModule.ts
│   │   │   └── VouchSecurityModule.ts
│   │   └── services/
│   │       ├── BridgeProtocol.ts
│   │       └── NotificationService.ts
│   ├── ios/
│   │   └── VouchVerifier/
│   │       ├── VouchSonicBridge.swift
│   │       └── VouchSecurityBridge.swift
│   ├── android/
│   │   └── app/src/main/java/com/vouch/
│   │       ├── VouchSonicModule.kt
│   │       └── VouchSecurityModule.kt
│   └── app.json                   # Expo config
│
├── rust/                          # Rust native core
│   ├── vouch-sonic-ffi/
│   │   ├── src/
│   │   │   ├── lib.rs             # uniffi exports
│   │   │   ├── dsp.rs             # DSP algorithms
│   │   │   ├── watermark.rs       # Detection logic
│   │   │   └── fft.rs             # FFT implementation
│   │   ├── Cargo.toml
│   │   └── uniffi.toml
│   │
│   ├── vouch-crypto/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── ed25519.rs
│   │   │   └── ecdh.rs
│   │   └── Cargo.toml
│   │
│   └── vouch-protocol/
│       ├── src/
│       │   ├── lib.rs
│       │   ├── bridge.rs          # WebSocket protocol
│       │   └── messages.rs        # Message types
│       └── Cargo.toml
│
├── Makefile                       # Build automation
├── MOBILE_ARCHITECTURE.md         # This document
└── README.md
```

---

## 8. Build & Deployment

### 8.1 Build Pipeline

```bash
# 1. Build Rust core for all platforms
cd rust/vouch-sonic-ffi
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-linux-android

# 2. Generate bindings
uniffi-bindgen generate src/lib.rs --language swift --out-dir ../generated/ios
uniffi-bindgen generate src/lib.rs --language kotlin --out-dir ../generated/android

# 3. Build React Native app
cd ../../app
npx expo prebuild
npx expo build:ios
npx expo build:android
```

### 8.2 Distribution

| Platform | Distribution Method |
|----------|---------------------|
| iOS | TestFlight → App Store |
| Android | Google Play Internal Testing → Production |
| Enterprise | MDM distribution (optional) |

---

## 9. Performance Requirements

| Metric | Target | Measurement |
|--------|--------|-------------|
| Watermark detection latency | < 200ms | From audio frame to callback |
| Signing response time | < 500ms | From biometric success to signature |
| Battery impact (listening) | < 5% per hour | Background audio processing |
| Memory footprint | < 100MB | Runtime heap usage |
| App cold start | < 1s | To interactive UI |

---

## 10. Dependencies

### 10.1 Rust Crates

```toml
[dependencies]
uniffi = "0.27"
rustfft = "6.0"           # FFT for spectral analysis
ed25519-dalek = "2.0"     # Ed25519 signatures
x25519-dalek = "2.0"      # ECDH key exchange
sha2 = "0.10"             # SHA-256 hashing
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["rt", "sync"] }
```

### 10.2 React Native Packages

```json
{
  "dependencies": {
    "expo": "~50.0.0",
    "expo-camera": "~14.0.0",
    "expo-local-authentication": "~13.0.0",
    "expo-secure-store": "~12.0.0",
    "react-native-webview": "^13.0.0",
    "@react-native-community/netinfo": "^9.0.0",
    "react-native-vision-camera": "^3.0.0"
  }
}
```

---

## 11. API Reference

### 11.1 Rust FFI (exported via uniffi)

```rust
// Core functions exposed to mobile platforms

// Sonic Listener
fn sonic_listener_new(config: SonicConfig) -> Result<SonicListener, SonicError>;
fn sonic_listener_start(listener: &SonicListener, callback: Box<dyn WatermarkCallback>);
fn sonic_listener_stop(listener: &SonicListener);
fn sonic_listener_process_buffer(listener: &SonicListener, samples: Vec<f32>) -> WatermarkPayload;

// Verification
fn verify_c2pa_manifest(file_data: Vec<u8>) -> Result<ManifestInfo, VerifyError>;
fn verify_watermark_payload(payload: &WatermarkPayload) -> bool;

// Protocol
fn create_bridge_session(qr_data: String) -> Result<BridgeSession, BridgeError>;
fn send_sign_response(session: &BridgeSession, response: SignResponse);
```

---

## 12. Next Steps

1. **Phase 1 (Week 1-2)**: Set up React Native + Expo project, Rust workspace
2. **Phase 2 (Week 3-4)**: Implement Rust DSP core with uniffi bindings
3. **Phase 3 (Week 5-6)**: iOS/Android native module integration
4. **Phase 4 (Week 7-8)**: Remote Bridge protocol implementation
5. **Phase 5 (Week 9-10)**: UI polish, testing, App Store submission

---

## 13. References

- [uniffi-rs Documentation](https://mozilla.github.io/uniffi-rs/)
- [Apple Secure Enclave Guide](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave)
- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [React Native New Architecture](https://reactnative.dev/docs/the-new-architecture/landing-page)
- [Vouch Protocol PAD-013 (AirGap)](../disclosures/PAD-013-vouch-airgap.md)
- [Vouch Protocol PAD-014 (Sonic)](../disclosures/PAD-014-vouch-sonic.md)
