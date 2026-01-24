# Vouch Sonic Core

Rust native library for real-time audio watermark detection on mobile devices.

## Overview

This crate provides the Vouch Sonic Engine - a high-performance audio processing library designed to detect cryptographic watermarks in audio streams in real-time.

## Features

- **Real-time watermark detection** using spread-spectrum correlation
- **Cross-platform** via UniFFI bindings (Swift/Kotlin)
- **Hardware-friendly** optimized for mobile CPUs
- **Thread-safe** with callback-based async API

## Building

### Prerequisites

- Rust 1.70+
- For iOS: Xcode with iOS SDK
- For Android: Android NDK

### Quick Start

```bash
# Run tests
./build.sh test

# Generate bindings (Swift + Kotlin)
./build.sh bindings

# Build for iOS
./build.sh ios

# Build for Android
./build.sh android

# Build everything
./build.sh all
```

### Installing Rust Targets

```bash
# iOS
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Android
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
```

## Usage

### From Rust

```rust
use vouch_sonic_core::*;

// Create configuration
let config = SonicConfig::default();

// Create listener
let listener = SonicListener::new(config)?;

// Process audio samples
let samples: Vec<f32> = get_audio_from_microphone();
let result = listener.process_samples(&samples)?;

if result.detected {
    println!("Watermark found!");
    println!("  Signer: {:?}", result.signer_did);
    println!("  Confidence: {:.1}%", result.confidence * 100.0);
}
```

### From Swift (iOS)

```swift
import VouchSonicCore

// Create listener
let config = SonicConfig(
    sampleRate: 16000,
    frameSizeMs: 50,
    detectionThreshold: 0.5,
    spreadingFactor: 100,
    enableChirpSync: true
)

let listener = try SonicListener(config: config)

// Implement callback
class MyCallback: WatermarkCallback {
    func onWatermarkDetected(result: WatermarkResult) {
        print("Detected: \(result.signerDid ?? "unknown")")
    }
    
    func onAudioLevelChanged(levelDb: Float) {
        // Update UI meter
    }
    
    func onError(message: String) {
        print("Error: \(message)")
    }
    
    func onStateChanged(state: ListenerState) {
        // Handle state change
    }
}

// Start listening
try listener.startListening(callback: MyCallback())
```

### From Kotlin (Android)

```kotlin
import com.vouch.sonic.core.*

// Create listener
val config = SonicConfig(
    sampleRate = 16000u,
    frameSizeMs = 50u,
    detectionThreshold = 0.5f,
    spreadingFactor = 100u,
    enableChirpSync = true
)

val listener = SonicListener(config)

// Implement callback
val callback = object : WatermarkCallback {
    override fun onWatermarkDetected(result: WatermarkResult) {
        Log.d("Vouch", "Detected: ${result.signerDid}")
    }
    
    override fun onAudioLevelChanged(levelDb: Float) {
        // Update UI meter
    }
    
    override fun onError(message: String) {
        Log.e("Vouch", message)
    }
    
    override fun onStateChanged(state: ListenerState) {
        // Handle state change
    }
}

// Start listening
listener.startListening(callback)
```

## API Reference

### SonicConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sample_rate` | u32 | 16000 | Audio sample rate in Hz |
| `frame_size_ms` | u32 | 50 | Processing frame size in ms |
| `detection_threshold` | f32 | 0.5 | Detection confidence threshold (0-1) |
| `spreading_factor` | u32 | 100 | Spread spectrum factor |
| `enable_chirp_sync` | bool | true | Enable chirp synchronization |

### WatermarkResult

| Field | Type | Description |
|-------|------|-------------|
| `detected` | bool | Whether watermark was detected |
| `confidence` | f32 | Detection confidence (0.0-1.0) |
| `signer_did` | String? | Signer's DID if extracted |
| `timestamp` | u64? | Unix timestamp when signed |
| `covenant_json` | String? | Usage policy as JSON |
| `audio_quality` | f32 | Estimated audio quality (0.0-1.0) |
| `detection_method` | String | Method used for detection |

### SonicListener Methods

- `new(config)` - Create new listener
- `start_listening(callback)` - Start with callback
- `stop_listening()` - Stop listening
- `process_buffer(pcm_data)` - Process PCM bytes
- `process_samples(samples)` - Process float samples
- `is_listening()` - Check if active
- `get_state()` - Get current state
- `set_detection_threshold(threshold)` - Update threshold

## Project Structure

```
mobile/core/
├── Cargo.toml           # Rust dependencies
├── build.rs             # Build script for UniFFI
├── build.sh             # Cross-compilation script
├── uniffi-bindgen.rs    # Binding generator CLI
├── src/
│   ├── lib.rs           # Main implementation
│   └── vouch_sonic_core.udl  # UniFFI interface definition
└── generated/           # Generated after build
    ├── ios/
    │   └── swift/       # Swift bindings
    └── android/
        ├── kotlin/      # Kotlin bindings
        └── jniLibs/     # Native libraries
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   React Native / Flutter                │
│                   (JavaScript / Dart)                   │
└────────────────────────┬────────────────────────────────┘
                         │ TurboModule / Platform Channel
┌────────────────────────┴────────────────────────────────┐
│              Swift (iOS) / Kotlin (Android)             │
│                   UniFFI Generated Bindings             │
└────────────────────────┬────────────────────────────────┘
                         │ FFI
┌────────────────────────┴────────────────────────────────┐
│                 vouch-sonic-core (Rust)                 │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐   │
│  │ SonicListener│  │  DspEngine  │  │ SignatureVerif│   │
│  │              │  │  (FFT, PN)  │  │     ier       │   │
│  └──────────────┘  └─────────────┘  └───────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## License

MIT License - See [LICENSE](../../LICENSE)
