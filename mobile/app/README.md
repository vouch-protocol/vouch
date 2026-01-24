# Vouch Verifier - Mobile App

React Native (Expo) mobile app for audio watermark detection and remote signing.

## Features

- 🎙️ **Verify Audio** - Real-time watermark detection using Vouch Sonic
- 🔗 **Pair with Desktop** - QR-based secure connection to Vouch Bridge
- 🔐 **Identity Vault** - Hardware-backed keys (Secure Enclave/Keystore)
- 👻 **Ghost Signatures** - Delegated agent identities

## Project Structure

```
mobile/app/
├── src/
│   ├── app/                    # Expo Router screens
│   │   ├── _layout.tsx         # Root navigation layout
│   │   ├── index.tsx           # Home screen
│   │   ├── verify.tsx          # Audio verification
│   │   ├── pair.tsx            # Desktop pairing
│   │   └── identity.tsx        # Identity management
│   ├── services/
│   │   └── IdentityService.ts  # Hardware key management
│   └── native/
│       └── VouchSonicBridge.ts # Rust FFI bridge
├── package.json
├── app.json                    # Expo configuration
├── tsconfig.json
└── babel.config.js
```

## Getting Started

### Prerequisites

- Node.js 18+
- Expo CLI (`npm install -g expo-cli`)
- iOS: Xcode 15+ (for iOS development)
- Android: Android Studio (for Android development)

### Installation

```bash
cd mobile/app

# Install dependencies
npm install

# Start development server
npm start

# Run on iOS simulator
npm run ios

# Run on Android emulator
npm run android
```

### Building the Native Modules

Before running on a real device, build the Rust core:

```bash
cd ../core
./build.sh bindings  # Generate Swift/Kotlin bindings
./build.sh ios       # Build for iOS
./build.sh android   # Build for Android
```

## Key Components

### IdentityService

Hardware-backed cryptographic identity management:

```typescript
import { identityService, generateHardwareKey, signPayload } from '@/services/IdentityService';

// Initialize
await identityService.initialize();

// Check biometric capability
const bio = await identityService.checkBiometricCapability();
// { available: true, biometryType: 'FaceID', level: 'strong' }

// Generate hardware-backed key (triggers biometric prompt)
const keyPair = await generateHardwareKey({ name: 'My Key', type: 'root' });

// Sign with biometric auth
const result = await signPayload('data to sign');
// { success: true, signature: 'base64...', keyId: '...' }
```

### VouchSonicBridge

Interface to the Rust Sonic Core:

```typescript
import SonicListener from '@/native/VouchSonicBridge';

const listener = new SonicListener({
  sampleRate: 16000,
  detectionThreshold: 0.5,
});

await listener.start({
  onWatermarkDetected: (result) => {
    console.log('Detected:', result.signerDid);
    console.log('Confidence:', result.confidence);
  },
  onAudioLevelChanged: (levelDb) => {
    // Update UI meter
  },
});

// Later...
await listener.stop();
```

## Screens

### Home Screen (`index.tsx`)

- Setup identity if not exists
- Two main action buttons: Verify Audio, Pair with Desktop
- Shows current identity status
- Biometric and Sonic engine status

### Verify Screen (`verify.tsx`)

- Audio level visualizer
- Start/Stop listening controls
- Detection result display with covenant info
- Verification history (last 10)

### Pair Screen (`pair.tsx`)

- Camera QR scanner for bridge pairing
- Paired devices list
- Connection instructions

### Identity Screen (`identity.tsx`)

- DID display (tap to copy)
- Biometric security info
- Key management (root + agent keys)
- Export public key

## Configuration

### iOS Permissions (app.json)

- `NSMicrophoneUsageDescription` - For audio watermark detection
- `NSCameraUsageDescription` - For QR code scanning
- `NSFaceIDUsageDescription` - For biometric signing

### Android Permissions

- `RECORD_AUDIO` - For audio capture
- `CAMERA` - For QR scanning
- `USE_BIOMETRIC` / `USE_FINGERPRINT` - For signing

## Development

### Path Aliases

Configured in `tsconfig.json` and `babel.config.js`:

- `@/` → `./src/`
- `@components/` → `./src/components/`
- `@services/` → `./src/services/`
- `@native/` → `./src/native/`

### Testing

```bash
npm test
```

## Native Module Integration

The Rust Sonic Core is integrated via native modules:

1. **iOS**: Swift bindings from UniFFI in `ios/VouchSonicBridge.swift`
2. **Android**: Kotlin bindings in `android/app/src/main/java/com/vouch/`

When the native module is not available (development mode), the bridge falls back to a mock implementation for testing.

## Security

- Private keys are stored in Secure Enclave (iOS) / StrongBox Keystore (Android)
- Keys never leave the device
- All signing operations require biometric authentication
- WebSocket connections use TLS + ECDH session encryption

## License

MIT
