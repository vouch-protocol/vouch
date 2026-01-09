# Vouch Mobile App

Cross-platform mobile app for Vouch Protocol media signing.

## Features

- 📱 **Capture-time Signing**: Sign photos at the moment of capture
- 🔐 **Device-level Attestation**: Uses Secure Enclave / Keystore
- 📷 **Camera Integration**: Direct camera access with EXIF preservation
- 🔗 **Chain of Trust**: Links to organization credentials

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | React Native + Expo |
| Crypto | vouch-protocol npm package |
| Camera | expo-camera |
| Storage | expo-secure-store |
| Sharing | expo-sharing |

## Folder Structure

```
expo-app/
├── App.tsx                 ← Entry point
├── src/
│   ├── camera/             ← Camera capture & signing
│   │   ├── CaptureScreen.tsx
│   │   └── SigningBridge.ts
│   ├── signing/            ← Core signing logic
│   │   ├── NativeSigner.ts
│   │   └── BadgeFactory.ts
│   ├── verify/             ← Verification UI
│   │   └── ScanScreen.tsx
│   └── identity/           ← DID management
│       └── KeyManager.ts
├── assets/
│   └── vouch-badge.png
└── package.json
```

## Quick Start

```bash
cd expo-app
npm install
npx expo start
```

## Integration with Python Library

The mobile app bridges to the Python `vouch-protocol` library via:

1. **NPM Package**: `@vouch-protocol/core` (TypeScript)
2. **REST API**: For server-side signing operations
3. **Direct Native**: For offline signing with device keys

## Related

- [Python Library](../vouch/) - Core signing logic
- [Browser Extension](../browser-extension/) - Web verification
- [TypeScript SDK](../typescript/) - Shared crypto
