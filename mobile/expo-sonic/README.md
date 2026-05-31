# @vouch-protocol-official/expo-sonic

Expo native module that bridges React Native to the **Vouch Sonic Core**
(Rust, via UniFFI) for **real on-device** audio-watermark detection and
Ed25519 signature verification. Replaces hand-rolled / mocked `SonicBridge`
implementations with the actual DSP core.

- New-Architecture compatible (Expo SDK 54 / RN 0.81+, `expo-modules-core` 3.x).
- Registered as the native module **`VouchSonicCore`**.
- **Android + iOS** native bridges (both compile the Rust core from source on
  the build machine / EAS workers — see *Building the native binaries*).

## Install

```bash
npx expo install @vouch-protocol-official/expo-sonic
```

Add the config plugin (ensures `RECORD_AUDIO`) to `app.json`:

```json
{ "expo": { "plugins": ["@vouch-protocol-official/expo-sonic"] } }
```

This module requires custom native code, so it runs in a **dev client** or a
**production build** — not in Expo Go. In Expo Go the native module is absent
and `isSonicAvailable()` returns `false`.

## Usage (drop-in `SonicListener`)

```ts
import { SonicListener, isSonicAvailable, verifySignature } from '@vouch-protocol-official/expo-sonic';

if (isSonicAvailable()) {
  const listener = new SonicListener({ sampleRate: 16000, detectionThreshold: 0.5 });
  await listener.start({
    onWatermarkDetected: (r) => console.log('signer:', r.signerDid, r.detectionMethod),
    onStateChanged: (s) => console.log('state:', s),
  });
  // Or feed PCM yourself (base64 of 16-bit LE mono):
  const result = await listener.processBuffer(pcmBase64);
  listener.dispose();
}
```

### Migrating the mobile host app's `SonicBridge.ts`

The native contract is identical (`createListener`/`startListening`/
`processBuffer`/events…), so the change is small:

```diff
- import { NativeModules, NativeEventEmitter } from "react-native";
- const { VouchSonicCore } = NativeModules;
- const eventEmitter = new NativeEventEmitter(NativeModules.VouchSonicCore);
+ import { SonicListener, isSonicAvailable } from "@vouch-protocol-official/expo-sonic";
```

Then delete the `mockDetection()` path and use the exported `SonicListener`
directly (it already exposes `start`/`stop`/`processBuffer`/`processSamples`/
`setDetectionThreshold`/`getConfig`/`dispose` with the same shapes). The
expo-av microphone-capture fallback can stay in the app layer if you still
want it for Expo Go.

## Building the native binaries

The Rust core is compiled to per-ABI `.so` during the Android build via
**cargo-ndk** (the crate source is vendored at `rust/`). The build machine
(your laptop or EAS) needs:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android
cargo install cargo-ndk
# plus the Android NDK (ANDROID_NDK_HOME)
```

On **EAS**, install these in an `eas-build-pre-install` hook in the app's
`package.json` (so EAS workers have the Rust toolchain before Gradle runs).
If you instead vendor prebuilt `.so` files into
`android/src/main/jniLibs/<abi>/`, pass `-Pvouch.skipRustBuild=true` to skip
the cargo step.

## Status / roadmap

- ✅ Android module (Kotlin bridge over UniFFI), config plugin, cargo-ndk wiring.
- ✅ TypeScript API (type-checked against expo-modules-core 3.0.29).
- ✅ iOS module (Swift bridge over UniFFI) + `VouchSonicCore.podspec` that
  compiles the Rust core per-triple (`aarch64-apple-ios` / `-sim`) in a
  `before_compile` script phase on the EAS macOS worker. iOS workers need the
  Rust toolchain + targets (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim`),
  same `eas-build-pre-install` pattern as Android.
- ⚠️ **Validation:** neither the Android (Gradle/cargo-ndk) nor iOS
  (podspec/cargo) native path has been compiled in a real EAS build from this
  environment (no Android NDK, no macOS here). Exercise both in dev-client
  builds before production.

## Note on detection vs. web embedding

This core's `detect_watermark` uses a spread-spectrum/chirp scheme. The web
watermark **embedder** (`@vouch-protocol-official/sonic-wasm`) uses a
multi-layer 4-band + Barker-13 scheme. Cross-surface detection (mobile
detecting a web-embedded mark) requires the two schemes to match; confirm
parameters before relying on web→mobile interop.

## License

Apache-2.0. See [LICENSE](./LICENSE).
