# VouchCore (Swift SDK)

The Swift SDK for the Vouch Protocol (#32). A thin, idiomatic layer over the
UniFFI bindings to the canonical Rust core (`vouch-core`), so iOS and macOS apps
verify credentials with the exact same bytes as the TypeScript, Python, Go, JVM,
and .NET SDKs. Apache-2.0.

## What you get

- JCS canonicalization, Ed25519, did:key/multikey
- Data Integrity proofs (`eddsa-jcs-2022`): sign + verify, with validity-window checks
- Post-quantum: ML-DSA-44 and dual proofs (Ed25519 + ML-DSA), plus composite verify
- BitstringStatusList revocation checks

## Build

The native core ships as an XCFramework. Build it once on macOS (needs Xcode and
the Rust toolchain):

```
./build-xcframework.sh     # -> Frameworks/vouch_coreFFI.xcframework
swift test                 # runs the XCTest suite
```

`build-xcframework.sh` compiles the Rust core for iOS device, iOS simulator
(arm64 + x86_64), and macOS (arm64 + x86_64), regenerates the UniFFI Swift
binding, and assembles the XCFramework.

For an EAS / CI build that produces an iOS app, add a pre-install step that
installs the Rust toolchain and the Apple targets (the same pattern the
`expo-sonic` package documents):

```
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

## Use (Swift Package Manager)

```swift
.package(path: "../vouch-protocol/sdks/swift")   // or a tagged URL once published
```

```swift
import VouchCore

let kp = try Vouch.generateEd25519()
let signed = try Vouch.signCredential(
    credentialJson,
    seed: kp.seed,
    verificationMethod: kp.didKey + "#key-1",
    created: "2026-04-26T10:00:00Z"
)
let result = try Vouch.verifyCredential(signed, publicKey: kp.publicKey, now: isoNow)
// result.valid, result.proofValid, result.timeValid
```

Binary values are `Data`; credentials and proofs are JSON `String`s. The lower
level UniFFI functions (`canonicalize(json:)`, `generateEd25519()`, ...) are also
exported directly if you prefer them over the `Vouch` namespace.

## Interop

Output is verified byte-for-byte against the shared cross-language vectors in
`test-vectors/`. A proof built here verifies in every other Vouch SDK.
