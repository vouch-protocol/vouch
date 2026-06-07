# Language SDKs

Vouch has one canonical core written in Rust (`vouch-core`). It does the
cryptography once: JCS canonicalization, Ed25519, did:key and multikey, Data
Integrity proofs (eddsa-jcs-2022), credential build and verify, delegation,
dual-proof ML-DSA-44, and BitstringStatusList revocation. Every language SDK is
a thin wrapper over that core, exposed through WebAssembly for the web and
through a UniFFI / C ABI layer for native and enterprise platforms.

The point of doing it this way: JCS canonicalization and proof generation are
never re-implemented per language, so there is no subtle drift. A credential
signed by any SDK verifies in every other SDK, byte for byte, and they all pass
the same shared test vectors.

## What is available where

- **Python** (`pip install vouch-protocol`): the original reference SDK. Signer,
  verifier, async verifier, KMS, reputation, revocation, CLI.
- **TypeScript and Go**: the existing reference SDKs (npm and Go module).
- **Browser and Node.js, WebAssembly** (`npm install @vouch-protocol-official/core-wasm`):
  the Rust core compiled to WASM. Runs in browsers and in Node.
- **Swift, for iOS and macOS**: the `VouchCore` Swift package. Built as an
  XCFramework over the core via UniFFI. Add it with Swift Package Manager.
- **JVM, Java and Kotlin** (`com.vouchprotocol:vouch-core`): a Gradle module.
  Java users get a plain class; Kotlin users get the generated UniFFI binding.
- **.NET** (`VouchProtocol.Core` on NuGet): a C# library over the C ABI.
- **C and C++**: the C bindings shipped with the core, a header plus a prebuilt
  library, with a Makefile and CMake example. This is bindings, not a separate
  code SDK.

There are also auto-generated HTTP clients for the Bridge service (sign, verify,
audio) in TypeScript (`@vouch-protocol-official/api-client`) and Python
(`vouch-api-client`). Those talk to a running Bridge over HTTP; the SDKs above do
the crypto locally with no network.

## What every SDK can do

All of the local SDKs cover the same surface:

- Sign and verify Vouch credentials (eddsa-jcs-2022)
- Verify a credential's validity window
- Post-quantum: ML-DSA-44 and dual proofs (Ed25519 plus ML-DSA), and verify the
  older composite profile
- Delegation: build a link and validate a chain's time-bound rule
- Revocation: check a credential's BitstringStatusList status

Binary values cross the boundary as base64; credentials and proofs cross as JSON.

## Mobile and native builds

For mobile, the native core compiles on the build server. As with the audio
module, an Expo or EAS build adds a pre-install step that installs the Rust
toolchain and the platform targets so the core compiles for the device. Each SDK
directory has a build script and a README with the exact steps.

## Interop

The shared vectors live in `test-vectors/`. The strongest one is the
eddsa-jcs-2022 vector: every SDK reproduces the exact same proofValue from the
same inputs and verifies the same signed credential. If two SDKs ever disagreed,
a build would fail.
