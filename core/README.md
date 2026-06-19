# Vouch Protocol core (Rust)

One byte-exact implementation of the Vouch Protocol primitives, shared by every
language SDK so that JCS canonicalization and Data Integrity proofs are never
re-derived per language (which is how subtle cross-platform verification drift
creeps in). This is task #31: the canonical core.

It mirrors the proven `sonic-dsp -> sonic-wasm -> expo-sonic` pipeline: one pure
Rust crate, compiled to multiple outputs.

```
core/
  vouch-core/   the canonical crate: all protocol logic + interop tests
  wasm/         wasm-bindgen wrapper  -> @vouch-protocol-official/core-wasm  (browser + Node)
  uniffi/       UniFFI + C-FFI wrapper -> Swift, Kotlin/Java bindings + a cbindgen C header
```

Apache-2.0, protocol-pure (no downstream product names; the `brand-guard` CI
applies).

## What the core does

- **JCS canonicalization** (RFC 8785)
- **Ed25519** keygen, sign, verify
- **did:key** and **multikey** (Ed25519 `0xed01`, ML-DSA-44 `0x8724`) encode/decode
- **Data Integrity proofs**, cryptosuite `eddsa-jcs-2022` (build/verify)
- **Vouch credentials** build + verify (with validity-window checks)
- **Delegation** time-bound chain validation (Specification 9.3 step 6)
- **Post-quantum**: ML-DSA-44 (FIPS 204) keygen/sign/verify; **dual proofs**
  (Ed25519 + ML-DSA-44 as two independent proofs, the current design); and
  verification of the v1.6.x composite profile
- **Revocation**: BitstringStatusList status checks

## Cross-implementation interop (the whole point)

Every cryptographic primitive is verified against shared vectors in
`test-vectors/`, and a proof built by the Rust core verifies in the TypeScript
SDK and vice versa. Proven by tests, not by assertion:

- `jcs`: Rust canonical output is byte-identical to the shared RFC 8785 vectors.
- `keys`: Rust derives the same Ed25519 public key from the shared seed (KAT).
- `data-integrity-eddsa-jcs-2022`: a NEW shared vector that the Rust core
  generated; both the Rust core and the TS SDK verify it AND reproduce the exact
  same `proofValue` (Ed25519/JCS/SHA-256 are deterministic). See
  `core/vouch-core/tests/interop_eddsa_vector.rs` and
  `packages/sdk-ts/tests/core-eddsa-interop.test.ts`.
- `hybrid`: Rust FIPS-204 verifies the SDK's `@noble/post-quantum` ML-DSA-44
  signature, and verifies the shared composite hybrid credential end to end.
- `bitstring-status-list`: Rust decodes the Python-generated list and reports
  identical bits; `verify_status` agrees with the sample entries.

## Build and test

```
cd core/vouch-core && cargo test          # the core + all interop tests

cd core/wasm && ./build-npm.sh 0.1.0       # -> pkg/ (publishable) ; node smoke.mjs to smoke-test

cd core/uniffi && cargo build --release    # then generate bindings:
cargo run --release --bin uniffi-bindgen -- generate src/vouch_core.udl --language kotlin --out-dir generated/kotlin
cargo run --release --bin uniffi-bindgen -- generate src/vouch_core.udl --language swift  --out-dir generated/swift
cbindgen --config cbindgen.toml --crate vouch-core-uniffi --output generated/c/vouch_core.h
```

## Outputs

- **WASM**: `@vouch-protocol-official/core-wasm` (web target, runs in browser and
  Node). JS API uses base64 for binary and JSON strings for credentials. See
  `core/wasm/README.npm.md`, including the Node ESM `crypto` polyfill note for
  keygen/ML-DSA signing (browsers need nothing).
- **UniFFI**: Swift (`vouch_core.swift` + FFI header + modulemap) and Kotlin
  (`vouch_core.kt`) bindings, generated from `src/vouch_core.udl`.
- **C-FFI**: `generated/c/vouch_core.h` (cbindgen), a clean C API where every
  value is a C string (JSON or base64); returned strings are freed with
  `vouch_string_free`. For .NET P/Invoke and C/C++.

For mobile, vendor the generated bindings + the Rust crate into the app package
and compile on the build server. As with `expo-sonic`, an EAS build needs a
`eas-build-pre-install` hook to install the Rust toolchain (rustup + the Android
targets + cargo-ndk) so the core compiles for the device.

## Follow-on SDKs (once the core lands)

These wrap the bindings above and are tracked separately:

- #32 Swift SDK (over UniFFI)
- #33 JVM SDK, Kotlin + Java (over UniFFI/JNI)
- #34 .NET SDK (over the C-FFI)
- #36 C/C++ header (cbindgen, shipped here as `generated/c/vouch_core.h`)
- #35 auto-generated API clients from the public OpenAPI spec
