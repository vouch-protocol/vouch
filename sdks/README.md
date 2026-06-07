# Vouch Protocol SDKs

Language SDKs over the canonical Rust core (`core/`). The core does the crypto
once in Rust; these are thin, idiomatic wrappers, so every platform verifies
credentials with byte-identical results.

| SDK | Path | Over | Status |
|---|---|---|---|
| Swift (iOS/macOS) | `swift/` | UniFFI bindings | #32. Builds on macOS via `build-xcframework.sh`; XCTest suite. |
| JVM (Kotlin + Java) | `jvm/` | JNA / UniFFI | #33. Java SDK verified on JDK 21 (cross-impl interop); Kotlin UniFFI binding bundled. |
| .NET | `dotnet/` | C-FFI (P/Invoke) | #34. C# SDK + xUnit suite (incl. cross-impl interop); builds with `dotnet test`. |
| API clients (TS + Python) | `clients/` | OpenAPI spec | #35. Auto-generated typed HTTP clients for the Vouch Bridge API. |

The C/C++ header (#36) ships with the core at
`core/uniffi/generated/c/vouch_core.h` (cbindgen).

## Two kinds of SDK

- **Core SDKs** (`swift/`, `jvm/`, `dotnet/`, plus the existing TypeScript,
  Python, Go, and `core/wasm`): local crypto, no network. Sign and verify
  credentials, proofs, delegation, dual-proof ML-DSA, and revocation, all
  byte-compatible with the shared `test-vectors/`.
- **API clients** (`clients/`): typed HTTP clients for the Vouch Bridge service
  (sign / verify / audio endpoints), generated from its OpenAPI spec.

Each SDK directory has its own README with build and usage instructions.
