# @vouch-protocol-official/core-wasm

The canonical Vouch Protocol core, compiled to WebAssembly for browsers and
Node.js. It is a thin wrapper over one byte-exact Rust crate (`vouch-core`), the
same core that powers the native and mobile SDKs, so every platform produces and
verifies identical bytes. No JCS or proof logic is re-implemented per language.

Apache-2.0. Part of the Vouch Protocol (https://vouch-protocol.com).

## What it does

- **JCS canonicalization** (RFC 8785)
- **Ed25519** keygen, sign, verify
- **did:key** and **multikey** (Ed25519, ML-DSA-44) encode/decode
- **Data Integrity proofs**, cryptosuite `eddsa-jcs-2022` (build/verify)
- **Vouch credentials** build and verify (with validity-window checks)
- **Delegation** time-bound chain validation
- **Post-quantum**: ML-DSA-44 (FIPS 204) and dual proofs (Ed25519 + ML-DSA, two
  independent proofs), plus verification of the v1.6.x composite profile
- **Revocation**: BitstringStatusList status checks

## Install

```
npm install @vouch-protocol-official/core-wasm
```

## Usage (browser)

The package is built with the `web` target, so you initialize the WASM module
once, then call the functions. Binary values (keys, messages, signatures) are
base64 strings; credentials and proofs are JSON strings.

```js
import init, * as core from '@vouch-protocol-official/core-wasm';

await init(); // fetches the .wasm next to the module

const kp = JSON.parse(core.generateEd25519());
const signed = core.signCredential(
  JSON.stringify(myCredential),
  kp.seed_b64,
  kp.did_key + '#key-1',
  '2026-04-26T10:00:00Z'
);
const ok = core.verifyProof(signed, kp.public_b64); // true
```

## Usage (Node.js, ESM)

Two Node-specific notes:

1. Pass the wasm bytes to `init` (no fetch in Node):

   ```js
   import init, * as core from '@vouch-protocol-official/core-wasm';
   import { readFileSync } from 'fs';
   import { createRequire } from 'module';
   const require = createRequire(import.meta.url);
   const wasmPath = require.resolve('@vouch-protocol-official/core-wasm/vouch_core_wasm_bg.wasm');
   await init({ module_or_path: readFileSync(wasmPath) });
   ```

2. Key generation and ML-DSA signing need a CSPRNG. Browsers expose it natively;
   under Node ESM you must make Web Crypto global before calling those functions
   (verification and deterministic signing do not need this):

   ```js
   import { webcrypto } from 'node:crypto';
   if (!globalThis.crypto) globalThis.crypto = webcrypto;
   ```

## Next.js / bundlers

This is a WASM module. With the App Router, call `init()` in a client component
(or a server action) before using the API, and ensure your bundler serves the
`.wasm` asset. With Webpack set `experiments.asyncWebAssembly = true`; with
Turbopack and Vite the default wasm handling works.

## API

All functions return strings (JSON or base64) or booleans, and throw on bad
input. Highlights:

- `canonicalize(json) -> string`
- `generateEd25519() -> {seed_b64, public_b64, multikey, did_key}` (JSON)
- `ed25519Sign(seed_b64, message_b64) -> string`, `ed25519Verify(public_b64, message_b64, signature_b64) -> bool`
- `encodeEd25519Multikey(public_b64) -> string`, `decodeMultikey(mk) -> {algorithm, raw_b64}`
- `didKeyFromEd25519(public_b64) -> string`, `ed25519FromDidKey(did) -> string`
- `buildProof(credentialJson, seed_b64, verificationMethod, createdIso) -> proofJson`
- `signCredential(...)`, `verifyProof(credentialJson, public_b64) -> bool`
- `verifyCredential(credentialJson, public_b64, nowIso, clockSkewSeconds) -> {proofValid, timeValid, valid}`
- `verifyChainTimeBound(chainJson, nowIso, clockSkewSeconds) -> bool`
- `generateMldsa44() -> {secret_b64, public_b64}`, `mldsa44Sign(...)`, `mldsa44Verify(...)`
- `signDual(...)`, `verifyDual(...)`, `verifyComposite(...)`
- `verifyStatus(credentialStatusJson, statusListCredentialJson) -> bool`
- `version() -> string`

## Interop

Output is verified byte-for-byte against shared cross-language vectors in
`test-vectors/` (JCS, eddsa-jcs-2022, hybrid ML-DSA, BitstringStatusList). A
proof built here verifies in the TypeScript, Python, and Go SDKs and vice versa.
