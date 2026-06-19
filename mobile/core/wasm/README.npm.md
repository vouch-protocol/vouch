# @vouch-protocol-official/sonic-wasm

WebAssembly build of the **Vouch Sonic Engine** — an inaudible spread-spectrum
audio watermark (multi-layer 4-band embed, Hamming(7,4) FEC, Barker-13 sync,
psychoacoustic masking) plus voice feature extraction. Compiled from Rust
(`rustfft`, `ed25519-dalek`, `sha2`) to WASM via `wasm-pack` (**`web` target**),
so it runs in **both the browser and Node.js**.

## Install

```bash
npm install @vouch-protocol-official/sonic-wasm
```

## Exports

| Function | Signature | Notes |
|---|---|---|
| `initSonic()` | `() => string` | Returns the engine version banner. Call after init. |
| `embedWatermark(pcm, sampleRate, did, timestampMs)` | `(Uint8Array, number, string, number) => EmbedResult` | `sampleRate` must be ≥ 44100. |
| `detectWatermark(pcm, sampleRate)` | `(Uint8Array, number) => DetectResult` | Needs sufficiently long audio. |
| `extractVoiceFeatures(pcm, sampleRate)` | `(Uint8Array, number) => VoiceFeatures` | 13-dim feature vector. |
| `cosineSimilarity(a, b)` | `(Float32Array, Float32Array) => number` | |

`pcm` is raw **16-bit signed little-endian, mono** PCM.

`EmbedResult` fields: `watermarked_audio: Uint8Array`, `watermark_id: string`,
`audio_hash: string` (sha256 hex), `payload_hash: string` (sha256 hex).

## Initialization (required once)

This is wasm-pack's `web` target: you must call the default export to
instantiate the module before calling any function.

### Browser

```ts
import init, { initSonic, embedWatermark } from '@vouch-protocol-official/sonic-wasm';

// With no argument, init() fetches the sibling .wasm via import.meta.url.
await init();
initSonic();
```

If your bundler does not resolve the sibling `.wasm` automatically, pass an
explicit URL:

```ts
import wasmUrl from '@vouch-protocol-official/sonic-wasm/vouch_sonic_wasm_bg.wasm?url';
await init({ module_or_path: wasmUrl });
```

### Node.js (e.g. Next.js API route / server component)

```ts
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import init, { detectWatermark } from '@vouch-protocol-official/sonic-wasm';

const require = createRequire(import.meta.url);
const wasmPath = require.resolve('@vouch-protocol-official/sonic-wasm/vouch_sonic_wasm_bg.wasm');
await init({ module_or_path: readFileSync(wasmPath) });
```

## Next.js notes

The `web` target instantiates WASM itself (no `WebAssembly.instantiateStreaming`
of an opaque import), so you generally do **not** need webpack's
`experiments.asyncWebAssembly`. Two gotchas:

- **Server side:** call the module only inside request handlers / server
  actions, and load the `.wasm` bytes from disk via `require.resolve` (above) so
  the file is traced into the serverless bundle. To be safe with output tracing,
  add it to `outputFileTracingIncludes` in `next.config.js`.
- **Client side:** import dynamically in a client component
  (`const mod = await import('@vouch-protocol-official/sonic-wasm')`) to keep the
  WASM out of the server render path, then `await mod.default()`.

If you prefer bundler-managed WASM instead, a `--target bundler` build can be
published as a `./bundler` subpath; open an issue if you need it.

## License

Apache-2.0. See [LICENSE](./LICENSE).
