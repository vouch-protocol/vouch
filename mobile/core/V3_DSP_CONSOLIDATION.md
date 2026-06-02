# v3 DSP consolidation — wiring the hardened codec into the UniFFI mobile core

**Status:** plan only (Task 3 deferred — large/risky refactor). Tasks 1 and 2 are
done: `mobile/core/wasm` now embeds and detects with the hardened **v3** codec,
and the public `embedWatermark` / `detectWatermark` wasm functions use it.

This note lives in `mobile/core/` (kept inside the task's edit boundary). It
extends the broader consolidation roadmap (in `notes/dsp-consolidation-roadmap-31-plan.md`,
not modified here) with the v3-specific wiring now that the canonical scheme has
changed.

---

## What changed in this pass (already shipped, `mobile/core/wasm/src/lib.rs`)

The canonical web DSP is no longer the Barker-13 / 4-band scheme described in the
older roadmap. It is now the **v3 codec**:

- **Sync:** Hann-tapered linear chirp (1.5–3.5 kHz, 600 ms) located by an FFT
  normalized matched filter (`gen_chirp`, `find_chirp_candidates`). The chirp band
  sits above the bass and inside every channel's passband (survives codec-8k /
  lowpass-4k / re-recording). Sync tries the top-K candidate peaks and lets the
  CRC pick the true one — robust to host coincidence peaks.
- **Payload:** a **compact 4-byte ID** (server lookup key, `derive_v3_id`) plus a
  **CRC-16**, Hamming(7,4)-coded, embedded as 4-layer dual-tone FSK
  (`V3_LAYER_BANDS`, all tones unique and ≥300 Hz apart) and **repeated across
  time** for diversity.
- **Detect (`detect_v3`):** per-(layer,bit) coherent FSK soft values, folded over
  all repetitions, then **two-stage maximal-ratio combining** (per-layer
  inverse-variance weight, so band-limited/dead bands self-erase) and a
  **CRC-validated layer-subset search** (all 15 non-empty subsets; the subset that
  drops a host-biased band passes CRC and recovers the ID exactly). Returns `None`
  unless the CRC validates → negligible false-positive rate.

Result: `robustness_profile_v3` decodes the 32-bit ID **EXACT (0 bit errors)** on
clean, +20/+10 dB noise, lowpass 8k/4k, codec ~16k/~8k, re-recording, and
re-record+codec-8k.

## The mobile core today (`mobile/core/src/lib.rs`) — still a mock

`mobile/core` (UniFFI → expo-sonic) does **not** decode a payload. `MockDetector`
returns `WatermarkResult::mock_detected(...)` and the DSP engine only computes a
spread-spectrum / chirp **presence** boolean (`detect_spread_spectrum`,
`detect_chirp_sync`). Source comment confirms: *"Real implementation would extract
payload from watermark."* So a web-embedded v3 watermark is currently **not**
recoverable on mobile.

## Why this is deferred (large + risky)

1. **No shared DSP crate.** v3 lives in `mobile/core/wasm` behind `#[wasm_bindgen]`.
   Porting it means either (a) extracting a pure-Rust `dsp` crate both wrappers
   depend on, or (b) duplicating ~450 lines (chirp, matched filter, Hamming, CRC,
   MRC combine, layer bands, soft decode). (a) is correct but touches the crate
   graph and both published surfaces.
2. **Surface mismatch.** `WatermarkResult` (UniFFI) ≠ `DetectResult` (wasm): the
   UDL has `signer_did`, `payload`, `detection_method`, callbacks, listener state.
   Mapping the v3 ID (+ `payload_hash`) into `WatermarkResult` is a UDL/API change.
3. **Consumer blast radius.** Changing the UniFFI surface ripples into
   `expo-sonic` bindings and its vendor script; should not land unvalidated.

## Recommended sequence (when picked up)

Aligns with the workspace target in the roadmap (`mobile/sonic/{dsp,wasm,uniffi}`):

1. **Extract `mobile/sonic/dsp`** (pure Rust) from `mobile/core/wasm/src/lib.rs`:
   move the v3 internals verbatim — `gen_chirp`, `find_chirp_candidates`,
   `layer_chip_soft`, `hamming74_*`, `hamming*_decode_payload_n`,
   `hamming_soft_decode_payload_n`, `crc16`, `embed_v3`, `detect_v3`,
   `compute_masking_amplitude`, `pcm_to_float`/`float_to_pcm`, the `V3_*`
   constants and `V3_LAYER_BANDS`. Strip `#[wasm_bindgen]`. Re-export a plain Rust
   API: `embed(samples, id, sr) -> Vec<f32>` and `detect(samples, sr, id_len) -> Option<Vec<u8>>`.
2. **`mobile/core/wasm` becomes a thin shim** over `dsp` (keep the exact JS surface
   and `EmbedResult`/`DetectResult` shapes — already v3-correct).
3. **Back the UniFFI core with `dsp`:** replace `MockDetector` /
   `process_buffer` / `process_samples` with `dsp::detect_v3`. Populate
   `WatermarkResult` from the recovered ID: set `detected`, `confidence` (0.95 on
   CRC-valid, else 0), `payload`/`payload_hash` = the v3 ID and its SHA-256,
   `detection_method = "chirp_v3"`. Delete the spread-spectrum mock paths.
4. **Interop proof = one native test in `dsp`** (no browser/EAS needed):
   ```rust
   let pcm = embed_v3(&host, &id, sr);          // "web" embed
   let got = detect_v3(&pcm, sr, V3_ID_BYTES);  // "mobile" detect
   assert_eq!(got, Some(id));
   ```
   Commit a test-vector file (embed output bytes) so both wasm and uniffi CI assert
   the same decode. (`mobile/core/wasm` already has `test_v3_production_roundtrip`
   and `robustness_profile_v3` to lift.)
5. **Re-point `expo-sonic`** vendor script at `mobile/sonic/uniffi`; bump and
   republish `sonic-wasm` (same v3 scheme → existing web embeds stay valid).

## Compatibility note

The web embed now carries a 4-byte ID + CRC-16 under the v3 chirp, **not** the old
128-bit Barker/Hamming payload. Any consumer still on the old detect path will not
find v3 watermarks. The mobile port must adopt v3 wholesale (no mixed-scheme
period), keyed on `payload_hash = sha256(v3_id)` for server lookup.
