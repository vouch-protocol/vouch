# Changelog

All notable changes to Vouch Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Robotics: living trust, revocation, and accountable safety record

The Python reference adds three robotics capabilities on the same
`eddsa-jcs-2022` credentials:

- `vouch.robotics.liveness`: a robot heartbeat carrying a per-interval motion
  digest (peak force, speed, speed near humans, zone breaches) with trust that
  decays unless a fresh, in-envelope heartbeat keeps arriving.
- `vouch.robotics.revocation`: surgical per-credential revocation via
  BitstringStatusList plus whole-DID kill via the existing registry.
- `vouch.robotics.safety_record`: a tamper-evident incident and near-miss ledger
  summarized into a portable, signed safety-record credential.

Implemented in Python, TypeScript, Go, and the Rust core (flowing to the Swift,
Kotlin/JVM, .NET, C/C++, and WebAssembly wrappers), byte-identical and pinned by
the robotics interop vector.

## [1.6.3] - 2026-06-15

### Added

#### Claude Code integration for per-region attribution (PAD-061)

The editor wiring and demo for `vouch attribute`: a PostToolUse hook
(`vouch/integrations/claude-code/`) that records the assistant's Edit, Write,
and MultiEdit operations automatically, plus the `who_wrote_this` runnable
example. The attribution engine itself shipped earlier; this release adds the
Claude Code integration and the example on top of it.

## [Unreleased]

### Added

#### Robotics primitives across every language SDK (PAD-064 through PAD-070)

Six capabilities for robots and embodied agents, implemented once in the Rust
core (`core/vouch-core`, module `robotics`) and exposed through the UniFFI and
WebAssembly wrappers (Swift, Kotlin/JVM, .NET, C/C++, and the browser), plus
byte-identical reference implementations in Python (`vouch.robotics`), TypeScript
(`packages/sdk-ts/src/robotics`), and Go (`go-sidecar/robotics`):

- **Hardware-rooted identity**: a `RobotIdentityCredential` binding the robot key
  to a TPM or secure element, so the identity cannot be cloned to other hardware.
- **Model and config provenance**: a re-signable attestation of the model, weights
  hash, safety policy, and config hash, surviving over-the-air updates.
- **Physical capability scope**: force, speed, near-humans, zone, and shift-window
  limits, checked before each actuation, with narrow-only delegation.
- **Robot-to-robot handshake**: a three-message bounded-trust session gated by a
  `did:web` domain trust policy.
- **Black box and kill switch**: an AES-256-GCM encrypted, hash-linked, tamper-evident
  log, plus a verifiable emergency stop constrained to an attested authority.
- **Scannable passport**: a `vouch-passport:` URI for offline QR or NFC verification.

A shared interop vector (`test-vectors/robotics/vector.json`) pins the hardware-root
binding and the config hash, so a robotics credential signed in any language
verifies in every other.

#### State Verifiability runtime (Specification §11, §15)

First-class implementation of the State Verifiability layer the spec
previously described as informative. Six new Python modules animate the
SessionVoucher VC format with a concrete renewal protocol:

- **`vouch.trust_entropy`** — verifier-side decay computation per §11.5.
 `compute_trust_at`, `evaluate_trust`, `check_trust_threshold`,
 `half_life_seconds`, `time_until_threshold`. Closes the previous gap
 where `decay_lambda` was round-tripped through credentials but never
 consumed by any verifier.
- **`vouch.behavioral_attestation`** — per-interval signal collector
 producing the §11.3 `behavioralDigest` (api calls, tokens consumed,
 resources accessed, intent drift). Thread-safe `BehavioralCollector`
 with three reference drift scorers (mean, max, EWMA).
- **`vouch.canary`** — commit/reveal chain per §11.3 / §11.7 giving the
 Heartbeat Protocol a dead-man's-switch property. `CanaryChain` on the
 agent side, `CanaryVerifier` on the validator side, both stateful and
 thread-safe.
- **`vouch.merkle`** — binary Merkle tree primitives with RFC 6962 domain
 separation. `MerkleTree`, `InclusionProof` (O(log n) selective
 disclosure), `compute_action_merkle_root` for the §11.3
 `actionMerkleRoot` field. Used by Heartbeat and adjacent to PAD-017
 Reasoning Trees and PAD-042 transparency-log anchoring.
- **`vouch.heartbeat`** — orchestration per §11.3. `HeartbeatRequest`
 wire format, `HeartbeatSession` (composes canary chain + behavioral
 collector + action tracker), `HeartbeatScheduler` (asyncio periodic
 firing with caller-supplied submit callback), `HeartbeatValidator`
 (single-validator implementation that issues SessionVouchers and walks
 per-session canary state and interval-index monotonicity).
- **`vouch.quorum`** — M-of-N federation per §11.6. `QuorumValidator`
 wraps a HeartbeatValidator with a role tag and optional weight;
 `HeartbeatQuorum` coordinates N validators and aggregates trust
 parameters across approvers (default: min `initial_trust`, max
 `decay_lambda`, min validity window, intersection of scopes).

#### BitstringStatusList

Reference implementation of VC-BITSTRING-STATUS-LIST for
credential-level revocation and suspension status (Specification §11.2)
across Python, TypeScript, and Go SDKs:
 - `StatusList` class (in-memory bitstring with gzip + base64url multibase encoding per W3C §4.2, 131,072-bit minimum, deterministic gzip headers across languages).
 - `build_status_list_credential` / `buildStatusListCredential` / `BuildStatusListCredential` issuers for `BitstringStatusListCredential` VCs.
 - `build_status_list_entry` / `buildStatusListEntry` / `BuildStatusListEntry` builders for the `credentialStatus` reference attached to a Vouch Credential.
 - `verify_status` / `verifyStatus` / `VerifyStatus` for verifier-side bit lookup with structural validation.
 - `build_vouch_credential` (and TS / Go equivalents) accept an optional `credential_status` / `credentialStatus` / `CredentialStatus` parameter to attach a status entry at issuance.
 - `StatusList.to_state_dict` / `from_state_dict` (and TS / Go equivalents) for persistence between issuer restarts, including the allocation cursor that is not recoverable from the encoded bitstring alone.
 - `FilesystemStatusListStore` (Python) reference filesystem-backed store with atomic writes.
- **HTTP fetcher for verifier-side status list retrieval** (`vouch.status_list_fetcher.StatusListFetcher`): in-memory TTL cache, conditional GETs via `ETag` / `If-Modified-Since`, configurable response-size limit, `force_refresh` for verification-failure handling. Uses the existing `httpx` dependency.
- **Cross-language test vector** at `test-vectors/bitstring-status-list/vector.json` with a deterministic generator (`generate.py`). Python and TypeScript implementations produce byte-identical encoded output for the same revoked indices; Go's `compress/flate` produces a valid DEFLATE stream that decodes equivalently (-required equivalence).

### Tests
- 48 Python tests, 32 TypeScript tests, and 39 Go tests covering construction validation, bit operations, encoding round-trip, structural validation, end-to-end revocation flow, state dict persistence, filesystem store atomicity, HTTP fetcher caching and conditional GETs, package exports, and cross-language interop.

## [1.6.0] - 2026-04-29

### Added

standards-aligned alignment with backward-compatible coexistence of the legacy v0.x JWS path.

- **Verifiable Credentials issuance** (`Signer.sign_credential`): produces a VC Data Model 2.0 credential carrying the agent's intent (`action`, `target`, required `resource`), reputation, and optional delegation chain.
- **Data Integrity proofs** with the `eddsa-jcs-2022` cryptosuite (`Verifier.verify_credential`): proof attaches as a sibling object on the credential, no Base64-wrapping of the payload.
- **JCS canonicalization** (`vouch.jcs`): RFC 8785 implementation. Cross-implementation interop verified against shared test vectors at `test-vectors/jcs/vectors.json`.
- **Multikey verification methods** (`vouch.multikey`): multibase + multicodec encoding for Ed25519 (`0xed01`) and ML-DSA-44 (`0x1207`). Algorithm-agnostic key resolution via `DIDDocument.get_ed25519_public_key()` (auto-falls-back to legacy JWK).
- **Hybrid post-quantum profile** (`Signer.sign_credential_hybrid`): optional `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite. Both Ed25519 and ML-DSA-44 sign the same JCS canonical bytes for graceful verifier downgrade. Aligns with NIST CNSA 2.0 / NSM-10 migration timelines. Requires `pip install vouch-protocol[pq]` for the optional `pqcrypto` dependency.
- **VC envelope helpers** (`vouch.vc`): `build_vouch_credential`, `build_session_voucher`.
- **Async verifier credential path** (`AsyncVerifier.verify_credential`, `AsyncVerifier.check_vouch_credential`): mirrors the sync path with async DID resolution.
- **Three-language interop** with TypeScript (`typescript/`) and Go (`go-sidecar/`) producing byte-identical canonical form.
- **Three new defensive disclosures** (PAD-039, PAD-040, PAD-041) plus 16 amendments to existing PADs documenting Data Integrity embodiments and JCS-determinism properties.

### Changed
- `Signer` constructor now derives raw Ed25519 bytes from the JWK seed for the modern Data Integrity path. Existing callers using `Signer.sign()` are unaffected.
- `did_web.DIDDocument` adds `get_public_key_multibase()` and `get_ed25519_public_key()` helpers.

### Deprecated
- Legacy v0.x JWS paths (`Signer.sign`, `Verifier.verify`, `Verifier.check_vouch`) remain operational during the deprecation window. New code should prefer the credential methods.

## [1.5.0] - 2026-03-03

### Added
- C2PA Certificate Authority infrastructure
- Multi-layer sonic watermark embedding with Hamming(7,4) error correction
- Psychoacoustic masking for frequency-adaptive watermark amplitude
- Audio bridge routes for real-time watermarking service
- Prior art disclosures PAD-028 (cross-modal identity provenance) and PAD-029 (Eldear scam protection)

### Changed
- Bridge server now includes audio watermarking endpoints
- WASM core upgraded from single-layer to multi-layer spread-spectrum embedding
- Setuptools config excludes `vouch.pro` from published packages

### Fixed
- Legacy single-layer fallback preserved for backwards compatibility in watermark detection

## [1.4.0] - 2026-01-05

### Added
- **Vouch Git Workflow** - One-command SSH signing for git commits
 - `vouch git init` - Configure SSH signing, install commit hooks, inject badge
 - `vouch git status` - Show current Vouch git configuration
- Commit trailer hook with Vouch-DID for supply chain security
- CI workflow for verifying Vouch signatures on PRs
- README badge injection ("Protected by Vouch")
- Chain of Custody (delegation chains) for multi-agent systems

### Changed
- Updated README with hero image and viral Quick Start
- Formatted entire codebase with ruff

### Fixed
- Resolved jwcrypto deprecation warnings
- Python 3.9 compatibility for type hints

## [1.3.1] - 2025-12-31

### Added
- `reputation_score` parameter to `Signer.sign()` 
- Reputation field in `Passport` dataclass
- Prior art disclosure system (PAD-001, PAD-002, PAD-003)

### Changed
- Updated documentation with visual diagrams

## [1.3.0] - 2025-12-28

### Added
- Apache 2.0 as default license
- Comprehensive README with use cases

### Changed
- Major README overhaul

## [1.2.0] - 2025-12-15

### Added
- Key revocation registry
- Reputation engine with event tracking
- Cloud KMS providers (AWS, GCP, Azure)
- TypeScript SDK (separate package)
- Redis-backed stores for all components
- Kafka integration for reputation events

### Changed
- License structure redesign

## [1.1.3] - 2025-12-10

### Added
- Comprehensive test suite (76 tests)
- AsyncVerifier for concurrent verification
- Caching layer (Memory, Redis, Tiered)
- Rate limiting with Redis support
- Nonce tracking for replay protection

## [1.1.0] - 2025-12-01

### Added
- Audio signing for real-time voice
- Key rotation with RotatingKeyProvider
- Agent registry for key discovery
- Metrics collection with Prometheus format

### Changed
- Improved verifier performance

## [1.0.0] - 2025-11-15

### Added
- Initial release
- Signer with Ed25519 keys
- Verifier with DID resolution
- JWS token format
- Basic documentation

[Unreleased]: https://github.com/vouch-protocol/vouch/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/vouch-protocol/vouch/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/vouch-protocol/vouch/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/vouch-protocol/vouch/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/vouch-protocol/vouch/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/vouch-protocol/vouch/compare/v1.1.3...v1.2.0
[1.1.3]: https://github.com/vouch-protocol/vouch/compare/v1.1.0...v1.1.3
[1.1.0]: https://github.com/vouch-protocol/vouch/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/vouch-protocol/vouch/releases/tag/v1.0.0
