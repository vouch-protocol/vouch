# Changelog

All notable changes to Vouch Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-05

### Changed (BREAKING)

- Renamed the credential API to `sign` / `verify` across every SDK and the Rust core. `Signer.sign_credential` is now `Signer.sign`, `Verifier.verify_credential` is now `Verifier.verify`, and `sign_credential_hybrid` is now `sign_hybrid`. The same rename applies in the TypeScript, Swift, JVM, .NET, C++, and Go SDKs, and in the C ABI (`vouch_sign_credential` becomes `vouch_sign`, `vouch_verify_credential` becomes `vouch_verify`).

### Removed (BREAKING)

- Removed the legacy v0.x JWS credential path (`Signer.sign()` returning a JWS token, and the JWS `Verifier.verify()` / `check_vouch()`). Credentials are W3C Verifiable Credentials with `eddsa-jcs-2022` Data Integrity proofs.

### Added

- `vouch-mcp`: a Model Context Protocol server that lets any MCP client issue and verify Vouch Credentials (`sign`, `verify`, `create_session`, `check_revocation`, `get_identity`), over stdio or Streamable HTTP, with an optional post-quantum profile.

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
- `vouch.robotics.perception`: signed, hash-linked provenance for captured sensor
  frames (camera, lidar, audio, and more), so a robot can prove what its sensors
  saw and a substituted frame is detectable.
- `vouch.robotics.lease`: a short-lived, scope-bounded delegation lease a
  disconnected robot verifies and acts on offline, nesting across vendors.
- `vouch.robotics.physical_quorum`: a cryptographic two-person rule requiring M of
  N attested approvers before a high-consequence physical action is authorized.
- `vouch.robotics.lifecycle`: ownership transfer (chain of custody), key rotation
  (key history), and a signed decommission credential for a robot's whole life.
- `vouch.robotics.conformance`: machine-checkable profiles mapping robot credentials
  to ISO 10218/15066, the EU Machinery Regulation, the EU AI Act, and UL 3300, a
  deterministic conformance checker, and a signed conformance attestation.
- `vouch.robotics.pq`: hybrid post-quantum signing for robot credentials
  (hybrid-eddsa-mldsa44-jcs-2026), backward-compatible dual verification, and a
  re-signing migration path for a robot's decade-long service life.
- `vouch.robotics.embodiment`: cross-embodiment identity continuity, an embodiment
  credential binding an agent to a body and its hardware root, a continuity chain
  proving one accountable agent persisted across bodies, and a fork check.
- `vouch.robotics.custody`: a physical custody handoff chain across human and robot
  actors, a holder-at-time lookup, and condition localization of a state change to
  the responsible hop.
- `vouch.robotics.access`: bounded, revocable robot access to physical
  infrastructure, an operator-signed grant naming a resource, its operations, an
  optional zone, and a time window, paired with a robot-signed request the resource
  authorizes offline, plus shrink-only attenuation of a sub-grant.
- `vouch.robotics.fusion`: fused-sensor provenance, a signed attestation binding a
  robot's fused world model to the ordered set of input frame hashes and the fusion
  method that produced it, with an input digest that makes the input set
  tamper-evident and a check of each input against the robot's perception log.
- `vouch.robotics.wear`: wear and degradation attestation, a robot-signed wear level
  bound to its identity and hash-linked over time, with a deterministic rule that
  narrows its physical capability scope as it degrades, so the derated scope stays a
  valid attenuation of the original.
- `vouch.robotics.consent`: bystander-consent evidence, a robot binds the basis for a
  capture to the capture hash and its identity, holding only hashes, and a bystander
  signs a consent token bound to one capture and robot so it cannot be replayed.

Implemented in Python, TypeScript, Go, and the Rust core (flowing to the Swift,
Kotlin/JVM, .NET, C/C++, and WebAssembly wrappers), byte-identical and pinned by
the robotics interop vector.

#### Robotics: control, operating domain, swarm, and human handover

The Python reference adds four forward-looking robotics capabilities, each with an
interactive website demo and defensive disclosures:

- `vouch.robotics.teleop`: accountable teleoperation handoff, a signed chain of
  control-authority transfers between an autonomous policy and human teleoperators,
  with a controller-at-time lookup and a control-continuity check.
- `vouch.robotics.odd`: operating-domain conformance, an operator-certified operating
  domain and a robot-signed attestation that it stayed inside it, with a deterministic
  in-domain check.
- `vouch.robotics.swarm`: multi-robot swarm accountability, verifiable swarm membership
  and attribution of a collective action to its admitted members.
- `vouch.robotics.handover`: safe robot-to-human handover, a signed handover with the
  force and speed envelope at the release and a recipient acknowledgement bound to it.

Disclosed as PAD-095 through PAD-102. Cross-language ports follow.

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

#### Root-anchored hardware-rooted robot identity (PAD-103)

The robotics layer binds the hardware-rooted robot identity to the Root of Trust for
Machine Identity, so a verifier pinning one root confirms in a single offline check both
that a robot comes from a recognized manufacturer and that its identity key is
hardware-rooted:

- **`build_robot_identity`**: a manufacturer recognized by the pinned root to issue robot
  identities issues an authority identity whose subject references the robot's
  hardware-rooted key.
- **`verify_robot_identity_chain`**: anchors the manufacturer's recognition to the pinned
  root, verifies the robot's hardware attestation, and confirms the key the manufacturer
  vouched for is the exact key the hardware attested, with the same anchor-once model and
  reason-code style as the recognized-issuer authority layer.

Implemented in Python (`vouch.robotics.root_identity`), TypeScript, Go, and the Rust
core, with the root-anchored robot identity added to the Root of Trust interop vector
(`test-vectors/root-of-trust/vector.json`).

#### Halos safety-evidence recorder (NVIDIA Halos integration, PAD-105)

An evidence layer for a robot running an NVIDIA Halos-certified stack. Halos certifies
that the stack is safe and secure by design; this records what a specific robot actually
did and binds it to the robot's identity:

- **`SafetyEventRecorder`**: captures the Halos safety-event stream (the Outside-In
  Safety Blueprint components SIPP, SAIM, SEI, SDM, plus emergency stops and operator
  actions) into the tamper-evident, encrypted black-box.
- **`build_safety_evidence` / `verify_safety_evidence`**: the robot signs a
  `HalosSafetyEvidenceCredential` that seals the black-box head and entry count and binds
  them to its identity and to the Halos stack elements it ran on (IGX system-on-module,
  Halos Core, Blueprint applications). A verifier confirms, without the black-box key,
  that the record is unaltered, untruncated, attributable to that robot, and tied to the
  certified configuration, while the payloads stay confidential.

Implemented in the Python reference (`vouch.robotics.halos`) and the Rust core, exposed
through the curated robotics C ABI.

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

- **Verifiable Credentials issuance** (`Signer.sign`): produces a VC Data Model 2.0 credential carrying the agent's intent (`action`, `target`, required `resource`), reputation, and optional delegation chain.
- **Data Integrity proofs** with the `eddsa-jcs-2022` cryptosuite (`Verifier.verify`): proof attaches as a sibling object on the credential, no Base64-wrapping of the payload.
- **JCS canonicalization** (`vouch.jcs`): RFC 8785 implementation. Cross-implementation interop verified against shared test vectors at `test-vectors/jcs/vectors.json`.
- **Multikey verification methods** (`vouch.multikey`): multibase + multicodec encoding for Ed25519 (`0xed01`) and ML-DSA-44 (`0x1207`). Algorithm-agnostic key resolution via `DIDDocument.get_ed25519_public_key()` (auto-falls-back to legacy JWK).
- **Hybrid post-quantum profile** (`Signer.sign_hybrid`): optional `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite. Both Ed25519 and ML-DSA-44 sign the same JCS canonical bytes for graceful verifier downgrade. Aligns with NIST CNSA 2.0 / NSM-10 migration timelines. Requires `pip install vouch-protocol[pq]` for the optional `pqcrypto` dependency.
- **VC envelope helpers** (`vouch.vc`): `build_vouch_credential`, `build_session_voucher`.
- **Async verifier credential path** (`AsyncVerifier.verify`, `AsyncVerifier.check_vouch_credential`): mirrors the sync path with async DID resolution.
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
