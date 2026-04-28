# Changelog

All notable changes to Vouch Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.6.0] - 2026-04-29

### Added

W3C-track alignment with backward-compatible coexistence of the legacy v0.x JWS path.

- **W3C Verifiable Credentials issuance** (`Signer.sign_credential`): produces a W3C VC Data Model 2.0 credential carrying the agent's intent (`action`, `target`, required `resource`), reputation, and optional delegation chain.
- **W3C Data Integrity proofs** with the `eddsa-jcs-2022` cryptosuite (`Verifier.verify_credential`): proof attaches as a sibling object on the credential, no Base64-wrapping of the payload.
- **JCS canonicalization** (`vouch.jcs`): RFC 8785 implementation. Cross-implementation interop verified against shared test vectors at `test-vectors/jcs/vectors.json`.
- **Multikey verification methods** (`vouch.multikey`): multibase + multicodec encoding for Ed25519 (`0xed01`) and ML-DSA-44 (`0x1207`). Algorithm-agnostic key resolution via `DIDDocument.get_ed25519_public_key()` (auto-falls-back to legacy JWK).
- **Hybrid post-quantum profile** (`Signer.sign_credential_hybrid`): optional `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite. Both Ed25519 and ML-DSA-44 sign the same JCS canonical bytes for graceful verifier downgrade. Aligns with NIST CNSA 2.0 / NSM-10 migration timelines. Requires `pip install vouch-protocol[pq]` for the optional `pqcrypto` dependency.
- **W3C VC envelope helpers** (`vouch.vc`): `build_vouch_credential`, `build_session_voucher`.
- **Async verifier credential path** (`AsyncVerifier.verify_credential`, `AsyncVerifier.check_vouch_credential`): mirrors the sync path with async DID resolution.
- **Three-language interop** with TypeScript (`typescript/`) and Go (`go-sidecar/`) producing byte-identical canonical form.
- **Three new defensive disclosures** (PAD-039, PAD-040, PAD-041) plus 16 amendments to existing PADs documenting W3C Data Integrity embodiments and JCS-determinism properties.

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
