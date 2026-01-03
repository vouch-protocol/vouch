# Changelog

All notable changes to Vouch Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Chain of Custody (delegation chains) for multi-agent systems
- W3C specification draft

### Fixed
- Resolved jwcrypto deprecation warnings

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

[Unreleased]: https://github.com/vouch-protocol/vouch/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/vouch-protocol/vouch/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/vouch-protocol/vouch/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/vouch-protocol/vouch/compare/v1.1.3...v1.2.0
[1.1.3]: https://github.com/vouch-protocol/vouch/compare/v1.1.0...v1.1.3
[1.1.0]: https://github.com/vouch-protocol/vouch/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/vouch-protocol/vouch/releases/tag/v1.0.0
