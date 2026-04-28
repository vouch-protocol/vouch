/**
 * Vouch Protocol TypeScript SDK
 *
 * The official TypeScript SDK for Vouch Protocol, the open W3C-track
 * standard for cryptographic identity and provenance of AI agents.
 *
 * Two surfaces are exported from this package:
 *
 * 1. Cryptographic SDK (v1.0+): W3C Verifiable Credentials issuance
 *    and verification with W3C Data Integrity proofs (`eddsa-jcs-2022`),
 *    Multikey verification methods, optional hybrid post-quantum profile
 *    (`hybrid-eddsa-mldsa44-jcs-2026`). Use for issuing and verifying
 *    Vouch credentials directly.
 *
 * 2. Daemon Client: A client library for communicating with the Vouch
 *    Bridge Daemon over HTTP/fetch. Works in both Browser and Node.js.
 *    Use for delegating signing operations to a locally-running daemon.
 *
 * Both surfaces share the same agent identity model (DIDs, Multikey)
 * and can be used together: issue credentials cryptographically via
 * the SDK, or delegate to the daemon for centrally-managed key
 * material.
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// Cryptographic SDK (v1.0+)
// ---------------------------------------------------------------------------

export { Signer, generateIdentity } from './signer';
export { Verifier } from './verifier';

export type {
    Passport,
    VerificationResult,
    CredentialPassport,
    CredentialVerificationResult,
    SignerConfig,
    VerifierConfig,
    JWKKey,
    SignCredentialOptions,
} from './types';

export type {
    VouchCredential,
    Intent,
    DelegationLink,
    CredentialSubject,
} from './vc';
export {
    VC_CONTEXT_V2,
    VOUCH_CONTEXT_V1,
    VC_TYPE,
    VOUCH_CREDENTIAL_TYPE,
    PROTOCOL_VERSION,
    buildVouchCredential,
} from './vc';

export {
    canonicalize,
    canonicalizeToString,
} from './jcs';
export {
    encodeEd25519Public,
    encodeMLDSA44Public,
    decode as decodeMultikey,
    algorithmOf as multikeyAlgorithm,
} from './multikey';
export {
    buildProof,
    verifyProof,
    CRYPTOSUITE_ID as DATA_INTEGRITY_CRYPTOSUITE,
    PROOF_TYPE as DATA_INTEGRITY_PROOF_TYPE,
} from './data-integrity';
export type { DataIntegrityProof } from './data-integrity';
export {
    buildHybridProof,
    verifyHybridProof,
    generateMLDSA44KeyPair,
    hybridVerificationMethodPair,
    HYBRID_CRYPTOSUITE_ID,
} from './data-integrity-hybrid';
export type { HybridKeyPair, BuildHybridProofOptions } from './data-integrity-hybrid';

// ---------------------------------------------------------------------------
// Daemon Client
// ---------------------------------------------------------------------------

export {
    VouchClient,
    VouchClientConfig,
    DaemonStatus,
    PublicKeyInfo,
    SignMetadata,
    SignResult,
    MediaSignResult,
    UserDeniedSignatureError,
    DaemonNotAvailableError,
    NoKeysConfiguredError,
} from './vouch-client';

// ---------------------------------------------------------------------------
// Package version
// ---------------------------------------------------------------------------

export const VERSION = '1.0.0';
