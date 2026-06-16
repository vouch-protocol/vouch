/**
 * Vouch Protocol TypeScript SDK
 *
 * The official TypeScript SDK for Vouch Protocol, the open standards-aligned
 * standard for cryptographic identity and provenance of AI agents.
 *
 * Two surfaces are exported from this package:
 *
 * 1. Cryptographic SDK (v1.0+): Verifiable Credentials issuance
 *  and verification with Data Integrity proofs (`eddsa-jcs-2022`),
 *  Multikey verification methods, optional hybrid post-quantum profile
 *  (`hybrid-eddsa-mldsa44-jcs-2026`). Use for issuing and verifying
 *  Vouch credentials directly.
 *
 * 2. Daemon Client: A client library for communicating with the Vouch
 *  Bridge Daemon over HTTP/fetch. Works in both Browser and Node.js.
 *  Use for delegating signing operations to a locally-running daemon.
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

// Robotics (Phase 5): hardware-rooted robot identity and embodied-agent
// credentials, byte-identical with the Python `vouch.robotics` package.
export {
  ROBOT_IDENTITY_TYPE,
  RoboticsError,
  SoftwareRootOfTrust,
  mintRobotIdentity,
  verifyRobotIdentity,
  lifecycleEvent,
} from './robotics/identity';
export type {
  HardwareRootOfTrust,
  MintRobotIdentityOptions,
} from './robotics/identity';
export {
  MODEL_PROVENANCE_TYPE,
  configHash,
  buildProvenanceAttestation,
  verifyProvenanceAttestation,
} from './robotics/provenance';
export type { BuildProvenanceOptions } from './robotics/provenance';
export {
  PHYSICAL_SCOPE_TYPE,
  buildPhysicalScopeCredential,
  checkPhysicalAction,
  attenuates,
} from './robotics/capability';
export type {
  PhysicalAction,
  CheckResult,
  ShiftWindow,
  BuildPhysicalScopeOptions,
} from './robotics/capability';
export {
  HELLO,
  ACCEPT,
  CONFIRM,
  HandshakeError,
  TrustPolicy,
  buildHello,
  buildAccept,
  verifyAccept,
  buildConfirm,
  verifyConfirm,
} from './robotics/handshake';
export type {
  BoundedSession,
  BuildHelloOptions,
  BuildAcceptOptions,
} from './robotics/handshake';

// BitstringStatusList (VC-BITSTRING-STATUS-LIST, Specification §11.2)
export {
  StatusList,
  StatusListError,
  buildStatusListCredential,
  buildStatusListEntry,
  verifyStatus,
  DEFAULT_BITSTRING_LENGTH,
  STATUS_PURPOSE_REVOCATION,
  STATUS_PURPOSE_SUSPENSION,
  STATUS_PURPOSE_MESSAGE,
  VALID_STATUS_PURPOSES,
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_SUBJECT_TYPE,
  BITSTRING_STATUS_LIST_ENTRY_TYPE,
  MULTIBASE_BASE64URL_PREFIX,
} from './status-list';
export type {
  StatusPurpose,
  BitstringStatusListCredential,
  BitstringStatusListEntry,
  StatusListOptions,
  BuildStatusListCredentialOptions,
  BuildStatusListEntryOptions,
  VerifyStatusOptions,
  StatusListStateDict,
} from './status-list';

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

export const VERSION = '1.1.0';
