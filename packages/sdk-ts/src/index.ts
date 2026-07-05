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

export { Signer, generateIdentity, sign } from './signer';
export { Verifier, verify } from './verifier';
export { Agent } from './agent';
export type { AgentCreateOptions, AgentVerifyOptions } from './agent';
export { Credential } from './credential';
export {
  requireSigned,
  guardMcp,
  guardTools,
  DEFAULT_CREDENTIAL_ARG,
} from './guard';
export type { RequireSignedOptions } from './guard';
export {
  MemoryKeyStore,
  EncryptedFileKeyStore,
  resolveDefaultStore,
} from './keystore';
export type { KeyStore, StoredIdentity } from './keystore';
export { enrollDevice, verifyDelegatedChain, DeviceRegistry } from './fleet';
export type {
  EnrollDeviceOptions,
  FleetResult,
  VerifyDelegatedChainOptions,
} from './fleet';
export {
  splitSecret,
  combineShares,
  splitIdentity,
  recoverIdentity,
} from './recovery';
export type { SplitOptions, RecoveredIdentity } from './recovery';
export {
  ThresholdError,
  ThresholdSigner,
  groupPublicKeyMultikey,
  generateKey as thresholdGenerateKey,
  commit as thresholdCommit,
  signShare as thresholdSignShare,
  aggregate as thresholdAggregate,
} from './threshold';
export type { KeyShare, GroupPublicKey, GenerateKeyResult, Round1 } from './threshold';

export type {
  Passport,
  VerificationResult,
  CredentialPassport,
  CredentialVerificationResult,
  SignerConfig,
  VerifierConfig,
  JWKKey,
  SignOptions,
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
export {
  KILLSWITCH_TYPE,
  BLACKBOX_VERSION,
  EMERGENCY_STOP,
  GENESIS_PREV_HASH,
  BlackBoxError,
  BlackBoxLog,
  openEntry,
  verifyBlackboxChain,
  buildKillswitchCredential,
  verifyKillswitchCredential,
} from './robotics/blackbox';
export type { BuildKillswitchOptions } from './robotics/blackbox';
export {
  ROBOT_PASSPORT_TYPE,
  PASSPORT_URI_SCHEME,
  STATUS_ACTIVE,
  STATUS_SUSPENDED,
  STATUS_DECOMMISSIONED,
  PassportError,
  buildPassport,
  encodePassport,
  decodePassport,
  verifyPassport,
} from './robotics/passport';
export type { BuildPassportOptions, PassportSummary } from './robotics/passport';
export {
  ROBOT_HEARTBEAT_TYPE,
  DEFAULT_GRACE_INTERVALS,
  MotionCollector,
  validateMotionDigest,
  buildRobotHeartbeat,
  verifyRobotHeartbeat,
  isLive,
} from './robotics/liveness';
export type {
  MotionSample,
  MotionDigest,
  RecordMotionOptions,
  BuildHeartbeatOptions,
  IsLiveOptions,
} from './robotics/liveness';
export {
  StatusListError as RoboticsStatusListError,
  buildStatusListCredential as buildRoboticsStatusListCredential,
  buildStatusListEntry as buildRoboticsStatusListEntry,
  attachCredentialStatus,
  checkCredentialStatus,
} from './robotics/revocation';
export type {
  AttachCredentialStatusOptions,
  CheckCredentialStatusOptions,
} from './robotics/revocation';
export {
  SAFETY_RECORD_TYPE,
  SAFETY_LOG_VERSION,
  EVENT_TYPES,
  SEVERITIES,
  SafetyEventLog,
  verifySafetyLog,
  summarizeEntries,
  buildSafetyRecord,
  verifySafetyRecord,
  validateSafetySummary,
} from './robotics/safety_record';
export type {
  Severity,
  SafetySummary,
  AppendEventOptions,
  BuildSafetyRecordOptions,
} from './robotics/safety_record';
export {
  PERCEPTION_TYPE,
  PERCEPTION_LOG_VERSION,
  MODALITIES,
  hashFrame,
  PerceptionLog,
  verifyPerceptionLog,
  buildPerceptionAttestation,
  verifyPerceptionAttestation,
} from './robotics/perception';
export type {
  RecordFrameOptions,
  BuildPerceptionAttestationOptions,
} from './robotics/perception';
export {
  DELEGATION_LEASE_TYPE,
  buildDelegationLease,
  verifyDelegationLease,
  leasePermits,
} from './robotics/lease';
export type {
  BuildDelegationLeaseOptions,
  VerifyDelegationLeaseOptions,
  LeasePermitsOptions,
} from './robotics/lease';
export {
  ACTION_APPROVAL_TYPE,
  APPROVE,
  REJECT,
  buildActionApproval,
  verifyActionAuthorization,
} from './robotics/physical_quorum';
export type {
  BuildActionApprovalOptions,
  VerifyActionAuthorizationOptions,
} from './robotics/physical_quorum';
export {
  OWNERSHIP_TRANSFER_TYPE,
  KEY_ROTATION_TYPE,
  DECOMMISSION_TYPE,
  buildOwnershipTransfer,
  verifyOwnershipTransfer,
  verifyCustodyChain,
  buildKeyRotation,
  verifyKeyRotation,
  verifyKeyHistory,
  buildDecommission,
  verifyDecommission,
} from './robotics/lifecycle';
export type {
  BuildOwnershipTransferOptions,
  VerifyCustodyChainOptions,
  BuildKeyRotationOptions,
  BuildDecommissionOptions,
  VerifyDecommissionOptions,
} from './robotics/lifecycle';

// Regulatory conformance profiles, deterministic checker, and signed
// point-in-time attestation, byte-identical with the Python module.
export {
  CONFORMANCE_ATTESTATION_TYPE,
  PROFILES,
  profile,
  checkConformance,
  reportDigest,
  buildConformanceAttestation,
  verifyConformanceAttestation,
} from './robotics/conformance';
export type {
  Requirement,
  Profile,
  RequirementResult,
  ConformanceReport,
  BuildConformanceAttestationOptions,
} from './robotics/conformance';

// Cross-embodiment identity continuity: signed embodiment credentials,
// continuity-chain verification, and software fork detection, byte-identical
// with the Python module.
export {
  EMBODIMENT_TYPE,
  buildEmbodiment,
  verifyEmbodiment,
  verifyContinuityChain,
  checkNoFork,
} from './robotics/embodiment';
export type {
  BuildEmbodimentOptions,
  VerifyContinuityChainOptions,
  CheckNoForkConflict,
} from './robotics/embodiment';

// Physical custody handoff: signed handoff credentials, chain verification, a
// holder-at-time helper, and software condition localization, byte-identical
// with the Python module.
export {
  CUSTODY_HANDOFF_TYPE,
  buildHandoff,
  verifyHandoff,
  verifyHandoffChain,
  holderAt,
  locateConditionChange,
} from './robotics/custody';
export type {
  BuildHandoffOptions,
  VerifyHandoffChainOptions,
  ConditionChange,
} from './robotics/custody';

// Robot-to-infrastructure bounded access: signed grants and requests, an
// offline authorize decision, and shrink-only attenuation, byte-identical with
// the Python module.
export {
  ACCESS_GRANT_TYPE,
  ACCESS_REQUEST_TYPE,
  buildAccessGrant,
  verifyAccessGrant,
  buildAccessRequest,
  authorizeAccess,
  attenuatesGrant,
} from './robotics/access';
export type {
  BuildAccessGrantOptions,
  BuildAccessRequestOptions,
  AuthorizeResult,
} from './robotics/access';

// Fused-sensor provenance: a signed attestation binding a fused output to its
// input frame hashes and a fusion method, with a deterministic digest over the
// ordered inputs, byte-identical with the Python module.
export {
  FUSED_PERCEPTION_TYPE,
  hashFusedOutput,
  fusionInputsDigest,
  buildFusedAttestation,
  verifyFusedAttestation,
  verifyFusionInputs,
} from './robotics/fusion';
export type { BuildFusedAttestationOptions } from './robotics/fusion';

// Robot post-quantum signing (hybrid Ed25519 + ML-DSA-44, Specification §13.2)
export {
  CLASSICAL_CRYPTOSUITE,
  HYBRID_CRYPTOSUITE,
  signPq,
  isPq,
  verifyPq,
  verifyRobotCredential,
  migrateToPq,
} from './robotics/pq';
export type { VerifyRobotCredentialOptions } from './robotics/pq';

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
