/**
 * Vouch Protocol, TypeScript SDK
 *
 * The Identity & Reputation Standard for AI Agents.
 *
 * Two coexisting issuance/verification paths:
 *
 *   1. Legacy JWS (v0.x): Signer.sign() and Verifier.verify().
 *   2. W3C VC + Data Integrity (v1.0, eddsa-jcs-2022):
 *      Signer.signCredential() and Verifier.verifyCredential().
 *
 * New code should prefer the modern path.
 */

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

// W3C VC envelope types
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

// Cryptosuite primitives
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

/**
 * Package version
 */
export const VERSION = '1.4.0';
