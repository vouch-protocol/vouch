/**
 * Vouch Protocol TypeScript SDK — Portable (React-Native-safe) surface.
 *
 * This entry point exposes ONLY the modules that are pure and free of the
 * Node `crypto` module and `jose`, so it can be imported in environments
 * that cannot bundle Node built-ins — most notably React Native (Hermes).
 *
 * Import via the subpath:
 *
 *   import { decodeMultikey, canonicalize, buildVouchCredential }
 *     from '@vouch-protocol-official/sdk/portable';
 *
 * What is included (all dependency-free, side-effect-free):
 *   - Multikey encode/decode (DID key resolution)
 *   - JCS canonicalization (RFC 8785)
 *   - Vouch Credential builder + types/constants
 *
 * What is NOT included (these require Node `crypto` / `jose` and are only
 * available from the package root `@vouch-protocol-official/sdk`):
 *   - `Signer` / `Verifier`
 *   - Data Integrity proof signing/verification (`buildProof`/`verifyProof`,
 *     hybrid PQ variants)
 *   - `VouchClient` daemon client
 *
 * Consumers that need to sign proofs in React Native should perform the
 * Ed25519 signing themselves (e.g. with `@noble/ed25519`) over the JCS
 * canonical bytes produced here.
 */

// --- Multikey (DID key encode/decode) --------------------------------------
export {
  encodeEd25519Public,
  encodeMLDSA44Public,
  decode as decodeMultikey,
  algorithmOf as multikeyAlgorithm,
  ED25519_PUB_PREFIX,
  ED25519_PRIV_PREFIX,
  MLDSA44_PUB_PREFIX,
  MLDSA44_PRIV_PREFIX,
} from './multikey';

// --- JCS canonicalization (RFC 8785) ---------------------------------------
export { canonicalize, canonicalizeToString } from './jcs';

// --- Data Integrity proofs (eddsa-jcs-2022), RN-safe -----------------------
// Byte-compatible with the Node buildProof/verifyProof; sign/verify with raw
// 32-byte Ed25519 keys via @noble (no Node crypto, no jose).
export {
  buildProofPortable,
  verifyProofPortable,
  hashDataPortable,
  legacyProofDigestPortable,
} from './data-integrity-portable';
export type { BuildProofPortableOptions } from './data-integrity-portable';
export type { DataIntegrityProof } from './data-integrity';

// --- Vouch Credential builder ----------------------------------------------
export {
  VC_CONTEXT_V2,
  VOUCH_CONTEXT_V1,
  VC_TYPE,
  VOUCH_CREDENTIAL_TYPE,
  PROTOCOL_VERSION,
  buildVouchCredential,
} from './vc';
export type {
  VouchCredential,
  Intent,
  DelegationLink,
  CredentialSubject,
  BuildVouchCredentialOptions,
} from './vc';
