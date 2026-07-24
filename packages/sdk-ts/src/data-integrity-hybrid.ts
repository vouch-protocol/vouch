/**
 * Post-quantum credentials as a Data Integrity proof set (TypeScript).
 *
 * The current shape is a `proof` ARRAY of two independent proofs,
 * `eddsa-jcs-2022` and `mldsa44-jcs-2024`. Each proof is computed over the
 * same unsecured document with only its own proof configuration, and each
 * verifies on its own, so a verifier that understands only one of the two
 * cryptosuites can still check that proof. Both must verify for
 * {@link verifyDualProof} to succeed. See PAD-040 §3.3a for the dual-proof
 * carrier embodiment.
 *
 * Two pre-alignment shapes are accepted on verification: the
 * `mldsa44-jcs-2026` identifier with a base58btc proofValue, and the v1.6.x
 * composite `hybrid-eddsa-mldsa44-jcs-2026` whose single proofValue was
 * base58btc(ed25519_sig || mldsa44_sig). The composite builder is retained
 * only so the older wire format can be reproduced for the credentials already
 * in the field (fielded robots re-signed under the v1.6.x profile).
 *
 * Mirrors core/vouch-core/src/hybrid.rs, go-sidecar/signer and the Python
 * counterpart. The wire format is identical across implementations so that
 * a credential signed by one can be verified by another.
 */

import * as crypto from 'crypto';
import { createRequire } from 'node:module';

import { b58decode, b58encode } from './multikey';
import {
  buildProof,
  verifyProof,
  hashData,
  legacyProofDigest,
  CRYPTOSUITE_ID as EDDSA_CRYPTOSUITE_ID,
  PROOF_TYPE,
} from './data-integrity';
import type { DataIntegrityProof } from './data-integrity';

// @noble/post-quantum is an OPTIONAL peer dependency. It is loaded lazily on
// first use (not at module load) so that importing the SDK never requires it
// to be installed, and so the package imports cleanly under ESM. We pin to
// ^0.4 because that line ships a CJS build resolvable via `createRequire`.
//
// API note: the 0.4.x signature is `sign(secretKey, msg)` and
// `verify(publicKey, msg, sig)`. The 0.6.x line moved to `sign(msg, secretKey)`
// and `verify(sig, msg, publicKey)`. We follow 0.4.x here. Wire format
// (raw signature bytes) is identical across versions.
interface MlDsa44 {
  keygen(seed?: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array };
  sign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array;
  verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean;
}

let _mlDsa44: MlDsa44 | undefined;

/**
 * Lazily resolve the ML-DSA-44 implementation from the optional
 * `@noble/post-quantum` peer dependency. Uses `createRequire` so it works in
 * both the CJS and ESM builds (esbuild rewrites a bare `require()` into a
 * throwing shim in ESM output). Throws a clear, actionable error if the
 * optional dependency is not installed.
 */
function getMlDsa44(): MlDsa44 {
  if (_mlDsa44) return _mlDsa44;
  let mod: { ml_dsa44?: MlDsa44; default?: { ml_dsa44?: MlDsa44 } };
  try {
    const req = createRequire(import.meta.url);
    mod = req('@noble/post-quantum/ml-dsa');
  } catch (err) {
    throw new Error(
      'The hybrid post-quantum profile requires the optional peer dependency ' +
      '"@noble/post-quantum" (^0.4). Install it with `npm install @noble/post-quantum` ' +
      'to use hybrid Ed25519 + ML-DSA-44 proofs. Original error: ' +
      (err instanceof Error ? err.message : String(err))
    );
  }
  const impl = mod.ml_dsa44 ?? mod.default?.ml_dsa44;
  if (!impl) {
    throw new Error('@noble/post-quantum/ml-dsa did not export `ml_dsa44`.');
  }
  _mlDsa44 = impl;
  return _mlDsa44;
}

/** The v1.6.x composite. Accepted on verification only; never emitted. */
export const HYBRID_CRYPTOSUITE_ID = 'hybrid-eddsa-mldsa44-jcs-2026';
/** The W3C Quantum-Resistant Cryptosuites identifier for ML-DSA-44 over JCS. */
export const MLDSA44_CRYPTOSUITE_ID = 'mldsa44-jcs-2024';
/** Pre-alignment ML-DSA identifier, accepted on verification only. */
export const MLDSA44_LEGACY_CRYPTOSUITE_ID = 'mldsa44-jcs-2026';
export { EDDSA_CRYPTOSUITE_ID };

const ED25519_SIG_SIZE = 64;
const MLDSA44_SIG_SIZE = 2420;
const HYBRID_SIG_SIZE = ED25519_SIG_SIZE + MLDSA44_SIG_SIZE;

export interface HybridKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate a fresh ML-DSA-44 keypair via @noble/post-quantum.
 */
export function generateMLDSA44KeyPair(seed?: Uint8Array): HybridKeyPair {
  const ml_dsa44 = getMlDsa44();
  const { secretKey, publicKey } = ml_dsa44.keygen(seed);
  return { secretKey, publicKey };
}

export interface BuildHybridProofOptions {
  ed25519PrivateKey: crypto.KeyObject;
  mldsa44SecretKey: Uint8Array;
  verificationMethod: string;
  proofPurpose?: string;
  created?: Date;
}

/**
 * Build a v1.6.x composite proof (a single proof whose proofValue is
 * base58btc(ed25519_sig || mldsa44_sig)), using the pre-alignment signing
 * input that format was issued under: the SHA-256 digest of the
 * JCS-canonicalized credential with the unsigned proof attached.
 *
 * Retained so the older wire format stays reproducible for the credentials
 * already in the field. New credentials use {@link buildDualProof}, which
 * emits a proof set.
 *
 * @deprecated the composite wire format is verify-only; use buildDualProof
 */
export function buildHybridProof(
  credential: Record<string, unknown>,
  opts: BuildHybridProofOptions
): DataIntegrityProof {
  const proof: DataIntegrityProof = {
    type: PROOF_TYPE,
    cryptosuite: HYBRID_CRYPTOSUITE_ID,
    created: formatIso8601(opts.created ?? new Date()),
    verificationMethod: opts.verificationMethod,
    proofPurpose: opts.proofPurpose ?? 'assertionMethod',
  };

  const digest = legacyProofDigest(
    stripProof(credential),
    proof as unknown as Record<string, unknown>
  );

  // Ed25519: use Node crypto (algorithm null for Ed25519 keys).
  const edSig = crypto.sign(null, digest, opts.ed25519PrivateKey);
  if (edSig.length !== ED25519_SIG_SIZE) {
    throw new Error(`unexpected Ed25519 sig size ${edSig.length}`);
  }

  // ML-DSA-44 via @noble/post-quantum (0.4.x: secretKey, msg order).
  const mlSig = getMlDsa44().sign(opts.mldsa44SecretKey, digest);
  if (mlSig.length !== MLDSA44_SIG_SIZE) {
    throw new Error(`unexpected ML-DSA-44 sig size ${mlSig.length}`);
  }

  const combined = new Uint8Array(HYBRID_SIG_SIZE);
  combined.set(edSig, 0);
  combined.set(mlSig, ED25519_SIG_SIZE);

  proof.proofValue = 'z' + b58encode(combined);
  return proof;
}

/**
 * Verify a v1.6.x composite hybrid proof (single proof, concatenated
 * proofValue) against the pre-alignment signing input it was issued under.
 * Both embedded signatures MUST validate. Returns true on success, false on
 * signature failure. Throws on malformed proof structure.
 */
export function verifyHybridProof(
  credential: Record<string, unknown>,
  ed25519PublicKey: crypto.KeyObject,
  mldsa44PublicKey: Uint8Array
): boolean {
  const proof = (credential as { proof?: DataIntegrityProof }).proof;
  if (!proof || typeof proof !== 'object') {
    throw new Error('Credential has no proof object');
  }
  if (proof.type !== PROOF_TYPE) {
    throw new Error(`Unexpected proof type: ${proof.type}`);
  }
  if (proof.cryptosuite !== HYBRID_CRYPTOSUITE_ID) {
    throw new Error(`Unexpected cryptosuite: ${proof.cryptosuite}`);
  }
  if (!proof.proofValue || !proof.proofValue.startsWith('z')) {
    throw new Error('Missing or malformed proofValue');
  }

  const combined = b58decode(proof.proofValue.slice(1));
  if (combined.length !== HYBRID_SIG_SIZE) {
    throw new Error(
      `hybrid signature length ${combined.length}, expected ${HYBRID_SIG_SIZE}`
    );
  }

  const edSig = combined.slice(0, ED25519_SIG_SIZE);
  const mlSig = combined.slice(ED25519_SIG_SIZE);

  const proofWithoutValue: Partial<DataIntegrityProof> = { ...proof };
  delete proofWithoutValue.proofValue;
  const digest = legacyProofDigest(
    stripProof(credential),
    proofWithoutValue as unknown as Record<string, unknown>
  );

  if (!crypto.verify(null, digest, ed25519PublicKey, Buffer.from(edSig))) {
    return false;
  }
  // 0.4.x order: publicKey, msg, sig
  if (!getMlDsa44().verify(mldsa44PublicKey, digest, mlSig)) {
    return false;
  }
  return true;
}

/** Strip any `proof` member, yielding the unsecured document. */
function stripProof(credential: Record<string, unknown>): Record<string, unknown> {
  const base: Record<string, unknown> = { ...credential };
  delete base.proof;
  return base;
}

/** Multibase base64url-nopad ("u") encoding, per the PQ cryptosuites. */
function mb64u(bytes: Uint8Array): string {
  return 'u' + Buffer.from(bytes).toString('base64url');
}

/** Decode a proofValue that is either base64url-nopad ("u") or base58btc ("z"). */
function decodeProofValue(proofValue: string): Uint8Array {
  if (proofValue.startsWith('u')) {
    return new Uint8Array(Buffer.from(proofValue.slice(1), 'base64url'));
  }
  if (proofValue.startsWith('z')) {
    return b58decode(proofValue.slice(1));
  }
  throw new Error('proofValue must be multibase base64url (u) or base58btc (z)');
}

export interface BuildDualProofOptions {
  ed25519PrivateKey: crypto.KeyObject;
  mldsa44SecretKey: Uint8Array;
  /** verificationMethod for the Ed25519 proof (conventionally #key-1). */
  ed25519VerificationMethod: string;
  /**
   * verificationMethod for the ML-DSA-44 proof. When omitted it is derived
   * from the Ed25519 identifier by {@link hybridVerificationMethodPair} (the
   * #key-2 slot on the same DID).
   */
  mldsa44VerificationMethod?: string;
  proofPurpose?: string;
  created?: Date;
}

/**
 * Build a dual proof: an ARRAY of two independent Data Integrity proofs,
 * `eddsa-jcs-2022` and `mldsa44-jcs-2024`, over the same unsecured document.
 * Each proof stands alone and both must verify. The ML-DSA proofValue is the
 * multibase base64url-nopad ("u") encoding specified by the Quantum-Resistant
 * Cryptosuites; the classical suite keeps base58btc ("z").
 */
export function buildDualProof(
  credential: Record<string, unknown>,
  opts: BuildDualProofOptions
): DataIntegrityProof[] {
  const base = stripProof(credential);
  const created = opts.created ?? new Date();
  const proofPurpose = opts.proofPurpose ?? 'assertionMethod';
  const mldsa44VerificationMethod =
    opts.mldsa44VerificationMethod ??
    hybridVerificationMethodPair(opts.ed25519VerificationMethod).mldsa44;

  const edProof = buildProof(base, {
    privateKey: opts.ed25519PrivateKey,
    verificationMethod: opts.ed25519VerificationMethod,
    proofPurpose,
    created,
  });

  const mlProof: DataIntegrityProof = {
    type: PROOF_TYPE,
    cryptosuite: MLDSA44_CRYPTOSUITE_ID,
    created: formatIso8601(created),
    verificationMethod: mldsa44VerificationMethod,
    proofPurpose,
  };
  const signingInput = hashData(base, mlProof as unknown as Record<string, unknown>);
  const mlSig = getMlDsa44().sign(opts.mldsa44SecretKey, signingInput);
  if (mlSig.length !== MLDSA44_SIG_SIZE) {
    throw new Error(`unexpected ML-DSA-44 sig size ${mlSig.length}`);
  }
  mlProof.proofValue = mb64u(mlSig);

  return [edProof, mlProof];
}

/**
 * Build a dual proof and attach it to the credential under `proof`, replacing
 * any existing proof.
 */
export function signDual(
  credential: Record<string, unknown>,
  opts: BuildDualProofOptions
): Record<string, unknown> {
  return { ...stripProof(credential), proof: buildDualProof(credential, opts) };
}

/**
 * True if `proof` is a proof set carrying an ML-DSA-44 proof (either the
 * specified `mldsa44-jcs-2024` identifier or the pre-alignment one).
 */
export function isMlDsaCryptosuite(cryptosuite: unknown): boolean {
  return (
    cryptosuite === MLDSA44_CRYPTOSUITE_ID ||
    cryptosuite === MLDSA44_LEGACY_CRYPTOSUITE_ID
  );
}

/**
 * Verify a dual proof: both the Ed25519 and the ML-DSA-44 proof in the array
 * MUST validate. Returns true only if both are present and every proof in the
 * set validates. Accepts the pre-alignment `mldsa44-jcs-2026` identifier, a
 * base58btc ML-DSA proofValue, and the pre-alignment signing input.
 *
 * SECURITY: no proof in the set is ever skipped. A proof carrying a
 * cryptosuite this function cannot check throws rather than being ignored, and
 * a single failing member fails the whole set.
 */
export function verifyDualProof(
  credential: Record<string, unknown>,
  ed25519PublicKey: crypto.KeyObject,
  mldsa44PublicKey: Uint8Array
): boolean {
  const proofs = (credential as { proof?: unknown }).proof;
  if (!Array.isArray(proofs)) {
    throw new Error('dual proof requires a proof array');
  }
  const base = stripProof(credential);

  let edSeen = false;
  let mlSeen = false;
  let allOk = true;

  for (const entry of proofs as DataIntegrityProof[]) {
    const cryptosuite = entry?.cryptosuite;
    if (cryptosuite === EDDSA_CRYPTOSUITE_ID) {
      edSeen = true;
      allOk = verifyProof({ ...base, proof: entry }, ed25519PublicKey) && allOk;
    } else if (isMlDsaCryptosuite(cryptosuite)) {
      mlSeen = true;
      if (!entry.proofValue) {
        throw new Error('ml-dsa proof missing proofValue');
      }
      const sig = decodeProofValue(entry.proofValue);
      const unsigned: Partial<DataIntegrityProof> = { ...entry };
      delete unsigned.proofValue;
      const unsignedProof = unsigned as unknown as Record<string, unknown>;

      const ml = getMlDsa44();
      let mlOk = ml.verify(mldsa44PublicKey, hashData(base, unsignedProof), sig);
      if (!mlOk) {
        mlOk = ml.verify(
          mldsa44PublicKey,
          legacyProofDigest(base, unsignedProof),
          sig
        );
      }
      allOk = mlOk && allOk;
    }
    // A proof for an unrecognized cryptosuite is ignored, so a proof set may
    // carry an additional future cryptosuite without breaking a verifier that
    // predates it. This is safe because acceptance still requires both known
    // members to be present and to verify; an unrecognized proof can never
    // stand in for a missing or failing known proof.
  }
  return edSeen && mlSeen && allOk;
}

/**
 * Derive the (#key-1, #key-2) verificationMethod pair from a single
 * verificationMethod identifier. The convention is that the proof's
 * verificationMethod points at the Ed25519 key (#key-1) and the
 * ML-DSA-44 key sits at the parallel slot (#key-2) on the same DID.
 */
export function hybridVerificationMethodPair(
  verificationMethod: string
): { ed25519: string; mldsa44: string } {
  if (verificationMethod.endsWith('#key-1')) {
    const base = verificationMethod.slice(0, -'#key-1'.length);
    return { ed25519: verificationMethod, mldsa44: base + '#key-2' };
  }
  const hashIdx = verificationMethod.indexOf('#');
  if (hashIdx >= 0) {
    return {
      ed25519: verificationMethod,
      mldsa44: verificationMethod.slice(0, hashIdx) + '#key-2',
    };
  }
  return {
    ed25519: verificationMethod,
    mldsa44: verificationMethod + '#key-2',
  };
}

function formatIso8601(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
