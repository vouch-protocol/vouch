/**
 * Post-quantum signing for robot credentials (TypeScript).
 *
 * Mirrors `vouch/robotics/pq.py` and the robotics section of the Rust core. A
 * robot fielded today lives for ten to twenty years, longer than classical
 * Ed25519 is expected to stay safe, so a robot identity signed now could be
 * forged once a quantum computer arrives. This module makes the post-quantum
 * proof set (an `eddsa-jcs-2022` proof alongside an `mldsa44-jcs-2024` proof)
 * the recommended default for robot credentials, so they stay unforgeable
 * across the robot's whole service life.
 *
 *   - signPq: attach a post-quantum proof set to a robot credential.
 *   - verifyRobotCredential: verify a robot credential whether it carries a
 *     classical proof, a proof set, or the pre-alignment composite proof,
 *     auto-detected from the proof, so a fleet can move to PQ gradually without
 *     breaking the credentials already in the field.
 *   - migrateToPq: re-sign a fielded robot's classical credential under PQ.
 *
 * This is the open layer: post-quantum signing, backward-compatible
 * verification, and a software re-signing migration path. Managed PQ key
 * custody and fleet-wide PQ migration orchestration are out of scope for the
 * open layer.
 */

import * as crypto from 'crypto';

import { CRYPTOSUITE_ID as CLASSICAL_CRYPTOSUITE_ID, verifyProof } from '../data-integrity';
import {
  HYBRID_CRYPTOSUITE_ID,
  MLDSA44_CRYPTOSUITE_ID,
  hybridVerificationMethodPair,
  isMlDsaCryptosuite,
  verifyDualProof,
  verifyHybridProof,
} from '../data-integrity-hybrid';
import { decode as decodeMultikey } from '../multikey';
import type { Signer } from '../signer';

import { RoboticsError } from './identity';

export const CLASSICAL_CRYPTOSUITE = CLASSICAL_CRYPTOSUITE_ID;
/** The post-quantum member of the proof set robot credentials now carry. */
export const PQ_CRYPTOSUITE = MLDSA44_CRYPTOSUITE_ID;
/** The pre-alignment composite cryptosuite, accepted on verification only. */
export const HYBRID_CRYPTOSUITE = HYBRID_CRYPTOSUITE_ID;

/**
 * Coerce an Ed25519 public key into a Node KeyObject. Accepts a KeyObject as-is,
 * a JWK object, or a JWK JSON string. Returns null if it cannot be resolved.
 */
function coerceEd25519Public(
  publicKey: crypto.KeyObject | Record<string, unknown> | string
): crypto.KeyObject | null {
  if (publicKey instanceof crypto.KeyObject) {
    return publicKey;
  }
  try {
    const jwk =
      typeof publicKey === 'string'
        ? (JSON.parse(publicKey) as crypto.JsonWebKey)
        : (publicKey as crypto.JsonWebKey);
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    return null;
  }
}

/**
 * Coerce an ML-DSA-44 public key into raw bytes. Accepts raw bytes or a Multikey
 * (z-prefixed) string. Throws RoboticsError on a non-ML-DSA multikey or an
 * unsupported input type.
 */
function coerceMldsa44Public(publicKey: Uint8Array | string): Uint8Array {
  if (publicKey instanceof Uint8Array) {
    return publicKey;
  }
  if (typeof publicKey === 'string') {
    const { algorithm, rawKey } = decodeMultikey(publicKey);
    const alg = algorithm.toLowerCase();
    if (!alg.includes('mldsa') && !alg.includes('ml-dsa')) {
      throw new RoboticsError(`expected an ML-DSA-44 multikey, got ${algorithm}`);
    }
    return rawKey;
  }
  throw new RoboticsError('ML-DSA-44 public key must be raw bytes or a Multikey string');
}

/**
 * The Ed25519 and ML-DSA-44 verification method slots for a robot credential:
 * `{issuer}#key-1` and `{issuer}#key-2`, the convention the core and every SDK
 * derive for the two members of a post-quantum proof set. Falls back to the
 * signer's own slots when the credential carries no issuer.
 */
function pqVerificationMethods(
  credential: Record<string, unknown>,
  signer: Signer
): { ed25519: string; mldsa44: string } {
  const issuer = credential.issuer;
  if (typeof issuer === 'string' && issuer.length > 0) {
    return { ed25519: `${issuer}#key-1`, mldsa44: `${issuer}#key-2` };
  }
  const vm = signer.verificationMethodId();
  return { ed25519: vm, mldsa44: hybridVerificationMethodPair(vm).mldsa44 };
}

/**
 * Attach a post-quantum proof SET (an `eddsa-jcs-2022` proof plus an
 * `mldsa44-jcs-2024` proof) to a pre-built robot `credential`. Any existing
 * proof is replaced.
 */
export async function signPq(
  credential: Record<string, unknown>,
  signer: Signer
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(credential)) {
    if (k !== 'proof') body[k] = v;
  }
  const vms = pqVerificationMethods(body, signer);
  return signer.attachProofHybrid(body, {
    ed25519VerificationMethod: vms.ed25519,
    mldsa44VerificationMethod: vms.mldsa44,
  });
}

/**
 * Return true if `credential` carries a post-quantum proof, in either shape:
 * a `proof` ARRAY holding an ML-DSA-44 proof, or the pre-alignment composite
 * proof object.
 */
export function isPq(credential: Record<string, unknown>): boolean {
  const proof = credential.proof;
  if (Array.isArray(proof)) {
    return proof.some((p) =>
      isMlDsaCryptosuite((p as Record<string, unknown> | null)?.cryptosuite)
    );
  }
  if (proof && typeof proof === 'object') {
    return (proof as Record<string, unknown>).cryptosuite === HYBRID_CRYPTOSUITE;
  }
  return false;
}

/**
 * Verify a post-quantum robot credential in whichever shape it carries: a proof
 * set goes to the dual verifier, a composite proof object to the composite
 * verifier. Both the Ed25519 and the ML-DSA-44 signature must validate in
 * either shape, and no proof present in a set is ever skipped.
 */
function verifyPqEitherShape(
  credential: Record<string, unknown>,
  ed25519PublicKey: crypto.KeyObject,
  mldsa44PublicKey: Uint8Array
): boolean {
  if (Array.isArray(credential.proof)) {
    return verifyDualProof(credential, ed25519PublicKey, mldsa44PublicKey);
  }
  return verifyHybridProof(credential, ed25519PublicKey, mldsa44PublicKey);
}

/**
 * Verify a post-quantum robot credential. Both the Ed25519 and the ML-DSA-44
 * signature must validate. `mldsa44PublicKey` is raw bytes or a Multikey
 * string.
 */
export function verifyPq(
  credential: Record<string, unknown>,
  ed25519PublicKey: crypto.KeyObject | Record<string, unknown> | string,
  mldsa44PublicKey: Uint8Array | string
): boolean {
  const resolvedEd = coerceEd25519Public(ed25519PublicKey);
  if (resolvedEd === null) return false;
  let resolvedMl: Uint8Array;
  try {
    resolvedMl = coerceMldsa44Public(mldsa44PublicKey);
  } catch {
    return false;
  }
  try {
    return verifyPqEitherShape(credential, resolvedEd, resolvedMl);
  } catch {
    return false;
  }
}

export interface VerifyRobotCredentialOptions {
  mldsa44PublicKey?: Uint8Array | string;
}

/**
 * Verify a robot credential whether it carries a classical proof, a
 * post-quantum proof set, or the pre-alignment composite proof, auto-detected
 * from the proof. A post-quantum credential REQUIRES `mldsa44PublicKey` and
 * fails closed (returns false) without it, so a missing key is never mistaken
 * for a passing check. A classical credential ignores it. This is the
 * backward-compatible verify a fleet uses while migrating to PQ.
 */
export function verifyRobotCredential(
  credential: Record<string, unknown>,
  ed25519PublicKey: crypto.KeyObject | Record<string, unknown> | string,
  opts: VerifyRobotCredentialOptions = {}
): boolean {
  if (isPq(credential)) {
    if (opts.mldsa44PublicKey === undefined) return false;
    return verifyPq(credential, ed25519PublicKey, opts.mldsa44PublicKey);
  }
  const resolvedEd = coerceEd25519Public(ed25519PublicKey);
  if (resolvedEd === null) return false;
  try {
    return verifyProof(credential, resolvedEd);
  } catch {
    return false;
  }
}

/**
 * Re-sign a fielded robot's classical `credential` under the post-quantum
 * proof set, preserving its body. The signer holds the robot's current key.
 */
export async function migrateToPq(
  credential: Record<string, unknown>,
  signer: Signer
): Promise<Record<string, unknown>> {
  return signPq(credential, signer);
}
