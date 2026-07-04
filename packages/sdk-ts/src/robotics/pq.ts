/**
 * Post-quantum signing for robot credentials (TypeScript).
 *
 * Mirrors `vouch/robotics/pq.py`. A robot fielded today lives for ten to twenty
 * years, longer than classical Ed25519 is expected to stay safe, so a robot
 * identity signed now could be forged once a quantum computer arrives. This
 * module makes the hybrid post-quantum cryptosuite
 * (`hybrid-eddsa-mldsa44-jcs-2026`, a classical Ed25519 signature alongside an
 * ML-DSA-44 signature) the recommended default for robot credentials, so they
 * stay unforgeable across the robot's whole service life.
 *
 *   - signPq: attach a hybrid proof to a robot credential.
 *   - verifyRobotCredential: verify a robot credential whether it carries a
 *     classical or a hybrid proof, auto-detected from the proof, so a fleet can
 *     move to PQ gradually without breaking the classical credentials already in
 *     the field.
 *   - migrateToPq: re-sign a fielded robot's classical credential under PQ.
 *
 * This is the open layer: hybrid signing, backward-compatible verification, and
 * a software re-signing migration path. Managed PQ key custody and fleet-wide PQ
 * migration orchestration are out of scope for the open layer.
 */

import * as crypto from 'crypto';

import { CRYPTOSUITE_ID as CLASSICAL_CRYPTOSUITE_ID, verifyProof } from '../data-integrity';
import { HYBRID_CRYPTOSUITE_ID, verifyHybridProof } from '../data-integrity-hybrid';
import { decode as decodeMultikey } from '../multikey';
import type { Signer } from '../signer';

import { RoboticsError } from './identity';

export const CLASSICAL_CRYPTOSUITE = CLASSICAL_CRYPTOSUITE_ID;
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
 * Attach a hybrid (classical Ed25519 plus post-quantum ML-DSA-44) Data Integrity
 * proof to a pre-built robot `credential`. Any existing proof is replaced.
 */
export async function signPq(
  credential: Record<string, unknown>,
  signer: Signer
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(credential)) {
    if (k !== 'proof') body[k] = v;
  }
  return signer.attachProofHybrid(body);
}

/**
 * Return true if `credential` carries a hybrid post-quantum proof.
 */
export function isPq(credential: Record<string, unknown>): boolean {
  const proof = (credential.proof ?? {}) as Record<string, unknown>;
  return proof.cryptosuite === HYBRID_CRYPTOSUITE;
}

/**
 * Verify a hybrid robot credential. Both the Ed25519 and the ML-DSA-44 signature
 * must validate. `mldsa44PublicKey` is raw bytes or a Multikey string.
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
    return verifyHybridProof(credential, resolvedEd, resolvedMl);
  } catch {
    return false;
  }
}

export interface VerifyRobotCredentialOptions {
  mldsa44PublicKey?: Uint8Array | string;
}

/**
 * Verify a robot credential whether it carries a classical or a hybrid proof,
 * auto-detected from the proof cryptosuite. A hybrid credential requires
 * `mldsa44PublicKey`; a classical credential ignores it. This is the
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
 * Re-sign a fielded robot's classical `credential` under the hybrid PQ
 * cryptosuite, preserving its body. The signer holds the robot's current key.
 */
export async function migrateToPq(
  credential: Record<string, unknown>,
  signer: Signer
): Promise<Record<string, unknown>> {
  return signPq(credential, signer);
}
