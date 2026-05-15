/**
 * Hybrid Ed25519 + ML-DSA-44 Data Integrity proofs (TypeScript).
 *
 * NOTE (2026-05-16): This module implements the v1.6.x transitional
 * composite cryptosuite `hybrid-eddsa-mldsa44-jcs-2026`. Per Manu Sporny's
 * review feedback on the W3C CG Report, v1.7 of the specification
 * reformulates the hybrid profile as TWO independent Data Integrity
 * proofs on the same credential (`eddsa-jcs-2022` and `mldsa44-jcs-2026`),
 * rather than a single composite cryptosuite with a concatenated
 * proofValue. See PAD-040 §3.3a for the dual-proof carrier embodiment
 * and the Editor Review Queue at the top of docs/specs/w3c-cg-report.md
 * (entries 9-10) for the spec changes.
 *
 * This module remains the reference implementation while the dual-proof
 * rewrite waits on Digital Bazaar's forthcoming JCS variant of the
 * `mldsa44-rdfc-2024-cryptosuite` family and W3C registration of the
 * `mldsa44-jcs-*` cryptosuite identifier.
 *
 * Mirrors go-sidecar/signer/data_integrity_hybrid.go and the Python
 * counterpart. The wire format is identical across implementations so that
 * a credential signed by one can be verified by another.
 *
 * Wire format (composite, v1.6.x transitional):
 *  proofValue = "z" + base58btc( ed25519_sig (64 bytes) || mldsa44_sig (2420 bytes) )
 */

import * as crypto from 'crypto';

import { canonicalize } from './jcs';
import { b58decode, b58encode } from './multikey';
import {
  PROOF_TYPE,
} from './data-integrity';
import type { DataIntegrityProof } from './data-integrity';

// We pin @noble/post-quantum to ^0.4 because that release line still
// publishes a CJS build, which keeps the TypeScript test suite simple
// (ts-jest defaults to CJS). Newer 0.6+ releases are ESM-only and require
// Node 20.19+; switching to them is a separate test-runner upgrade.
//
// API note: the 0.4.x signature is `sign(secretKey, msg)` and
// `verify(publicKey, msg, sig)`. The 0.6.x line moved to `sign(msg, secretKey)`
// and `verify(sig, msg, publicKey)`. We follow 0.4.x here. Wire format
// (raw signature bytes) is identical across versions.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { ml_dsa44 } = require('@noble/post-quantum/ml-dsa') as {
  ml_dsa44: {
    keygen(seed?: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array };
    sign(secretKey: Uint8Array, msg: Uint8Array): Uint8Array;
    verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean;
  };
};

export const HYBRID_CRYPTOSUITE_ID = 'hybrid-eddsa-mldsa44-jcs-2026';

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
 * Generate a hybrid Data Integrity proof. Both Ed25519 and ML-DSA-44 sign
 * the SHA-256 digest of the JCS-canonicalized credential (with the
 * unsigned proof attached).
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

  const withUnsignedProof: Record<string, unknown> = { ...credential, proof };
  const canonical = canonicalize(withUnsignedProof);
  const digest = crypto.createHash('sha256').update(canonical).digest();

  // Ed25519: use Node crypto (algorithm null for Ed25519 keys).
  const edSig = crypto.sign(null, digest, opts.ed25519PrivateKey);
  if (edSig.length !== ED25519_SIG_SIZE) {
    throw new Error(`unexpected Ed25519 sig size ${edSig.length}`);
  }

  // ML-DSA-44 via @noble/post-quantum (0.4.x: secretKey, msg order).
  const mlSig = ml_dsa44.sign(opts.mldsa44SecretKey, digest);
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
 * Verify a hybrid Data Integrity proof. Both signatures MUST validate.
 * Returns true on success, false on signature failure. Throws on
 * malformed proof structure.
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
  const credForCheck: Record<string, unknown> = {
    ...credential,
    proof: proofWithoutValue as DataIntegrityProof,
  };
  const canonical = canonicalize(credForCheck);
  const digest = crypto.createHash('sha256').update(canonical).digest();

  if (!crypto.verify(null, digest, ed25519PublicKey, Buffer.from(edSig))) {
    return false;
  }
  // 0.4.x order: publicKey, msg, sig
  if (!ml_dsa44.verify(mldsa44PublicKey, digest, mlSig)) {
    return false;
  }
  return true;
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
