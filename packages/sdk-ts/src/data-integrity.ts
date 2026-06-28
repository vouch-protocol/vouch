/**
 * Data Integrity proof builder and verifier, `eddsa-jcs-2022` cryptosuite.
 *
 * Mirrors `vouch/data_integrity.py`. Implements §3.1 of [VC-DI-EDDSA]:
 *   https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022
 *
 * The cryptosuite produces a `DataIntegrityProof` object that attaches
 * alongside the credential payload as a sibling `proof` property. No JWS,
 * no JOSE, no Base64 wrapping of the payload, the credential remains
 * human-readable JSON.
 *
 * Signing flow (Specification §7.1):
 *   1. Build credential with unsigned proof (no proofValue).
 *   2. JCS-canonicalize the entire object.
 *   3. SHA-256 the canonical bytes.
 *   4. Ed25519-sign the digest.
 *   5. Multibase-encode the signature into proof.proofValue.
 */

import * as crypto from 'crypto';
import { canonicalize } from './jcs';
import { b58decode, b58encode } from './multikey';

export const CRYPTOSUITE_ID = 'eddsa-jcs-2022';
export const PROOF_TYPE = 'DataIntegrityProof';

export interface DataIntegrityProof {
  type: string;
  cryptosuite: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue?: string;
}

export interface BuildProofOptions {
  /**
   * The Ed25519 private key (signs in process), OR provide `sign` instead to
   * keep the key outside this process. One of the two is required.
   */
  privateKey?: crypto.KeyObject;
  /**
   * A callback that signs the 32-byte digest and returns the 64-byte Ed25519
   * signature, without exposing the key to this process (an OS secure element,
   * a sidecar, a cloud KMS/HSM, or an MPC quorum). If both are set, `sign` wins.
   */
  sign?: (digest: Uint8Array) => Uint8Array;
  verificationMethod: string;
  proofPurpose?: string;
  created?: Date;
}

/**
 * Generate a Data Integrity proof object for `credential`.
 *
 * Sign either with `opts.privateKey` (in process) or `opts.sign` (a callback
 * that signs the digest without exposing the key). Returns the proof dict
 * (caller attaches it to the credential).
 *
 * Conforms to eddsa-jcs-2022 §3.1.
 */
export function buildProof(
  credential: Record<string, unknown>,
  opts: BuildProofOptions
): DataIntegrityProof {
  const proof: DataIntegrityProof = {
    type: PROOF_TYPE,
    cryptosuite: CRYPTOSUITE_ID,
    created: formatIso8601(opts.created ?? new Date()),
    verificationMethod: opts.verificationMethod,
    proofPurpose: opts.proofPurpose ?? 'assertionMethod',
  };

  // Attach the unsigned proof to a copy of the credential and canonicalize.
  const withUnsignedProof: Record<string, unknown> = { ...credential, proof };
  const canonical = canonicalize(withUnsignedProof);
  const digest = crypto.createHash('sha256').update(canonical).digest();

  let signature: Uint8Array;
  if (opts.sign) {
    signature = opts.sign(new Uint8Array(digest));
  } else if (opts.privateKey) {
    // Ed25519 signing in Node.js: algorithm parameter is null, the key type
    // alone determines the algorithm.
    signature = new Uint8Array(crypto.sign(null, digest, opts.privateKey));
  } else {
    throw new Error('buildProof needs a privateKey or a sign callback');
  }
  proof.proofValue = 'z' + b58encode(signature);
  return proof;
}

/**
 * Verify a Data Integrity proof attached to `credential`.
 *
 * Returns true on success, false on signature failure. Throws on malformed
 * proof structure.
 */
export function verifyProof(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject
): boolean {
  const proof = (credential as { proof?: DataIntegrityProof }).proof;
  if (!proof || typeof proof !== 'object') {
    throw new Error('Credential has no proof object');
  }
  if (proof.type !== PROOF_TYPE) {
    throw new Error(`Unexpected proof type: ${proof.type}`);
  }
  if (proof.cryptosuite !== CRYPTOSUITE_ID) {
    throw new Error(`Unexpected cryptosuite: ${proof.cryptosuite}`);
  }
  if (!proof.proofValue || !proof.proofValue.startsWith('z')) {
    throw new Error('Missing or malformed proofValue');
  }

  const signature = b58decode(proof.proofValue.slice(1));

  // Reconstruct the canonical form by removing proofValue from the proof
  // and canonicalizing the credential.
  const proofWithoutValue: Partial<DataIntegrityProof> = { ...proof };
  delete proofWithoutValue.proofValue;
  const credForCheck: Record<string, unknown> = {
    ...credential,
    proof: proofWithoutValue as DataIntegrityProof,
  };
  const canonical = canonicalize(credForCheck);
  const digest = crypto.createHash('sha256').update(canonical).digest();

  return crypto.verify(null, digest, publicKey, Buffer.from(signature));
}

function formatIso8601(d: Date): string {
  // RFC 3339 / XML Schema dateTime, second precision with Z suffix.
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
