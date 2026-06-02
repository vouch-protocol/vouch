/**
 * Portable (React-Native-safe) `eddsa-jcs-2022` Data Integrity proof helpers.
 *
 * Byte-compatible with the Node `buildProof`/`verifyProof` in
 * `./data-integrity`, but with NO Node `crypto` and NO `jose`: signing uses
 * `@noble/ed25519` + `@noble/hashes` and the vendored base58btc from
 * `./multikey`, so these run in React Native / browsers.
 *
 * Algorithm (identical to the Node path, [VC-DI-EDDSA] eddsa-jcs-2022):
 *   1. Attach an unsigned proof to the credential.
 *   2. JCS-canonicalize the whole object (RFC 8785).
 *   3. SHA-256 the canonical bytes.
 *   4. Ed25519-sign the 32-byte digest.
 *   5. proofValue = "z" + base58btc(signature).
 *
 * Keys are raw bytes: a 32-byte Ed25519 seed (private) and the 32-byte public
 * key. A proof produced here verifies with the Node `verifyProof`, and vice
 * versa.
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

import { canonicalize } from './jcs';
import { b58decode, b58encode } from './multikey';
import type { DataIntegrityProof } from './data-integrity';

// Re-declared locally so this module does not import ./data-integrity (which
// pulls in Node `crypto`). These literals MUST match that module.
const CRYPTOSUITE_ID = 'eddsa-jcs-2022';
const PROOF_TYPE = 'DataIntegrityProof';

// @noble/ed25519 v3's synchronous API needs a sha512 implementation wired in.
// Done lazily (not at import time) so merely importing this module stays
// side-effect-free for tree-shaking; only assigns if nothing else set it.
let edReady = false;
function ensureEd(): void {
  if (edReady) return;
  const hashes = (ed25519 as { hashes: { sha512?: (m: Uint8Array) => Uint8Array } }).hashes;
  if (!hashes.sha512) hashes.sha512 = sha512;
  edReady = true;
}

export interface BuildProofPortableOptions {
  /** 32-byte raw Ed25519 private seed. */
  rawPrivateKey: Uint8Array;
  verificationMethod: string;
  proofPurpose?: string;
  created?: Date;
}

/**
 * Build an `eddsa-jcs-2022` Data Integrity proof for `credential` using a raw
 * 32-byte Ed25519 seed. Returns the proof object (the caller attaches it).
 * Byte-compatible with the Node `buildProof`.
 */
export function buildProofPortable(
  credential: Record<string, unknown>,
  opts: BuildProofPortableOptions
): DataIntegrityProof {
  if (opts.rawPrivateKey.length !== 32) {
    throw new Error(
      `Ed25519 private seed must be 32 bytes, got ${opts.rawPrivateKey.length}`
    );
  }
  ensureEd();

  const proof: DataIntegrityProof = {
    type: PROOF_TYPE,
    cryptosuite: CRYPTOSUITE_ID,
    created: formatIso8601(opts.created ?? new Date()),
    verificationMethod: opts.verificationMethod,
    proofPurpose: opts.proofPurpose ?? 'assertionMethod',
  };

  const withUnsignedProof: Record<string, unknown> = { ...credential, proof };
  const canonical = canonicalize(withUnsignedProof);
  const digest = sha256(canonical);
  const signature = ed25519.sign(digest, opts.rawPrivateKey);

  proof.proofValue = 'z' + b58encode(signature);
  return proof;
}

/**
 * Verify an `eddsa-jcs-2022` Data Integrity proof attached to `credential`
 * using a raw 32-byte Ed25519 public key. Returns true on success, false on
 * signature failure. Throws on malformed proof structure. Byte-compatible with
 * the Node `verifyProof`.
 */
export function verifyProofPortable(
  credential: Record<string, unknown>,
  rawPublicKey: Uint8Array
): boolean {
  if (rawPublicKey.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes, got ${rawPublicKey.length}`
    );
  }
  ensureEd();

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

  const proofWithoutValue: Partial<DataIntegrityProof> = { ...proof };
  delete proofWithoutValue.proofValue;
  const credForCheck: Record<string, unknown> = {
    ...credential,
    proof: proofWithoutValue as DataIntegrityProof,
  };
  const canonical = canonicalize(credForCheck);
  const digest = sha256(canonical);

  return ed25519.verify(signature, digest, rawPublicKey);
}

function formatIso8601(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
