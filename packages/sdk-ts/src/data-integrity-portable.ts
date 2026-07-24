/**
 * Portable (React-Native-safe) `eddsa-jcs-2022` Data Integrity proof helpers.
 *
 * Byte-compatible with the Node `buildProof`/`verifyProof` in
 * `./data-integrity`, but with NO Node `crypto` and NO `jose`: signing uses
 * `@noble/ed25519` + `@noble/hashes` and the vendored base58btc from
 * `./multikey`, so these run in React Native / browsers.
 *
 * Algorithm (identical to the Node path, [VC-DI-EDDSA] eddsa-jcs-2022, the
 * W3C Data Integrity hashing algorithm):
 *   1. Build the proof configuration (the unsigned proof plus the document's
 *      `@context`) and JCS-canonicalize it (RFC 8785).
 *   2. JCS-canonicalize the unsecured document (the credential with no proof).
 *   3. hashData = SHA-256(canonical proof configuration)
 *                 || SHA-256(canonical document)   (64 bytes, config first).
 *   4. Ed25519-sign hashData.
 *   5. proofValue = "z" + base58btc(signature).
 *
 * Verification also accepts the pre-alignment signing input (a single SHA-256
 * over the JCS form of the credential with the unsigned proof attached), so
 * credentials issued before this alignment keep verifying.
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

/** Strip any `proof` member, yielding the unsecured document. */
function unsecuredDocument(
  credential: Record<string, unknown>
): Record<string, unknown> {
  const doc: Record<string, unknown> = { ...credential };
  delete doc.proof;
  return doc;
}

/**
 * Build the proof configuration: the unsigned proof carrying the document's
 * `@context`, per the Data Integrity proof configuration algorithm.
 */
function proofConfiguration(
  document: Record<string, unknown>,
  unsignedProof: Record<string, unknown>
): Record<string, unknown> {
  const config: Record<string, unknown> = { ...unsignedProof };
  delete config.proofValue;
  if (document['@context'] !== undefined) {
    config['@context'] = document['@context'];
  }
  return config;
}

/**
 * Compute the 64-byte W3C Data Integrity signing input for a JCS cryptosuite:
 * SHA-256 of the canonical proof configuration, joined with SHA-256 of the
 * canonical unsecured document. Byte-identical to the Node `hashData`.
 */
export function hashDataPortable(
  credential: Record<string, unknown>,
  unsignedProof: Record<string, unknown>
): Uint8Array {
  const document = unsecuredDocument(credential);
  const config = proofConfiguration(document, unsignedProof);

  const configHash = sha256(canonicalize(config));
  const documentHash = sha256(canonicalize(document));

  const out = new Uint8Array(64);
  out.set(configHash, 0);
  out.set(documentHash, 32);
  return out;
}

/**
 * The pre-alignment signing input: a single SHA-256 over the JCS canonical
 * form of the credential with the unsigned proof attached. Retained so
 * credentials issued before the alignment keep verifying. Never used for new
 * proofs.
 */
export function legacyProofDigestPortable(
  credential: Record<string, unknown>,
  unsignedProof: Record<string, unknown>
): Uint8Array {
  const withProof: Record<string, unknown> = {
    ...credential,
    proof: unsignedProof,
  };
  return sha256(canonicalize(withProof));
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

  const signingInput = hashDataPortable(
    credential,
    proof as unknown as Record<string, unknown>
  );
  const signature = ed25519.sign(signingInput, opts.rawPrivateKey);

  proof.proofValue = 'z' + b58encode(signature);
  return proof;
}

/**
 * Verify an `eddsa-jcs-2022` Data Integrity proof attached to `credential`
 * using a raw 32-byte Ed25519 public key. Returns true on success, false on
 * signature failure. Throws on malformed proof structure. Byte-compatible with
 * the Node `verifyProof`, including its acceptance of the pre-alignment
 * signing input.
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
  const unsignedProof = proofWithoutValue as unknown as Record<string, unknown>;

  const signingInput = hashDataPortable(credential, unsignedProof);
  if (ed25519.verify(signature, signingInput, rawPublicKey)) {
    return true;
  }
  // Fall back to the pre-alignment signing input so credentials issued before
  // the Data Integrity alignment still verify.
  const legacy = legacyProofDigestPortable(credential, unsignedProof);
  return ed25519.verify(signature, legacy, rawPublicKey);
}

function formatIso8601(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
