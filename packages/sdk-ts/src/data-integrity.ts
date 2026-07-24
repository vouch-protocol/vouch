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
 * Signing flow (the W3C Data Integrity hashing algorithm, so proofs issued
 * here verify under any conformant `eddsa-jcs-2022` implementation):
 *   1. Build the proof configuration (the unsigned proof plus the document's
 *      `@context`) and JCS-canonicalize it (RFC 8785).
 *   2. JCS-canonicalize the unsecured document (the credential with no proof).
 *   3. hashData = SHA-256(canonical proof configuration)
 *                 || SHA-256(canonical document)   (64 bytes, config first).
 *   4. Ed25519-sign hashData.
 *   5. proofValue = "z" + base58btc(signature).
 *
 * Verification also accepts the pre-alignment signing input (a single SHA-256
 * over the JCS form of the credential with the unsigned proof attached) so
 * credentials issued before this alignment keep verifying. See
 * {@link legacyProofDigest}.
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

/**
 * Strip any `proof` member, yielding the unsecured document.
 */
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
 * canonical unsecured document. This is the value that gets signed.
 */
export function hashData(
  credential: Record<string, unknown>,
  unsignedProof: Record<string, unknown>
): Uint8Array {
  const document = unsecuredDocument(credential);
  const config = proofConfiguration(document, unsignedProof);

  const configHash = crypto
    .createHash('sha256')
    .update(canonicalize(config))
    .digest();
  const documentHash = crypto
    .createHash('sha256')
    .update(canonicalize(document))
    .digest();

  const out = new Uint8Array(64);
  out.set(configHash, 0);
  out.set(documentHash, 32);
  return out;
}

/**
 * The pre-alignment signing input: a single SHA-256 over the JCS canonical form
 * of the credential with the unsigned proof attached. Retained so credentials
 * issued before the Data Integrity alignment continue to verify. Never used for
 * new proofs.
 */
export function legacyProofDigest(
  credential: Record<string, unknown>,
  unsignedProof: Record<string, unknown>
): Uint8Array {
  const withProof: Record<string, unknown> = {
    ...credential,
    proof: unsignedProof,
  };
  return new Uint8Array(
    crypto.createHash('sha256').update(canonicalize(withProof)).digest()
  );
}

export interface BuildProofOptions {
  /**
   * The Ed25519 private key (signs in process), OR provide `sign` instead to
   * keep the key outside this process. One of the two is required.
   */
  privateKey?: crypto.KeyObject;
  /**
   * A callback that signs the 64-byte signing input and returns the 64-byte
   * Ed25519 signature, without exposing the key to this process (an OS secure
   * element, a sidecar, a cloud KMS/HSM, or an MPC quorum). If both are set,
   * `sign` wins.
   */
  sign?: (signingInput: Uint8Array) => Uint8Array;
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

  const signingInput = hashData(credential, proof as unknown as Record<string, unknown>);

  let signature: Uint8Array;
  if (opts.sign) {
    signature = opts.sign(signingInput);
  } else if (opts.privateKey) {
    // Ed25519 signing in Node.js: algorithm parameter is null, the key type
    // alone determines the algorithm.
    signature = new Uint8Array(crypto.sign(null, signingInput, opts.privateKey));
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
 * proof structure. A signature over the pre-alignment signing input is also
 * accepted, so credentials issued before the Data Integrity alignment keep
 * verifying.
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

  // Rebuild the signing input from the proof with proofValue removed.
  const proofWithoutValue: Partial<DataIntegrityProof> = { ...proof };
  delete proofWithoutValue.proofValue;
  const unsignedProof = proofWithoutValue as unknown as Record<string, unknown>;

  const signingInput = hashData(credential, unsignedProof);
  if (crypto.verify(null, signingInput, publicKey, Buffer.from(signature))) {
    return true;
  }
  // Fall back to the pre-alignment signing input so credentials issued before
  // the Data Integrity alignment still verify.
  const legacy = legacyProofDigest(credential, unsignedProof);
  return crypto.verify(null, legacy, publicKey, Buffer.from(signature));
}

function formatIso8601(d: Date): string {
  // RFC 3339 / XML Schema dateTime, second precision with Z suffix.
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
