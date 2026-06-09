/**
 * Cross-implementation interop with the Rust core.
 *
 * Reads the shared eddsa-jcs-2022 vector that the Rust core generated
 * (test-vectors/data-integrity-eddsa-jcs-2022/vector.json) and asserts:
 *   1. The TS SDK verifies the Rust-produced signed credential.
 *   2. The TS SDK reproduces the exact same proofValue from the same inputs.
 *
 * Together with the matching Rust test (tests/interop_eddsa_vector.rs), this
 * proves a proof built by either implementation verifies in the other, byte for
 * byte, because Ed25519 (RFC 8032), JCS (RFC 8785), and SHA-256 are all
 * deterministic.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

import {
  buildProofPortable,
  verifyProofPortable,
} from '../src/data-integrity-portable';

const vectorPath = fileURLToPath(
  new URL(
    '../../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json',
    import.meta.url
  )
);
const vector = JSON.parse(readFileSync(vectorPath, 'utf8'));

function b64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

describe('Rust core <-> TS SDK eddsa-jcs-2022 interop', () => {
  it('TS verifies the Rust-produced signed credential', () => {
    const pub = b64(vector.ed25519.public_key_b64);
    expect(verifyProofPortable(vector.signed_credential, pub)).toBe(true);
  });

  it('TS reproduces the exact proofValue from the same inputs', () => {
    const seed = b64(vector.ed25519.seed_b64);
    const proof = buildProofPortable(vector.unsigned_credential, {
      rawPrivateKey: seed,
      verificationMethod: vector.verificationMethod,
      created: new Date(vector.created),
    });
    expect(proof.proofValue).toBe(vector.proofValue);
  });
});
