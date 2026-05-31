import * as crypto from 'crypto';
import { describe, expect, it } from 'vitest';

import { buildProof, verifyProof } from '../src/data-integrity';
import {
  buildProofPortable,
  verifyProofPortable,
} from '../src/data-integrity-portable';
import { buildVouchCredential } from '../src/vc';

const VM = 'did:key:zTest#key-1';

/** Generate an Ed25519 keypair and expose both KeyObjects and raw bytes. */
function makeKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwkPriv = privateKey.export({ format: 'jwk' }) as { d: string };
  const jwkPub = publicKey.export({ format: 'jwk' }) as { x: string };
  return {
    publicKey,
    privateKey,
    seed: new Uint8Array(Buffer.from(jwkPriv.d, 'base64url')),
    rawPub: new Uint8Array(Buffer.from(jwkPub.x, 'base64url')),
  };
}

function cred(overrides = {}) {
  return buildVouchCredential({
    issuerDid: 'did:key:zTest',
    intent: { action: 'read', target: 'db', resource: 'https://x/y' },
    ...overrides,
  });
}

describe('portable <-> node eddsa-jcs-2022 interop', () => {
  it('portable-built proof verifies with the Node verifyProof', () => {
    const k = makeKeys();
    const c = cred();
    const proof = buildProofPortable(c, { rawPrivateKey: k.seed, verificationMethod: VM });
    expect(verifyProof({ ...c, proof }, k.publicKey)).toBe(true);
  });

  it('node-built proof verifies with verifyProofPortable', () => {
    const k = makeKeys();
    const c = cred();
    const proof = buildProof(c, { privateKey: k.privateKey, verificationMethod: VM });
    expect(verifyProofPortable({ ...c, proof }, k.rawPub)).toBe(true);
  });

  it('produces a byte-identical proofValue for identical inputs (deterministic Ed25519)', () => {
    const k = makeKeys();
    const created = new Date('2026-01-01T00:00:00.000Z');
    const c = cred({
      credentialId: 'urn:uuid:fixed-0000',
      validFrom: new Date('2026-01-01T00:00:00.000Z'),
    });
    const pNode = buildProof(c, { privateKey: k.privateKey, verificationMethod: VM, created });
    const pPort = buildProofPortable(c, { rawPrivateKey: k.seed, verificationMethod: VM, created });
    expect(pPort.proofValue).toBe(pNode.proofValue);
  });

  it('rejects a tampered credential (node-built proof, portable verify)', () => {
    const k = makeKeys();
    const c = cred();
    const proof = buildProof(c, { privateKey: k.privateKey, verificationMethod: VM });
    const signed = { ...c, proof, issuer: 'did:key:zEvil' };
    expect(verifyProofPortable(signed, k.rawPub)).toBe(false);
  });

  it('rejects a wrong public key', () => {
    const k = makeKeys();
    const other = makeKeys();
    const c = cred();
    const proof = buildProofPortable(c, { rawPrivateKey: k.seed, verificationMethod: VM });
    expect(verifyProofPortable({ ...c, proof }, other.rawPub)).toBe(false);
  });
});
