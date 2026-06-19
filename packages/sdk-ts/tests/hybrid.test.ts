/**
 * Tests for the hybrid Ed25519 + ML-DSA-44 cryptosuite (Specification §13.2).
 * Mirrors go-sidecar/signer/data_integrity_hybrid_test.go.
 */

import * as crypto from 'crypto';

import {
  Signer,
  Verifier,
  generateIdentity,
  encodeMLDSA44Public,
  decodeMultikey,
  HYBRID_CRYPTOSUITE_ID,
  DATA_INTEGRITY_PROOF_TYPE,
  buildHybridProof,
  verifyHybridProof,
  generateMLDSA44KeyPair,
  hybridVerificationMethodPair,
  buildVouchCredential,
  VC_CONTEXT_V2,
  VOUCH_CONTEXT_V1,
  VC_TYPE,
  VOUCH_CREDENTIAL_TYPE,
} from '../src';
import type { Intent, VouchCredential } from '../src';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function newSigner(
  did = 'did:web:agent.example.com'
): Promise<{ signer: Signer; publicKeyJwk: string }> {
  const keys = await generateIdentity('agent.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  return { signer, publicKeyJwk: keys.publicKeyJwk };
}

function intent(): Intent {
  return {
    action: 'read_database',
    target: 'users_table',
    resource: 'https://api.example.com/v1/users',
  };
}

function publicKeyObject(jwkStr: string): crypto.KeyObject {
  return crypto.createPublicKey({
    key: JSON.parse(jwkStr) as crypto.JsonWebKey,
    format: 'jwk',
  });
}

// ---------------------------------------------------------------------------
// Multikey for ML-DSA-44
// ---------------------------------------------------------------------------

describe('Multikey ML-DSA-44', () => {
  test('rejects wrong key length', () => {
    expect(() => encodeMLDSA44Public(new Uint8Array(1311))).toThrow();
    expect(() => encodeMLDSA44Public(new Uint8Array(1313))).toThrow();
  });

  test('roundtrips a 1312-byte key', () => {
    const raw = new Uint8Array(1312);
    crypto.randomFillSync(raw);
    const mk = encodeMLDSA44Public(raw);
    expect(mk.startsWith('z')).toBe(true);
    const { algorithm, rawKey } = decodeMultikey(mk);
    expect(algorithm).toBe('ML-DSA-44');
    expect(rawKey.length).toBe(1312);
  });
});

// ---------------------------------------------------------------------------
// Signer.signCredentialHybrid
// ---------------------------------------------------------------------------

describe('Signer.signCredentialHybrid', () => {
  test('produces a hybrid cryptosuite proof', async () => {
    const { signer } = await newSigner();
    const cred = await signer.signCredentialHybrid({ intent: intent() });

    expect(cred['@context']).toEqual([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]);
    expect(cred.type).toContain(VC_TYPE);
    expect(cred.type).toContain(VOUCH_CREDENTIAL_TYPE);

    const proof = (cred as { proof?: Record<string, unknown> }).proof!;
    expect(proof.type).toBe(DATA_INTEGRITY_PROOF_TYPE);
    expect(proof.cryptosuite).toBe(HYBRID_CRYPTOSUITE_ID);
    expect(proof.proofPurpose).toBe('assertionMethod');
    expect(proof.verificationMethod).toBe(signer.verificationMethodId());
    expect((proof.proofValue as string).startsWith('z')).toBe(true);
  });

  test('exposes ML-DSA-44 public key in Multikey form', async () => {
    const { signer } = await newSigner();
    const mk = signer.publicKeyMLDSA44Multikey();
    const { algorithm, rawKey } = decodeMultikey(mk);
    expect(algorithm).toBe('ML-DSA-44');
    expect(rawKey.length).toBe(1312);
  });
});

// ---------------------------------------------------------------------------
// Verification roundtrip
// ---------------------------------------------------------------------------

describe('verifyHybridProof', () => {
  test('accepts a valid credential signed with the same signer', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.signCredentialHybrid({ intent: intent() });

    const ed25519Pub = publicKeyObject(publicKeyJwk);
    const mldsa44Pub = signer.publicKeyMLDSA44();

    const ok = verifyHybridProof(
      cred as unknown as Record<string, unknown>,
      ed25519Pub,
      mldsa44Pub
    );
    expect(ok).toBe(true);
  });

  test('rejects a tampered intent.resource', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.signCredentialHybrid({ intent: intent() });
    cred.credentialSubject.intent.resource = 'https://evil.example.com/x';

    const ed25519Pub = publicKeyObject(publicKeyJwk);
    const mldsa44Pub = signer.publicKeyMLDSA44();

    const ok = verifyHybridProof(
      cred as unknown as Record<string, unknown>,
      ed25519Pub,
      mldsa44Pub
    );
    expect(ok).toBe(false);
  });

  test('rejects a wrong Ed25519 public key', async () => {
    const { signer } = await newSigner();
    const other = await newSigner('did:web:other.example.com');
    const cred = await signer.signCredentialHybrid({ intent: intent() });

    const wrongEd = publicKeyObject(other.publicKeyJwk);
    const mldsa44Pub = signer.publicKeyMLDSA44();

    const ok = verifyHybridProof(
      cred as unknown as Record<string, unknown>,
      wrongEd,
      mldsa44Pub
    );
    expect(ok).toBe(false);
  });

  test('rejects a wrong ML-DSA-44 public key', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const other = await newSigner('did:web:other.example.com');
    const cred = await signer.signCredentialHybrid({ intent: intent() });

    const ed25519Pub = publicKeyObject(publicKeyJwk);
    const wrongMld = await other.signer.publicKeyMLDSA44();

    const ok = verifyHybridProof(
      cred as unknown as Record<string, unknown>,
      ed25519Pub,
      wrongMld
    );
    expect(ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Independence from the eddsa-jcs-2022 path
// ---------------------------------------------------------------------------

describe('Hybrid and eddsa-jcs-2022 paths coexist', () => {
  test('both paths work on the same signer', async () => {
    const { signer, publicKeyJwk } = await newSigner();

    const credEd = await signer.signCredential({ intent: intent() });
    const ed = await Verifier.verifyCredential(
      credEd,
      publicKeyObject(publicKeyJwk)
    );
    expect(ed.isValid).toBe(true);

    const credHyb = await signer.signCredentialHybrid({ intent: intent() });
    const ok = verifyHybridProof(
      credHyb as unknown as Record<string, unknown>,
      publicKeyObject(publicKeyJwk),
      signer.publicKeyMLDSA44()
    );
    expect(ok).toBe(true);
  });

  test('eddsa-jcs-2022 verifier rejects hybrid cryptosuite identifier', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const credHyb = await signer.signCredentialHybrid({ intent: intent() });

    // Standard eddsa-jcs-2022 verifier should not accept hybrid proofs.
    const result = await Verifier.verifyCredential(
      credHyb,
      publicKeyObject(publicKeyJwk)
    );
    expect(result.isValid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Verification method pair derivation
// ---------------------------------------------------------------------------

describe('hybridVerificationMethodPair', () => {
  test('appends #key-2 when input ends with #key-1', () => {
    const pair = hybridVerificationMethodPair(
      'did:web:agent.example.com#key-1'
    );
    expect(pair.ed25519).toBe('did:web:agent.example.com#key-1');
    expect(pair.mldsa44).toBe('did:web:agent.example.com#key-2');
  });

  test('replaces fragment when input ends with #abc', () => {
    const pair = hybridVerificationMethodPair(
      'did:web:agent.example.com#abc'
    );
    expect(pair.ed25519).toBe('did:web:agent.example.com#abc');
    expect(pair.mldsa44).toBe('did:web:agent.example.com#key-2');
  });

  test('appends #key-2 when input has no fragment', () => {
    const pair = hybridVerificationMethodPair('did:web:agent.example.com');
    expect(pair.ed25519).toBe('did:web:agent.example.com');
    expect(pair.mldsa44).toBe('did:web:agent.example.com#key-2');
  });
});

// ---------------------------------------------------------------------------
// Direct primitive (independent of Signer)
// ---------------------------------------------------------------------------

describe('buildHybridProof / verifyHybridProof direct usage', () => {
  test('roundtrip with caller-provided keys', () => {
    const { secretKey: edSecret, publicKey: edPubBytes } = (() => {
      const { generateKeyPairSync } = crypto;
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      return {
        secretKey: privateKey,
        publicKey: publicKey,
      };
    })();
    const mld = generateMLDSA44KeyPair();

    const cred = buildVouchCredential({
      issuerDid: 'did:web:test.example.com',
      intent: intent(),
    });

    const proof = buildHybridProof(
      cred as unknown as Record<string, unknown>,
      {
        ed25519PrivateKey: edSecret,
        mldsa44SecretKey: mld.secretKey,
        verificationMethod: 'did:web:test.example.com#key-1',
      }
    );
    (cred as unknown as { proof: unknown }).proof = proof;

    const ok = verifyHybridProof(
      cred as unknown as Record<string, unknown>,
      edPubBytes,
      mld.publicKey
    );
    expect(ok).toBe(true);
  });
});
