/**
 * W3C Data Integrity signing-input alignment.
 *
 * Covers the aligned signing input (hashData: SHA-256 of the canonical proof
 * configuration joined with SHA-256 of the canonical unsecured document), the
 * backward-compatible acceptance of the pre-alignment 32-byte digest, and the
 * post-quantum proof set (`eddsa-jcs-2022` + `mldsa44-jcs-2024`) including its
 * pre-alignment identifier and encoding.
 */

import * as crypto from 'crypto';

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa';
import { describe, expect, it } from 'vitest';

import {
  buildProof,
  verifyProof,
  hashData,
  legacyProofDigest,
} from '../src/data-integrity';
import {
  buildProofPortable,
  verifyProofPortable,
  hashDataPortable,
} from '../src/data-integrity-portable';
import {
  buildDualProof,
  signDual,
  verifyDualProof,
  generateMLDSA44KeyPair,
  MLDSA44_CRYPTOSUITE_ID,
  MLDSA44_LEGACY_CRYPTOSUITE_ID,
} from '../src/data-integrity-hybrid';
import { canonicalize } from '../src/jcs';
import { b58decode, b58encode } from '../src/multikey';

(ed25519 as { hashes: { sha512?: (m: Uint8Array) => Uint8Array } }).hashes.sha512 = sha512;

// ---------------------------------------------------------------------------
// A credential issued BEFORE the alignment. Its signature covers the
// pre-alignment signing input (a single SHA-256 over the JCS form of the
// credential with the unsigned proof attached). It MUST keep verifying.
// ---------------------------------------------------------------------------

const PRE_ALIGNMENT_PUBLIC_KEY = new Uint8Array([
  0x4c, 0xb5, 0xab, 0xf6, 0xad, 0x79, 0xfb, 0xf5, 0xab, 0xbc, 0xca, 0xfc, 0xc2,
  0x69, 0xd8, 0x5c, 0xd2, 0x65, 0x1e, 0xd4, 0xb8, 0x85, 0xb5, 0x86, 0x9f, 0x24,
  0x1a, 0xed, 0xf0, 0xa5, 0xba, 0x29,
]);

function preAlignmentCredential(): Record<string, unknown> {
  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://vouch-protocol.com/contexts/v1',
    ],
    type: ['VerifiableCredential', 'VouchCredential'],
    issuer: 'did:web:test.example.com',
    validFrom: '2026-04-26T10:00:00Z',
    validUntil: '2026-04-26T10:05:00Z',
    credentialSubject: {
      id: 'did:web:test.example.com',
      vouchVersion: '1.0',
      intent: {
        action: 'read_database',
        target: 'users_table',
        resource: 'https://api.example.com/v1/users',
      },
    },
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-04-26T10:00:00Z',
      verificationMethod: 'did:web:test.example.com#key-1',
      proofPurpose: 'assertionMethod',
      proofValue:
        'z24FsZHuADF9uwHAfsjW3okmynrNCCN4QkQirEPfEy5MtcXzg4uhFqz4o3RVH57cFvVXg9oarC4m51YEmNu5UQRLQ',
    },
  };
}

function publicKeyObject(raw: Uint8Array): crypto.KeyObject {
  const x = Buffer.from(raw).toString('base64url');
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x } as crypto.JsonWebKey,
    format: 'jwk',
  });
}

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

function sampleCredential(): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'VouchCredential'],
    issuer: 'did:web:agent.example.com',
    validFrom: '2026-04-26T10:00:00Z',
    validUntil: '2026-04-26T10:05:00Z',
    credentialSubject: {
      id: 'did:web:agent.example.com',
      vouchVersion: '1.0',
      intent: {
        action: 'read_database',
        target: 'users_table',
        resource: 'https://api.example.com/v1/users',
      },
    },
  };
}

const VM = 'did:web:agent.example.com#key-1';
const ML_VM = 'did:web:agent.example.com#key-2';

// ---------------------------------------------------------------------------
// Backward compatibility
// ---------------------------------------------------------------------------

describe('pre-alignment credentials keep verifying', () => {
  it('verifies with the Node verifyProof', () => {
    expect(
      verifyProof(preAlignmentCredential(), publicKeyObject(PRE_ALIGNMENT_PUBLIC_KEY))
    ).toBe(true);
  });

  it('verifies with verifyProofPortable', () => {
    expect(
      verifyProofPortable(preAlignmentCredential(), PRE_ALIGNMENT_PUBLIC_KEY)
    ).toBe(true);
  });

  it('still rejects a tampered pre-alignment credential', () => {
    const cred = preAlignmentCredential();
    (cred.credentialSubject as Record<string, unknown>).id = 'did:web:evil.example.com';
    expect(
      verifyProof(cred, publicKeyObject(PRE_ALIGNMENT_PUBLIC_KEY))
    ).toBe(false);
    expect(verifyProofPortable(cred, PRE_ALIGNMENT_PUBLIC_KEY)).toBe(false);
  });

  it('verifies through the legacy fallback, not the aligned signing input', () => {
    const cred = preAlignmentCredential();
    const proof = { ...(cred.proof as Record<string, unknown>) };
    const signature = b58decode((proof.proofValue as string).slice(1));
    delete proof.proofValue;

    expect(
      ed25519.verify(signature, legacyProofDigest(cred, proof), PRE_ALIGNMENT_PUBLIC_KEY)
    ).toBe(true);
    expect(
      ed25519.verify(signature, hashData(cred, proof), PRE_ALIGNMENT_PUBLIC_KEY)
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The aligned signing input
// ---------------------------------------------------------------------------

describe('hashData (W3C Data Integrity hashing algorithm)', () => {
  it('is SHA-256(JCS(proof config)) || SHA-256(JCS(document)), config first', () => {
    const cred = sampleCredential();
    const unsigned = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-04-26T10:00:00Z',
      verificationMethod: VM,
      proofPurpose: 'assertionMethod',
    };

    const expectedConfig = sha256(
      canonicalize({ ...unsigned, '@context': cred['@context'] })
    );
    const expectedDoc = sha256(canonicalize(cred));

    const got = hashData(cred, unsigned);
    expect(got.length).toBe(64);
    expect(Buffer.from(got.slice(0, 32)).toString('hex')).toBe(
      Buffer.from(expectedConfig).toString('hex')
    );
    expect(Buffer.from(got.slice(32)).toString('hex')).toBe(
      Buffer.from(expectedDoc).toString('hex')
    );
  });

  it('ignores an existing proof on the credential', () => {
    const cred = sampleCredential();
    const unsigned = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-04-26T10:00:00Z',
      verificationMethod: VM,
      proofPurpose: 'assertionMethod',
    };
    const withStaleProof = { ...cred, proof: { ...unsigned, proofValue: 'zStale' } };
    expect(Buffer.from(hashData(withStaleProof, unsigned)).toString('hex')).toBe(
      Buffer.from(hashData(cred, unsigned)).toString('hex')
    );
  });

  it('matches the portable implementation byte for byte', () => {
    const cred = sampleCredential();
    const unsigned = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-04-26T10:00:00Z',
      verificationMethod: VM,
      proofPurpose: 'assertionMethod',
    };
    expect(Buffer.from(hashDataPortable(cred, unsigned)).toString('hex')).toBe(
      Buffer.from(hashData(cred, unsigned)).toString('hex')
    );
  });

  it('is what a newly built proof signs', () => {
    const k = makeKeys();
    const cred = sampleCredential();
    const created = new Date('2026-04-26T10:00:00Z');
    const proof = buildProof(cred, {
      privateKey: k.privateKey,
      verificationMethod: VM,
      created,
    });
    const unsigned = { ...proof } as Record<string, unknown>;
    delete unsigned.proofValue;

    const signature = b58decode((proof.proofValue as string).slice(1));
    expect(ed25519.verify(signature, hashData(cred, unsigned), k.rawPub)).toBe(true);
    // ... and NOT the pre-alignment digest.
    expect(
      ed25519.verify(signature, legacyProofDigest(cred, unsigned), k.rawPub)
    ).toBe(false);
  });

  it('portable and Node still agree on the emitted proofValue', () => {
    const k = makeKeys();
    const cred = sampleCredential();
    const created = new Date('2026-04-26T10:00:00Z');
    const pNode = buildProof(cred, {
      privateKey: k.privateKey,
      verificationMethod: VM,
      created,
    });
    const pPort = buildProofPortable(cred, {
      rawPrivateKey: k.seed,
      verificationMethod: VM,
      created,
    });
    expect(pPort.proofValue).toBe(pNode.proofValue);
  });
});

// ---------------------------------------------------------------------------
// Post-quantum proof set
// ---------------------------------------------------------------------------

describe('dual proof set (eddsa-jcs-2022 + mldsa44-jcs-2024)', () => {
  it('emits the specified identifier and base64url proofValue', () => {
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const proofs = buildDualProof(sampleCredential(), {
      ed25519PrivateKey: k.privateKey,
      mldsa44SecretKey: ml.secretKey,
      ed25519VerificationMethod: VM,
      mldsa44VerificationMethod: ML_VM,
      created: new Date('2026-04-26T10:00:00Z'),
    });

    expect(proofs).toHaveLength(2);
    expect(proofs[0].cryptosuite).toBe('eddsa-jcs-2022');
    expect(proofs[0].proofValue?.startsWith('z')).toBe(true);
    expect(proofs[1].cryptosuite).toBe(MLDSA44_CRYPTOSUITE_ID);
    expect(proofs[1].cryptosuite).toBe('mldsa44-jcs-2024');
    expect(proofs[1].proofValue?.startsWith('u')).toBe(true);
    expect(proofs[1].verificationMethod).toBe(ML_VM);
  });

  it('round-trips through signDual / verifyDualProof', () => {
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const signed = signDual(sampleCredential(), {
      ed25519PrivateKey: k.privateKey,
      mldsa44SecretKey: ml.secretKey,
      ed25519VerificationMethod: VM,
      mldsa44VerificationMethod: ML_VM,
    });
    expect(Array.isArray(signed.proof)).toBe(true);
    expect(verifyDualProof(signed, k.publicKey, ml.publicKey)).toBe(true);
  });

  it('rejects a tampered credential', () => {
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const signed = signDual(sampleCredential(), {
      ed25519PrivateKey: k.privateKey,
      mldsa44SecretKey: ml.secretKey,
      ed25519VerificationMethod: VM,
      mldsa44VerificationMethod: ML_VM,
    });
    (signed.credentialSubject as Record<string, unknown>) = {
      ...(signed.credentialSubject as Record<string, unknown>),
      id: 'did:web:evil.example.com',
    };
    expect(verifyDualProof(signed, k.publicKey, ml.publicKey)).toBe(false);
  });

  it('a later valid proof does not mask an earlier failing proof of the same suite', () => {
    // Proof masking: an attacker corrupts the genuine classical proof and
    // appends a second, valid classical proof. The set MUST NOT verify.
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const signed = signDual(sampleCredential(), {
      ed25519PrivateKey: k.privateKey,
      mldsa44SecretKey: ml.secretKey,
      ed25519VerificationMethod: VM,
      mldsa44VerificationMethod: ML_VM,
      created: new Date('2026-04-26T10:00:00Z'),
    });
    const [edProof, mlProof] = signed.proof as Record<string, unknown>[];

    // Same structure, but the signature no longer covers this proof config.
    const corruptedEd = { ...edProof, created: '2020-01-01T00:00:00Z' };
    const masked = { ...signed, proof: [corruptedEd, mlProof, edProof] };

    expect(verifyDualProof(masked, k.publicKey, ml.publicKey)).toBe(false);
  });

  it('a set with the ML-DSA member removed does not verify', () => {
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const signed = signDual(sampleCredential(), {
      ed25519PrivateKey: k.privateKey,
      mldsa44SecretKey: ml.secretKey,
      ed25519VerificationMethod: VM,
      mldsa44VerificationMethod: ML_VM,
      created: new Date('2026-04-26T10:00:00Z'),
    });
    const [edProof] = signed.proof as Record<string, unknown>[];
    const stripped = { ...signed, proof: [edProof] };

    expect(verifyDualProof(stripped, k.publicKey, ml.publicKey)).toBe(false);
  });

  it('ignores an unrecognized extra proof but still verifies the known members', () => {
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const signed = signDual(sampleCredential(), {
      ed25519PrivateKey: k.privateKey,
      mldsa44SecretKey: ml.secretKey,
      ed25519VerificationMethod: VM,
      mldsa44VerificationMethod: ML_VM,
      created: new Date('2026-04-26T10:00:00Z'),
    });
    const proofs = signed.proof as Record<string, unknown>[];
    // A future cryptosuite added alongside the known members must not break a
    // verifier that predates it: the set still verifies on its known members.
    const withUnknown = {
      ...signed,
      proof: [
        ...proofs,
        { ...proofs[0], cryptosuite: 'some-unregistered-suite-2030' },
      ],
    };
    expect(verifyDualProof(withUnknown, k.publicKey, ml.publicKey)).toBe(true);

    // But the unknown proof cannot substitute for a missing known member.
    const edOnlyPlusUnknown = {
      ...signed,
      proof: [
        proofs[0],
        { ...proofs[0], cryptosuite: 'some-unregistered-suite-2030' },
      ],
    };
    expect(verifyDualProof(edOnlyPlusUnknown, k.publicKey, ml.publicKey)).toBe(
      false
    );
  });

  it('accepts a pre-alignment ML-DSA proof (2026 identifier, base58btc, legacy digest)', () => {
    const k = makeKeys();
    const ml = generateMLDSA44KeyPair();
    const cred = sampleCredential();

    // Ed25519 half: a pre-alignment proof over the legacy digest.
    const edUnsigned = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-04-26T10:00:00Z',
      verificationMethod: VM,
      proofPurpose: 'assertionMethod',
    };
    const edSig = new Uint8Array(
      crypto.sign(null, legacyProofDigest(cred, edUnsigned), k.privateKey)
    );
    const edProof = { ...edUnsigned, proofValue: 'z' + b58encode(edSig) };

    // ML-DSA half: the pre-alignment identifier, encoding and signing input.
    const mlUnsigned = {
      type: 'DataIntegrityProof',
      cryptosuite: MLDSA44_LEGACY_CRYPTOSUITE_ID,
      created: '2026-04-26T10:00:00Z',
      verificationMethod: ML_VM,
      proofPurpose: 'assertionMethod',
    };
    const mlSig = ml_dsa44.sign(ml.secretKey, legacyProofDigest(cred, mlUnsigned));
    const mlProof = { ...mlUnsigned, proofValue: 'z' + b58encode(mlSig) };

    const signed = { ...cred, proof: [edProof, mlProof] };
    expect(verifyDualProof(signed, k.publicKey, ml.publicKey)).toBe(true);
  });
});
