/**
 * Tests for the VC + Data Integrity path in the TypeScript SDK
 * (Specification §5, §7.1, §8). Mirrors tests/test_signer_vc.py and
 * tests/test_verifier_vc.py from the Python codebase.
 */

import * as crypto from 'crypto';

import {
  Signer,
  Verifier,
  generateIdentity,
  canonicalize,
  encodeEd25519Public,
  decodeMultikey,
  multikeyAlgorithm,
  buildVouchCredential,
  DATA_INTEGRITY_CRYPTOSUITE,
  DATA_INTEGRITY_PROOF_TYPE,
  VC_CONTEXT_V2,
  VOUCH_CONTEXT_V1,
  VC_TYPE,
  VOUCH_CREDENTIAL_TYPE,
  PROTOCOL_VERSION,
} from '../src';
import type { VouchCredential, Intent } from '../src';

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
// JCS canonicalization
// ---------------------------------------------------------------------------

describe('JCS canonicalization (RFC 8785)', () => {
  test('sorts object keys by code-point order', () => {
    const out = new TextDecoder().decode(canonicalize({ b: 1, a: 2 }));
    expect(out).toBe('{"a":2,"b":1}');
  });

  test('handles arrays without re-sorting', () => {
    const out = new TextDecoder().decode(canonicalize([3, 1, 2]));
    expect(out).toBe('[3,1,2]');
  });

  test('formats integers without exponent or trailing zeros', () => {
    const out = new TextDecoder().decode(canonicalize({ n: 42 }));
    expect(out).toBe('{"n":42}');
  });

  test('normalizes negative zero', () => {
    const out = new TextDecoder().decode(canonicalize({ n: -0 }));
    expect(out).toBe('{"n":0}');
  });

  test('rejects NaN and Infinity', () => {
    expect(() => canonicalize({ n: Number.NaN })).toThrow();
    expect(() => canonicalize({ n: Infinity })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Multikey
// ---------------------------------------------------------------------------

describe('Multikey encoding', () => {
  test('roundtrips a 32-byte Ed25519 public key', () => {
    const raw = new Uint8Array(32);
    crypto.randomFillSync(raw);
    const mk = encodeEd25519Public(raw);
    expect(mk.startsWith('z6Mk')).toBe(true);
    const { algorithm, rawKey } = decodeMultikey(mk);
    expect(algorithm).toBe('Ed25519');
    expect(rawKey.length).toBe(32);
    expect(Buffer.compare(Buffer.from(rawKey), Buffer.from(raw))).toBe(0);
  });

  test('rejects the wrong key length', () => {
    expect(() => encodeEd25519Public(new Uint8Array(31))).toThrow();
  });

  test('rejects Multikey without z-prefix', () => {
    expect(() => decodeMultikey('Q6MkInvalid')).toThrow();
  });

  test('algorithmOf does not expose key bytes', () => {
    const raw = new Uint8Array(32);
    crypto.randomFillSync(raw);
    const mk = encodeEd25519Public(raw);
    expect(multikeyAlgorithm(mk)).toBe('Ed25519');
  });
});

// ---------------------------------------------------------------------------
// Credential issuance
// ---------------------------------------------------------------------------

describe('Signer.sign', () => {
  test('returns a VC with eddsa-jcs-2022 proof', async () => {
    const { signer } = await newSigner();
    const cred = await signer.sign({ intent: intent() });

    expect(cred['@context']).toEqual([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]);
    expect(cred.type).toContain(VC_TYPE);
    expect(cred.type).toContain(VOUCH_CREDENTIAL_TYPE);
    expect(cred.issuer).toBe(signer.getDid());
    expect(cred.id.startsWith('urn:uuid:')).toBe(true);
    expect(cred.credentialSubject.vouchVersion).toBe(PROTOCOL_VERSION);
    expect(cred.credentialSubject.intent).toEqual(intent());

    const proof = (cred as { proof?: Record<string, unknown> }).proof!;
    expect(proof.type).toBe(DATA_INTEGRITY_PROOF_TYPE);
    expect(proof.cryptosuite).toBe(DATA_INTEGRITY_CRYPTOSUITE);
    expect(proof.proofPurpose).toBe('assertionMethod');
    expect(proof.verificationMethod).toBe(signer.verificationMethodId());
    expect(typeof proof.proofValue).toBe('string');
    expect((proof.proofValue as string).startsWith('z')).toBe(true);
  });

  test('clamps reputation score to [0, 100]', async () => {
    const { signer } = await newSigner();
    const high = await signer.sign({
      intent: intent(),
      reputationScore: 200,
    });
    const low = await signer.sign({
      intent: intent(),
      reputationScore: -10,
    });
    expect(high.credentialSubject.reputationScore).toBe(100);
    expect(low.credentialSubject.reputationScore).toBe(0);
  });

  test('rejects an intent missing the resource binding', async () => {
    const { signer } = await newSigner();
    const bad = { action: 'x', target: 'y' } as unknown as Intent;
    await expect(signer.sign({ intent: bad })).rejects.toThrow(
      /resource/
    );
  });

  test('signJson returns a JSON-serializable string', async () => {
    const { signer } = await newSigner();
    const text = await signer.signJson({ intent: intent() });
    const parsed = JSON.parse(text) as Record<string, unknown>;
    expect((parsed.proof as Record<string, unknown>).cryptosuite).toBe(
      DATA_INTEGRITY_CRYPTOSUITE
    );
  });

  test('exposes a Multikey-format public key', async () => {
    const { signer } = await newSigner();
    const mk = await signer.getPublicKeyMultikey();
    expect(mk.startsWith('z6Mk')).toBe(true);
    const { algorithm, rawKey } = decodeMultikey(mk);
    expect(algorithm).toBe('Ed25519');
    expect(rawKey.length).toBe(32);
  });

  test('verificationMethodId is canonical', async () => {
    const { signer } = await newSigner('did:web:demo.example.com');
    expect(signer.verificationMethodId()).toBe(
      `${signer.getDid()}#key-1`
    );
  });
});

// ---------------------------------------------------------------------------
// Verification roundtrip
// ---------------------------------------------------------------------------

describe('Verifier.verify', () => {
  test('accepts a valid credential with a Node KeyObject', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.sign({ intent: intent() });
    const pub = publicKeyObject(publicKeyJwk);

    const result = await Verifier.verify(cred, pub);
    expect(result.isValid).toBe(true);
    expect(result.passport!.sub).toBe(signer.getDid());
    expect(result.passport!.intent).toEqual(intent());
  });

  test('accepts a JWK string as the public key', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.sign({ intent: intent() });
    const result = await Verifier.verify(cred, publicKeyJwk);
    expect(result.isValid).toBe(true);
  });

  test('accepts a Multikey string as the public key', async () => {
    const { signer } = await newSigner();
    const cred = await signer.sign({ intent: intent() });
    const mk = await signer.getPublicKeyMultikey();
    const result = await Verifier.verify(cred, mk);
    expect(result.isValid).toBe(true);
  });

  test('accepts a JSON-encoded credential string', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const json = await signer.signJson({ intent: intent() });
    const result = await Verifier.verify(
      json,
      publicKeyObject(publicKeyJwk)
    );
    expect(result.isValid).toBe(true);
  });

  test('rejects a tampered intent.resource', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.sign({ intent: intent() });
    cred.credentialSubject.intent.resource = 'https://evil.example.com/x';
    const result = await Verifier.verify(
      cred,
      publicKeyObject(publicKeyJwk)
    );
    expect(result.isValid).toBe(false);
  });

  test('rejects a tampered issuer', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.sign({ intent: intent() });
    cred.issuer = 'did:web:attacker.example.com';
    const result = await Verifier.verify(
      cred,
      publicKeyObject(publicKeyJwk)
    );
    expect(result.isValid).toBe(false);
  });

  test('rejects an expired credential', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const longAgo = new Date(Date.now() - 600_000);
    const cred = await signer.sign({
      intent: intent(),
      validFrom: longAgo,
      validSeconds: 10,
    });
    const result = await Verifier.verify(
      cred,
      publicKeyObject(publicKeyJwk),
      30
    );
    expect(result.isValid).toBe(false);
  });

  test('rejects a not-yet-valid credential', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const future = new Date(Date.now() + 600_000);
    const cred = await signer.sign({
      intent: intent(),
      validFrom: future,
    });
    const result = await Verifier.verify(
      cred,
      publicKeyObject(publicKeyJwk),
      30
    );
    expect(result.isValid).toBe(false);
  });

  test('clock skew tolerance applies', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const justExpired = new Date(Date.now() - 320_000);
    const cred = await signer.sign({
      intent: intent(),
      validFrom: justExpired,
      validSeconds: 300,
    });

    // ~20 seconds expired, 30s skew accepts it.
    const withSkew = await Verifier.verify(
      cred,
      publicKeyObject(publicKeyJwk),
      30
    );
    expect(withSkew.isValid).toBe(true);

    // 5s skew rejects it.
    const noSkew = await Verifier.verify(
      cred,
      publicKeyObject(publicKeyJwk),
      5
    );
    expect(noSkew.isValid).toBe(false);
  });

  test('rejects credentials missing intent.resource', async () => {
    const { signer } = await newSigner();
    const cred = await signer.sign({ intent: intent() });
    // Strip resource after signing. The Verifier MUST reject regardless
    // (structural rule per §5.4.1, §8.4).
    delete (cred.credentialSubject.intent as Partial<Intent>).resource;
    const result = await Verifier.verify(cred);
    expect(result.isValid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Delegation chains
// ---------------------------------------------------------------------------

describe('Delegation chains', () => {
  test('appends a link from parent to child', async () => {
    const { signer: parent } = await newSigner('did:web:alice.example.com');
    const { signer: child, publicKeyJwk: childKey } = await newSigner(
      'did:web:assistant.example.com'
    );

    const parentCred = await parent.sign({
      intent: {
        action: 'plan_trip',
        target: 'destination:Paris',
        resource: 'https://travel-api.example.com/v1/bookings',
      },
    });

    const childCred = await child.sign({
      intent: {
        action: 'book_flight',
        target: 'flight:AF123',
        resource:
          'https://travel-api.example.com/v1/bookings/flight-AF123',
      },
      parentCredential: parentCred,
    });

    const chain = childCred.credentialSubject.delegationChain!;
    expect(chain).toHaveLength(1);
    expect(chain[0].issuer).toBe(parent.getDid());
    expect(chain[0].subject).toBe(child.getDid());
    expect(chain[0].intent.resource).toBe(
      'https://travel-api.example.com/v1/bookings/flight-AF123'
    );

    const result = await Verifier.verify(
      childCred,
      publicKeyObject(childKey)
    );
    expect(result.isValid).toBe(true);
    expect(result.passport!.delegationChain).toHaveLength(1);
  });

  test('rejects resource-narrowing violation', async () => {
    const { signer: parent } = await newSigner('did:web:alice.example.com');
    const { signer: child } = await newSigner('did:web:rogue.example.com');

    const parentCred = await parent.sign({
      intent: {
        action: 'read',
        target: 'users',
        resource: 'https://api.example.com/v1/users',
      },
    });

    await expect(
      child.sign({
        intent: {
          action: 'read',
          target: 'admin',
          resource: 'https://api.example.com/v1/admin',
        },
        parentCredential: parentCred,
      })
    ).rejects.toThrow(/resource-narrowing/);
  });

  test('enforces the depth limit', async () => {
    const commonResource = 'https://api.example.com/v1/data';
    const intentTpl: Intent = {
      action: 'read',
      target: 'data',
      resource: commonResource,
    };

    const signers = [];
    for (let i = 0; i < 7; i++) {
      const s = await newSigner(`did:web:agent${i}.example.com`);
      signers.push(s.signer);
    }

    let cred: VouchCredential = await signers[0].sign({
      intent: intentTpl,
    });
    for (let i = 1; i < 6; i++) {
      cred = await signers[i].sign({
        intent: intentTpl,
        parentCredential: cred,
      });
    }
    expect(cred.credentialSubject.delegationChain).toHaveLength(5);

    await expect(
      signers[6].sign({
        intent: intentTpl,
        parentCredential: cred,
      })
    ).rejects.toThrow(/max depth/);
  });

  test('binds to a proof-set (post-quantum) parent via its classical proof member', async () => {
    const { signer: parent } = await newSigner('did:web:alice.example.com');
    const { signer: child } = await newSigner('did:web:assistant.example.com');

    // A post-quantum parent carries a proof SET (an array), not a single
    // proof object. Build the classical credential, then re-sign it under the
    // proof set so its `proof` is an array.
    const classicalParent = await parent.sign({
      intent: {
        action: 'plan_trip',
        target: 'destination:Paris',
        resource: 'https://travel-api.example.com/v1/bookings',
      },
    });
    const proofSetParent = (await parent.attachProofHybrid(
      classicalParent
    )) as unknown as VouchCredential;
    const parentProofs = (proofSetParent as unknown as { proof: unknown }).proof;
    expect(Array.isArray(parentProofs)).toBe(true);

    const childCred = await child.sign({
      intent: {
        action: 'book_flight',
        target: 'flight:AF123',
        resource:
          'https://travel-api.example.com/v1/bookings/flight-AF123',
      },
      parentCredential: proofSetParent,
    });

    const chain = childCred.credentialSubject.delegationChain!;
    expect(chain).toHaveLength(1);
    // The binding is derived from the parent's classical eddsa-jcs-2022 proof
    // member, not silently dropped because the parent proof is an array.
    const eddsaMember = (
      parentProofs as Array<{ cryptosuite: string; proofValue: string }>
    ).find((p) => p.cryptosuite === DATA_INTEGRITY_CRYPTOSUITE)!;
    expect(chain[0].parentProofValue).toBeTruthy();
    expect(chain[0].parentProofValue).toBe(eddsaMember.proofValue.slice(0, 64));
  });
});

// ---------------------------------------------------------------------------
// Coexistence with legacy JWS path
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// buildVouchCredential as a low-level builder
// ---------------------------------------------------------------------------

describe('buildVouchCredential', () => {
  test('produces an unsigned credential ready for proof attachment', () => {
    const cred = buildVouchCredential({
      issuerDid: 'did:web:demo.example.com',
      intent: intent(),
    });
    expect(cred.proof).toBeUndefined();
    expect(cred.issuer).toBe('did:web:demo.example.com');
    expect(cred.credentialSubject.intent).toEqual(intent());
  });
});
