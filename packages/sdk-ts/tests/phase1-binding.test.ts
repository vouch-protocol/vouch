/**
 * Security regression tests for verifyCredential: cryptosuite dispatch, PQ
 * downgrade protection (requiredCryptosuite), and proofPurpose /
 * verificationMethod-to-issuer binding. These guard against a hybrid proof
 * being silently downgraded to Ed25519 and against cross-issuer key reuse.
 */
import * as crypto from 'crypto';
import {
  Signer,
  Verifier,
  generateIdentity,
  HYBRID_CRYPTOSUITE_ID,
} from '../src';
import type { Intent } from '../src';

function intent(): Intent {
  return {
    action: 'read_database',
    target: 'users_table',
    resource: 'https://api.example.com/v1/users',
  };
}
function pub(jwk: string): crypto.KeyObject {
  return crypto.createPublicKey({ key: JSON.parse(jwk) as crypto.JsonWebKey, format: 'jwk' });
}
async function newSigner(did = 'did:web:agent.example.com') {
  const keys = await generateIdentity('agent.example.com');
  return { signer: new Signer({ privateKey: keys.privateKeyJwk, did }), publicKeyJwk: keys.publicKeyJwk };
}

describe('Phase 1 verifyCredential hardening', () => {
  test('hybrid credential verifies with ML key + required hybrid suite', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.signCredentialHybrid({ intent: intent() });
    const res = await Verifier.verifyCredential(cred, pub(publicKeyJwk), 30, {
      mldsa44PublicKey: signer.publicKeyMLDSA44(),
      requiredCryptosuite: HYBRID_CRYPTOSUITE_ID,
    });
    expect(res.isValid).toBe(true);
  });

  test('requiredCryptosuite=hybrid rejects an eddsa-only credential (downgrade)', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.signCredential({ intent: intent() });
    const res = await Verifier.verifyCredential(cred, pub(publicKeyJwk), 30, {
      requiredCryptosuite: HYBRID_CRYPTOSUITE_ID,
    });
    expect(res.isValid).toBe(false);
  });

  test('hybrid proof without ML key fails closed (no silent downgrade)', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = await signer.signCredentialHybrid({ intent: intent() });
    const res = await Verifier.verifyCredential(cred, pub(publicKeyJwk));
    expect(res.isValid).toBe(false);
  });

  test('cross-issuer verificationMethod is rejected', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = (await signer.signCredential({ intent: intent() })) as unknown as Record<string, unknown>;
    (cred.proof as Record<string, unknown>).verificationMethod = 'did:web:attacker.example#key-1';
    const res = await Verifier.verifyCredential(cred, pub(publicKeyJwk));
    expect(res.isValid).toBe(false);
  });

  test('wrong proofPurpose is rejected', async () => {
    const { signer, publicKeyJwk } = await newSigner();
    const cred = (await signer.signCredential({ intent: intent() })) as unknown as Record<string, unknown>;
    (cred.proof as Record<string, unknown>).proofPurpose = 'authentication';
    const res = await Verifier.verifyCredential(cred, pub(publicKeyJwk));
    expect(res.isValid).toBe(false);
  });

  async function delegatedChild() {
    const a = await newSigner('did:web:alice.example.com');
    const b = await newSigner('did:web:assistant.example.com');
    const parentCred = await a.signer.signCredential({ intent: intent() });
    const childCred = await b.signer.signCredential({
      intent: {
        action: 'read_database',
        target: 'users_table',
        resource: 'https://api.example.com/v1/users/42',
      },
      parentCredential: parentCred,
    });
    return { parentCred, childCred };
  }

  test('delegation link stores the full parentProofValue (not truncated)', async () => {
    const { parentCred, childCred } = await delegatedChild();
    const link = childCred.credentialSubject.delegationChain![0];
    const full = (parentCred as unknown as { proof: { proofValue: string } }).proof.proofValue;
    expect(link.parentProofValue).toBe(full);
    expect(link.parentProofValue!.length).toBeGreaterThan(64);
  });

  test('verifier rejects a delegation link missing parentProofValue', async () => {
    const { childCred } = await delegatedChild();
    const c = childCred as unknown as {
      credentialSubject: { delegationChain: Array<Record<string, unknown>> };
    };
    delete c.credentialSubject.delegationChain[0].parentProofValue;
    // Structural-mode verification (no key) isolates the chain check.
    const res = await Verifier.verifyCredential(childCred as unknown as Record<string, unknown>);
    expect(res.isValid).toBe(false);
  });
});
