/**
 * Verifier.verify handles post-quantum dual-proof credentials, mirroring the
 * Python reference (tests/test_pq_verify.py) and the Go sidecar.
 */

import { Signer, Verifier, generateIdentity } from '../src';

const INTENT = { action: 'read', target: 'ledger', resource: 'https://bank.example.com/ledger' };

async function pq() {
  const keys = await generateIdentity('pq-agent.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did: keys.did! });
  const cred = (await signer.signHybrid({ intent: INTENT })) as unknown as Record<string, unknown>;
  return { signer, cred, edKey: keys.publicKeyJwk };
}

describe('post-quantum verify', () => {
  test('a valid dual proof verifies with both keys', async () => {
    const { signer, cred, edKey } = await pq();
    const r = await Verifier.verify(cred, edKey, 30, { mldsa44PublicKey: signer.publicKeyMLDSA44() });
    expect(r.isValid).toBe(true);
    const m = await Verifier.verify(cred, edKey, 30, { mldsa44PublicKey: signer.publicKeyMLDSA44Multikey() });
    expect(m.isValid).toBe(true);
  });

  test('a tampered payload fails', async () => {
    const { signer, cred, edKey } = await pq();
    const bad = JSON.parse(JSON.stringify(cred));
    bad.credentialSubject.intent.resource = 'https://bank.example.com/vault';
    const r = await Verifier.verify(bad, edKey, 30, { mldsa44PublicKey: signer.publicKeyMLDSA44() });
    expect(r.isValid).toBe(false);
  });

  test('a missing ML-DSA-44 key is a clear error', async () => {
    const { cred, edKey } = await pq();
    const r = await Verifier.verify(cred, edKey);
    expect(r.isValid).toBe(false);
    expect(r.error).toMatch(/ML-DSA-44/);
    expect(r.error).toMatch(/mldsa44PublicKey/);
  });

  test('a stripped proof set fails', async () => {
    const { signer, cred, edKey } = await pq();
    const stripped = JSON.parse(JSON.stringify(cred));
    stripped.proof = stripped.proof.filter((p: { cryptosuite: string }) => p.cryptosuite === 'eddsa-jcs-2022');
    const r = await Verifier.verify(stripped, edKey, 30, { mldsa44PublicKey: signer.publicKeyMLDSA44() });
    expect(r.isValid).toBe(false);
  });

  test('a classical credential is refused when post-quantum is required', async () => {
    const { signer, edKey } = await pq();
    const classical = await signer.sign({ intent: INTENT });
    const r = await Verifier.verify(classical, edKey, 30, { mldsa44PublicKey: signer.publicKeyMLDSA44() });
    expect(r.isValid).toBe(false);
  });
});
