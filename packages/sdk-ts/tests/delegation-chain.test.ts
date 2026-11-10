/**
 * Delegation chain verification against the shared vector, plus signer and
 * fleet narrowing. Mirrors tests/test_delegation_chain_vectors.py and
 * tests/test_delegation_verify.py (the Python reference).
 */

import * as fs from 'fs';
import * as path from 'path';

import { Agent, Verifier, enrollDevice, verifyDelegatedChain, verifyDelegationChain } from '../src';

const VECTOR = path.join(__dirname, '..', '..', '..', 'test-vectors', 'delegation-chain', 'vector.json');
const CASES: Array<{ name: string; now: string; credential: Record<string, unknown>; expected: string | null }> =
  JSON.parse(fs.readFileSync(VECTOR, 'utf-8')).cases;

describe('delegation-chain vector', () => {
  test('has the full case set', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(16);
  });

  for (const c of CASES) {
    test(`chain verdict: ${c.name}`, async () => {
      expect(await verifyDelegationChain(c.credential, { now: new Date(c.now) })).toBe(c.expected);
    });

    test(`full verify agrees: ${c.name}`, async () => {
      const issuer = c.credential.issuer as string;
      const r = await Verifier.verify(c.credential, issuer.slice('did:key:'.length), 30, {
        now: new Date(c.now),
      });
      expect(r.isValid).toBe(c.expected === null);
    });
  }

  test('a pinned root that is not the chain root is refused', async () => {
    const valid = CASES.find((c) => c.name === 'valid_two_hop')!;
    expect(
      await verifyDelegationChain(valid.credential, {
        now: new Date(valid.now),
        trustedRoots: ['did:key:z6MkNotTheRoot'],
      })
    ).toBe('untrusted_principal');
  });
});

describe('signer and Agent refuse to widen a grant', () => {
  const cases: Array<[string, Record<string, string>]> = [
    ['action', { action: 'refund', target: 'api.bank', resource: 'https://api.bank/invoices/42' }],
    ['target', { action: 'charge', target: 'api.payroll', resource: 'https://api.bank/invoices/42' }],
    ['resource', { action: 'charge', target: 'api.bank', resource: 'https://api.bank/payroll' }],
  ];
  for (const [dim, intent] of cases) {
    test(`widened ${dim} is refused`, async () => {
      const principal = await Agent.create('principal.example', { persist: false });
      const worker = await Agent.create(undefined, { persist: false });
      const grant = await principal.delegate({
        action: 'charge',
        target: 'api.bank',
        resource: 'https://api.bank/invoices',
        to: worker.did,
      });
      await expect(worker.sign({ ...intent, parentCredential: grant } as never)).rejects.toThrow();
    });
  }

  test('an in-scope child chains and verifies against the principal', async () => {
    const principal = await Agent.create('principal.example', { persist: false });
    const worker = await Agent.create(undefined, { persist: false });
    const grant = await principal.delegate({
      action: 'charge',
      target: 'api.bank',
      resource: 'https://api.bank/invoices',
      to: worker.did,
    });
    const child = await worker.sign({
      action: 'charge',
      target: 'api.bank',
      resource: 'https://api.bank/invoices/42',
      parentCredential: grant,
    });
    expect(
      await verifyDelegationChain(child as never, { trustedRoots: { [principal.did]: principal.publicKeyJwk } })
    ).toBeNull();
  });
});

describe('fleet narrows action and target', () => {
  for (const [action, target] of [
    ['deploy', 'k8s.prod'],
    ['delete', 'k8s.staging'],
  ]) {
    test(`leaf ${action} on ${target} under a deploy/k8s.staging grant is refused`, async () => {
      const root = await Agent.create('root.example', { persist: false });
      const device = await Agent.create(undefined, { persist: false });
      const grant = await enrollDevice(root, {
        deviceDid: device.did,
        action: 'deploy',
        target: 'k8s.staging',
        resource: 'https://k8s.example/apps',
      });
      const leaf = await device.sign({ action, target, resource: 'https://k8s.example/apps' });
      const r = await verifyDelegatedChain([grant, leaf], {
        trustedRoots: { [root.did]: root.publicKeyJwk },
      });
      expect(r.ok).toBe(false);
      expect(r.reason).toContain('not within the granted');
    });
  }
});
