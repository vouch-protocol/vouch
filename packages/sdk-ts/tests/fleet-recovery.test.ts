/**
 * Tests for cross-device identity (fleet) and root recovery (Shamir) in the
 * TypeScript SDK. Mirrors the Python tests/test_fleet.py and test_recovery.py.
 */

import * as crypto from 'crypto';

import {
  Agent,
  DeviceRegistry,
  Signer,
  Verifier,
  combineShares,
  enrollDevice,
  generateIdentity,
  recoverIdentity,
  splitIdentity,
  splitSecret,
  verifyDelegatedChain,
} from '../src';

async function rootAndDevice() {
  const root = await Agent.create('root.example', { persist: false });
  const device = await Agent.create(undefined, { persist: false }); // did:key
  return { root, device };
}

async function signedChain(root: Agent, device: Agent) {
  const grant = await enrollDevice(root, {
    deviceDid: device.did,
    action: 'charge',
    target: 'api.bank',
    resource: 'https://api.bank/invoices',
  });
  const action = await device.sign({
    action: 'charge',
    target: 'api.bank',
    resource: 'https://api.bank/invoices/42',
    parentCredential: grant,
  });
  return { grant, action };
}

describe('fleet: per-device delegation', () => {
  test('enroll and verify chain', async () => {
    const { root, device } = await rootAndDevice();
    const { grant, action } = await signedChain(root, device);
    const result = await verifyDelegatedChain([grant, action], {
      trustedRoots: { [root.did]: root.publicKeyJwk },
    });
    expect(result.ok).toBe(true);
    expect(result.rootDid).toBe(root.did);
    expect(result.leaf?.issuer).toBe(device.did);
  });

  test('untrusted root rejected', async () => {
    const { root, device } = await rootAndDevice();
    const { grant, action } = await signedChain(root, device);
    const result = await verifyDelegatedChain([grant, action], { trustedRoots: {} });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('trustedRoots');
  });

  test('wrong device issuer rejected', async () => {
    const { root, device } = await rootAndDevice();
    const grant = await enrollDevice(root, {
      deviceDid: device.did,
      action: 'charge',
      target: 'api.bank',
      resource: 'https://api.bank/invoices',
    });
    const impostor = await Agent.create(undefined, { persist: false });
    const action = await impostor.sign({
      action: 'charge',
      target: 'api.bank',
      resource: 'https://api.bank/invoices/42',
      parentCredential: grant,
    });
    const result = await verifyDelegatedChain([grant, action], {
      trustedRoots: { [root.did]: root.publicKeyJwk },
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('delegatee');
  });

  test('tampered action rejected', async () => {
    const { root, device } = await rootAndDevice();
    const { grant, action } = await signedChain(root, device);
    (action.credentialSubject.intent as Record<string, unknown>).resource =
      'https://api.bank/invoices/evil';
    const result = await verifyDelegatedChain([grant, action], {
      trustedRoots: { [root.did]: root.publicKeyJwk },
    });
    expect(result.ok).toBe(false);
  });

  test('leaf intent policy', async () => {
    const { root, device } = await rootAndDevice();
    const { grant, action } = await signedChain(root, device);
    const roots = { [root.did]: root.publicKeyJwk };
    expect((await verifyDelegatedChain([grant, action], { trustedRoots: roots, requireAction: 'charge' })).ok).toBe(true);
    expect((await verifyDelegatedChain([grant, action], { trustedRoots: roots, requireAction: 'refund' })).ok).toBe(false);
  });
});

describe('fleet: device revocation', () => {
  test('revoked device DID rejected', async () => {
    const { root, device } = await rootAndDevice();
    const { grant, action } = await signedChain(root, device);
    const roots = { [root.did]: root.publicKeyJwk };
    expect((await verifyDelegatedChain([grant, action], { trustedRoots: roots })).ok).toBe(true);
    const result = await verifyDelegatedChain([grant, action], {
      trustedRoots: roots,
      revoked: new Set([device.did]),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('revoked');
  });

  test('DeviceRegistry enroll and revoke', async () => {
    const { root, device } = await rootAndDevice();
    const { grant, action } = await signedChain(root, device);
    const roots = { [root.did]: root.publicKeyJwk };
    const registry = new DeviceRegistry();
    registry.enroll(device.did, grant);
    expect(registry.activeDevices()).toEqual([device.did]);
    expect((await verifyDelegatedChain([grant, action], { trustedRoots: roots, revoked: registry.isRevoked })).ok).toBe(true);
    registry.revoke(device.did);
    expect(registry.activeDevices()).toEqual([]);
    expect((await verifyDelegatedChain([grant, action], { trustedRoots: roots, revoked: registry.isRevoked })).ok).toBe(false);
  });
});

describe('recovery: Shamir', () => {
  test('split and combine round-trip', () => {
    const secret = crypto.randomBytes(32);
    const shares = splitSecret(new Uint8Array(secret), { threshold: 3, shares: 5 });
    expect(shares.length).toBe(5);
    expect(Buffer.from(combineShares(shares.slice(0, 3))).equals(secret)).toBe(true);
    expect(Buffer.from(combineShares([shares[0], shares[2], shares[4]])).equals(secret)).toBe(true);
  });

  test('below threshold does not reveal', () => {
    const secret = crypto.randomBytes(32);
    const shares = splitSecret(new Uint8Array(secret), { threshold: 3, shares: 5 });
    expect(Buffer.from(combineShares(shares.slice(0, 2))).equals(secret)).toBe(false);
  });

  test('split and recover identity signs identically', async () => {
    const keys = await generateIdentity('root.example');
    const shares = splitIdentity(keys, { threshold: 2, shares: 3 });
    expect(shares.length).toBe(3);
    const recovered = recoverIdentity(shares.slice(0, 2), { did: keys.did! });
    expect(recovered.did).toBe(keys.did);
    expect(recovered.publicKeyJwk).toBe(keys.publicKeyJwk);
    // The recovered key is the original: a credential it signs verifies against
    // the ORIGINAL public key.
    const signer = new Signer({ privateKey: recovered.privateKeyJwk, did: keys.did! });
    const cred = await signer.signCredential({ action: 'read', target: 't', resource: 'https://x/y' });
    const { isValid } = await Verifier.verifyCredential(cred, keys.publicKeyJwk);
    expect(isValid).toBe(true);
  });

  test('invalid parameters throw', () => {
    expect(() => splitSecret(new Uint8Array(), { threshold: 2, shares: 3 })).toThrow();
    expect(() => splitSecret(new Uint8Array([1]), { threshold: 1, shares: 3 })).toThrow();
    expect(() => splitSecret(new Uint8Array([1]), { threshold: 4, shares: 3 })).toThrow();
  });
});
