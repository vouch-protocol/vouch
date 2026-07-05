/**
 * Tests for the developer-experience and secure key-custody surface ported from
 * the Python SDK: Agent, top-level sign/verify, named-argument intent,
 * Signer.fromKeypair / fromBackend, the sign callback, did:key resolution, the
 * Credential wrapper, key stores, and the requireSigned / guardMcp guards.
 */

import * as crypto from 'crypto';

import {
  Agent,
  Credential,
  EncryptedFileKeyStore,
  MemoryKeyStore,
  Signer,
  Verifier,
  buildProof,
  buildVouchCredential,
  generateIdentity,
  guardMcp,
  guardTools,
  requireSigned,
  sign,
  verify,
} from '../src';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

const INTENT = {
  action: 'read',
  target: 'did:web:files',
  resource: 'https://files/x',
};

function rawPrivate(privateKeyJwk: string): crypto.KeyObject {
  return crypto.createPrivateKey({
    key: JSON.parse(privateKeyJwk) as crypto.JsonWebKey,
    format: 'jwk',
  });
}

// ---------------------------------------------------------------------------
// Named-argument intent + Signer.fromKeypair
// ---------------------------------------------------------------------------

describe('named-argument intent and fromKeypair', () => {
  test('named args equal the intent object and verify', async () => {
    const keys = await generateIdentity('agent.example');
    const signer = Signer.fromKeypair(keys);
    const byObject = await signer.sign({ intent: INTENT });
    const byNamed = await signer.sign({
      action: 'read',
      target: 'did:web:files',
      resource: 'https://files/x',
    });
    expect(byNamed.credentialSubject.intent).toEqual(byObject.credentialSubject.intent);
    const { isValid } = await Verifier.verify(byNamed, keys.publicKeyJwk);
    expect(isValid).toBe(true);
  });

  test('named fields override the intent object', async () => {
    const keys = await generateIdentity('agent.example');
    const signer = Signer.fromKeypair(keys);
    const cred = await signer.sign({
      intent: INTENT,
      resource: 'https://files/override',
    });
    expect(cred.credentialSubject.intent.resource).toBe('https://files/override');
    expect(cred.credentialSubject.intent.action).toBe('read');
  });

  test('fromKeypair without a DID throws', async () => {
    const keys = await generateIdentity();
    expect(() => Signer.fromKeypair(keys)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Top-level sign / verify
// ---------------------------------------------------------------------------

describe('top-level sign and verify', () => {
  test('sign then verify with an explicit key', async () => {
    const keys = await generateIdentity('agent.example');
    const signed = await sign(keys, INTENT);
    const { isValid, passport } = await verify(signed, keys.publicKeyJwk);
    expect(isValid).toBe(true);
    expect(passport?.action).toBe('read');
    expect(passport?.resource).toBe('https://files/x');
  });

  test('verify rejects the wrong key', async () => {
    const keys = await generateIdentity('agent.example');
    const other = await generateIdentity('other.example');
    const signed = await sign(keys, INTENT);
    const { isValid } = await verify(signed, other.publicKeyJwk);
    expect(isValid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

describe('Agent', () => {
  test('mint did:web, sign, self-verify', async () => {
    const agent = await Agent.create('agent.example', { persist: false });
    expect(agent.did).toBe('did:web:agent.example');
    const signed = await agent.sign(INTENT);
    const { isValid, passport } = await agent.verify(signed);
    expect(isValid).toBe(true);
    expect(passport?.issuer).toBe(agent.did);
  });

  test('mint did:key and verify offline through verify()', async () => {
    const agent = await Agent.create(undefined, { persist: false });
    expect(agent.did.startsWith('did:key:')).toBe(true);
    const signed = await agent.sign(INTENT);
    const { isValid, passport } = await verify(signed);
    expect(isValid).toBe(true);
    expect(passport?.issuer).toBe(agent.did);
  });

  test('load roundtrip', async () => {
    const agent = await Agent.create('agent.example', {
      persist: false,
      allowKeyExport: true,
    });
    const signed = await agent.sign(INTENT);
    const reloaded = Agent.load(agent.privateKeyJwk(), agent.did);
    expect(reloaded.did).toBe(agent.did);
    const { isValid } = await reloaded.verify(signed);
    expect(isValid).toBe(true);
  });

  test('private key is gated by default and signing still works', async () => {
    const agent = await Agent.create('agent.example', { persist: false });
    expect(() => agent.privateKeyJwk()).toThrow();
    const signed = await agent.sign(INTENT);
    const { isValid } = await agent.verify(signed);
    expect(isValid).toBe(true);
  });

  test('private key with explicit consent', async () => {
    const agent = await Agent.create('agent.example', {
      persist: false,
      allowKeyExport: true,
    });
    expect(agent.privateKeyJwk()).toBeTruthy();
  });

  test('persists to a given store and reloads', async () => {
    const store = new MemoryKeyStore();
    const agent = await Agent.create('agent.example', { store });
    expect(await store.list()).toEqual([agent.did]);
    const reloaded = await Agent.fromStore(agent.did, store);
    const signed = await reloaded.sign(INTENT);
    const { isValid } = await reloaded.verify(signed);
    expect(isValid).toBe(true);
    expect(() => reloaded.privateKeyJwk()).toThrow();
  });

  test('delegate and chain', async () => {
    const principal = await Agent.create('principal.example', { persist: false });
    const grant = await principal.delegate({
      action: 'charge',
      target: 'api.bank',
      resource: 'https://api.bank/invoices',
    });
    const worker = await Agent.create('worker.example', { persist: false });
    const child = await worker.sign({
      action: 'charge',
      target: 'api.bank',
      resource: 'https://api.bank/invoices/42',
      parentCredential: grant,
    });
    expect(child.credentialSubject.delegationChain?.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Backend signing (key never in the Signer)
// ---------------------------------------------------------------------------

describe('backend signing', () => {
  test('buildProof accepts a sign callback', async () => {
    const keys = await generateIdentity('agent.example');
    const raw = rawPrivate(keys.privateKeyJwk);
    let calls = 0;
    const cred = buildVouchCredential({ issuerDid: keys.did!, intent: INTENT });
    const proof = buildProof(cred as unknown as Record<string, unknown>, {
      sign: (digest) => {
        calls++;
        return new Uint8Array(crypto.sign(null, Buffer.from(digest), raw));
      },
      verificationMethod: `${keys.did}#key-1`,
    });
    (cred as Record<string, unknown>).proof = proof;
    expect(calls).toBe(1);
    const { isValid } = await Verifier.verify(cred, keys.publicKeyJwk);
    expect(isValid).toBe(true);
  });

  test('Signer.fromBackend signs without holding the key', async () => {
    const keys = await generateIdentity('agent.example');
    const raw = rawPrivate(keys.privateKeyJwk);
    const signer = Signer.fromBackend(keys.did!, keys.publicKeyJwk, (digest) =>
      new Uint8Array(crypto.sign(null, Buffer.from(digest), raw))
    );
    const cred = await signer.sign({ intent: INTENT });
    const { isValid, passport } = await Verifier.verify(cred, keys.publicKeyJwk);
    expect(isValid).toBe(true);
    expect(passport?.issuer).toBe(keys.did);
  });

  test('backend signer blocks legacy JWS and hybrid', async () => {
    const keys = await generateIdentity('agent.example');
    const raw = rawPrivate(keys.privateKeyJwk);
    const signer = Signer.fromBackend(keys.did!, keys.publicKeyJwk, (digest) =>
      new Uint8Array(crypto.sign(null, Buffer.from(digest), raw))
    );
    await expect(signer.sign({ action: 'x' })).rejects.toThrow();
    await expect(
      signer.signHybrid({ action: 'a', target: 'b', resource: 'c' })
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Credential wrapper
// ---------------------------------------------------------------------------

describe('Credential wrapper', () => {
  test('accessors and verify and JSON', async () => {
    const keys = await generateIdentity('agent.example');
    const signed = await sign(keys, INTENT);
    const c = new Credential(signed);
    expect(c.action).toBe('read');
    expect(c.target).toBe('did:web:files');
    expect(c.resource).toBe('https://files/x');
    expect(c.issuer).toBe(keys.did);
    expect(c.isExpired).toBe(false);
    const { isValid } = await c.verify(keys.publicKeyJwk);
    expect(isValid).toBe(true);
    expect(JSON.parse(c.toJsonString())).toEqual(signed);
  });

  test('rejects bad input', () => {
    expect(() => new Credential(12345 as never)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Key stores
// ---------------------------------------------------------------------------

describe('key stores', () => {
  test('memory store roundtrip', async () => {
    const keys = await generateIdentity('agent.example');
    const store = new MemoryKeyStore();
    await store.save({
      privateKeyJwk: keys.privateKeyJwk,
      publicKeyJwk: keys.publicKeyJwk,
      did: keys.did!,
    });
    expect(await store.list()).toEqual([keys.did]);
    const loaded = await store.load(keys.did!);
    expect(loaded.privateKeyJwk).toBe(keys.privateKeyJwk);
  });

  test('encrypted file store roundtrip and wrong password', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouch-ks-'));
    const keys = await generateIdentity('agent.example');
    const identity = {
      privateKeyJwk: keys.privateKeyJwk,
      publicKeyJwk: keys.publicKeyJwk,
      did: keys.did!,
    };
    const loc = await new EncryptedFileKeyStore({ keyDir: dir, password: 'right' }).save(identity);
    expect(loc).toContain('encrypted');
    const loaded = await new EncryptedFileKeyStore({ keyDir: dir, password: 'right' }).load(
      keys.did!
    );
    expect(loaded.privateKeyJwk).toBe(keys.privateKeyJwk);
    await expect(
      new EncryptedFileKeyStore({ keyDir: dir, password: 'wrong' }).load(keys.did!)
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

describe('requireSigned and guardMcp', () => {
  test('allows a trusted signed call and rejects others', async () => {
    const agent = await Agent.create(undefined, { persist: false }); // did:key
    const signed = await agent.sign(INTENT);
    const other = await Agent.create(undefined, { persist: false });
    const fromOther = await other.sign(INTENT);

    const writeFile = requireSigned(
      async (args: { path: string }) => `wrote ${args.path}`,
      { trustedDids: [agent.did] }
    );

    expect(await writeFile({ path: '/x', vouchCredential: signed } as never)).toBe('wrote /x');
    await expect(writeFile({ path: '/x' } as never)).rejects.toThrow();
    await expect(
      writeFile({ path: '/x', vouchCredential: fromOther } as never)
    ).rejects.toThrow();
  });

  test('intent policy', async () => {
    const agent = await Agent.create(undefined, { persist: false });
    const good = await agent.sign(INTENT);
    const bad = await agent.sign({ action: 'delete', target: 't', resource: 'r' });
    const handler = requireSigned(async () => 'ok', {
      trustedDids: [agent.did],
      requireAction: 'read',
    });
    expect(await handler({ vouchCredential: good } as never)).toBe('ok');
    await expect(handler({ vouchCredential: bad } as never)).rejects.toThrow();
  });

  test('onReject null returns null', async () => {
    const agent = await Agent.create(undefined, { persist: false });
    const handler = requireSigned(async () => 'ran', {
      trustedDids: [agent.did],
      onReject: 'null',
    });
    expect(await handler({} as never)).toBeNull();
  });

  test('guardTools wraps a list', async () => {
    const agent = await Agent.create(undefined, { persist: false });
    const signed = await agent.sign(INTENT);
    const [t1] = guardTools([async (args: { x: string }) => args.x], {
      trustedDids: [agent.did],
    });
    expect(await t1({ x: 'hi', vouchCredential: signed } as never)).toBe('hi');
    await expect(t1({ x: 'hi' } as never)).rejects.toThrow();
  });

  test('guardMcp patches a tool-registration hook', async () => {
    const agent = await Agent.create(undefined, { persist: false });
    const signed = await agent.sign(INTENT);

    const registered: Record<string, (args: never) => unknown> = {};
    const server = {
      tool(name: string, handler: (args: never) => unknown) {
        registered[name] = handler;
      },
    };
    guardMcp(server, { trustedDids: [agent.did] });
    server.tool('do_thing', async (args: { x: string }) => `did ${args.x}`);

    expect(await registered.do_thing({ x: 'y', vouchCredential: signed } as never)).toBe('did y');
    await expect(registered.do_thing({ x: 'y' } as never)).rejects.toThrow();
  });

  test('guardMcp throws without a hook', () => {
    expect(() => guardMcp({} as never, { trustedDids: ['did:web:x'] })).toThrow();
  });
});
