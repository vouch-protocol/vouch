/**
 * Every tool protected by default, checked before it runs.
 *
 * Ported from tests/test_vouch_mcp.py. The property under test is that the tool
 * body is not entered unless a verified credential authorises exactly that call
 * and Shield permits it, so most tests assert on a spy rather than only on the
 * returned value: a refusal that still ran the tool would be worthless.
 */

import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import * as crypto from 'node:crypto';

import { Signer, encodeEd25519Public } from '@vouch-protocol-official/sdk';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { McpServer, VouchMcpConfigError, VouchRefusedError } from './index.js';

const TARGET = 'files';

interface Fixture {
  did: string;
  signer: Signer;
  rulesPath: string;
}

function writeRules(dir: string, did: string, allow?: unknown[]): string {
  const rules = allow ?? [{ action: 'read_file', target: TARGET, resource: 'reports/**' }];
  const path = join(dir, 'rules.json');
  writeFileSync(
    path,
    JSON.stringify({ version: 2, rules: [{ did, allow: rules }], deny_default: true }),
  );
  return path;
}

// Node needs DER-wrapped keys; a raw Ed25519 seed gets this fixed PKCS8 prefix.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** A did:key identity, which resolves offline with no document to host. */
function makeIdentity(): { did: string; signer: Signer } {
  const seed = crypto.randomBytes(32);
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const pubJwk = crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x: string };
  const xRaw = new Uint8Array(Buffer.from(pubJwk.x, 'base64url'));
  const did = 'did:key:' + encodeEd25519Public(xRaw);
  const privateKey = JSON.stringify({
    kty: 'OKP',
    crv: 'Ed25519',
    x: pubJwk.x,
    d: seed.toString('base64url'),
  });
  return { did, signer: new Signer({ privateKey, did }) };
}

async function makeFixture(allow?: unknown[]): Promise<Fixture> {
  const { did, signer } = makeIdentity();
  const dir = mkdtempSync(join(tmpdir(), 'vouch-mcp-'));
  return { did, signer, rulesPath: writeRules(dir, did, allow) };
}

function server(fx: Fixture, register: (s: McpServer, spy: string[]) => void) {
  const spy: string[] = [];
  const s = new McpServer(
    { name: 'files', version: '1.0.0' },
    { rulesPath: fx.rulesPath, trustedIssuers: [fx.did], target: TARGET },
  );
  register(s, spy);
  return { server: s, spy };
}

/** Invoke a registered tool the way the SDK would, returning ok or refused. */
async function call(
  s: McpServer,
  name: string,
  args: Record<string, unknown>,
): Promise<{ status: 'ok' | 'refused'; payload?: Record<string, unknown> }> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registered = (s as any)._registeredTools[name];
  try {
    await registered.handler(args, {});
    return { status: 'ok' };
  } catch (error) {
    if (error instanceof VouchRefusedError) {
      return { status: 'refused', payload: error.refusal as unknown as Record<string, unknown> };
    }
    throw error;
  }
}

async function credentialFor(
  fx: Fixture,
  resource: string,
  overrides: { action?: string; target?: string } = {},
): Promise<string> {
  const credential = await fx.signer.sign({
    action: overrides.action ?? 'read_file',
    target: overrides.target ?? TARGET,
    resource,
  });
  return JSON.stringify(credential);
}

function registerReadFile(s: McpServer, spy: string[]) {
  s.registerTool(
    'read_file',
    {
      inputSchema: { path: z.string() },
      resource: (args: Record<string, unknown>) => args.path as string,
    },
    async ({ path }: { path: string }) => {
      spy.push(path);
      return { content: [{ type: 'text', text: `contents of ${path}` }] };
    },
  );
}

describe('the default is protected', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => undefined));

  it('refuses a call with no credential, without asking', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', { path: 'reports/q3.txt' });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('no credential');
    expect(spy).toEqual([]);
  });

  it('declares credential as a required argument', async () => {
    const fx = await makeFixture();
    const { server: s } = server(fx, registerReadFile);
    // The SDK compiles inputSchema into a Zod object, so read the shape back
    // out rather than the raw config we handed it.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const registered = (s as any)._registeredTools.read_file;
    const shape = registered.inputSchema?.shape ?? registered.inputSchema?._def?.shape?.();
    expect(Object.keys(shape ?? {})).toContain('credential');
  });

  it('lets an unprotected tool through and says so', async () => {
    const fx = await makeFixture();
    const spy: string[] = [];
    const s = new McpServer(
      { name: 'files', version: '1.0.0' },
      { rulesPath: fx.rulesPath, trustedIssuers: [fx.did], target: TARGET },
    );
    s.registerTool('health', { unprotected: true }, async () => {
      spy.push('health');
      return { content: [{ type: 'text', text: 'ok' }] };
    });

    const result = await call(s, 'health', {});
    expect(result.status).toBe('ok');
    expect(spy).toEqual(['health']);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('UNPROTECTED'));
  });

  it('rejects a resource callback on an unprotected tool', async () => {
    const fx = await makeFixture();
    const { server: s } = server(fx, () => undefined);
    expect(() =>
      s.registerTool('x', { unprotected: true, resource: () => 'a' }, async () => ({
        content: [],
      })),
    ).toThrow();
  });
});

describe('verification', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => undefined));

  it('runs an in-scope call', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', {
      path: 'reports/q3.txt',
      credential: await credentialFor(fx, 'reports/q3.txt'),
    });
    expect(result.status).toBe('ok');
    expect(spy).toEqual(['reports/q3.txt']);
  });

  it('refuses a forged signature', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const credential = JSON.parse(await credentialFor(fx, 'reports/q3.txt'));
    const proof = credential.proof.proofValue as string;
    credential.proof.proofValue = proof.slice(0, -1) + (proof.endsWith('A') ? 'B' : 'A');

    const result = await call(s, 'read_file', {
      path: 'reports/q3.txt',
      credential: JSON.stringify(credential),
    });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('credential did not verify');
    expect(spy).toEqual([]);
  });

  it('refuses an untrusted issuer', async () => {
    const fx = await makeFixture();
    const stranger = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', {
      path: 'reports/q3.txt',
      credential: await credentialFor(stranger, 'reports/q3.txt'),
    });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('untrusted issuer');
    expect(spy).toEqual([]);
  });

  it('refuses an unparseable credential', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', { path: 'reports/q3.txt', credential: 'not json' });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('no credential');
    expect(spy).toEqual([]);
  });
});

describe('the credential must be for this call', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => undefined));

  it('refuses a credential minted for a different file', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', {
      path: 'reports/q4.txt',
      credential: await credentialFor(fx, 'reports/q3.txt'),
    });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('credential does not match request');
    expect(spy).toEqual([]);
  });

  it('refuses a credential minted for a different action', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', {
      path: 'reports/q3.txt',
      credential: await credentialFor(fx, 'reports/q3.txt', { action: 'write_file' }),
    });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('credential does not match request');
    expect(spy).toEqual([]);
  });

  it('refuses a credential minted for a different target', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', {
      path: 'reports/q3.txt',
      credential: await credentialFor(fx, 'reports/q3.txt', { target: 'somewhere-else' }),
    });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('credential does not match request');
    expect(spy).toEqual([]);
  });
});

describe('Shield', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => undefined));

  it('never reaches the tool for an out-of-scope resource', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const result = await call(s, 'read_file', {
      path: 'secrets/keys.txt',
      credential: await credentialFor(fx, 'secrets/keys.txt'),
    });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('resource outside scope');
    expect(spy).toEqual([]);
  });

  it('refuses a traversal', async () => {
    const fx = await makeFixture();
    const { server: s, spy } = server(fx, registerReadFile);

    const path = 'reports/../secrets/keys.txt';
    const result = await call(s, 'read_file', { path, credential: await credentialFor(fx, path) });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('resource outside scope');
    expect(spy).toEqual([]);
  });
});

describe('resource binding', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => undefined));

  it('binds a credential to exact arguments by default', async () => {
    const fx = await makeFixture([{ action: 'run_query', target: TARGET, resource: '**' }]);
    const spy: string[] = [];
    const s = new McpServer(
      { name: 'files', version: '1.0.0' },
      { rulesPath: fx.rulesPath, trustedIssuers: [fx.did], target: TARGET },
    );
    s.registerTool(
      'run_query',
      { inputSchema: { table: z.string(), where: z.string() } },
      async ({ table, where }: { table: string; where: string }) => {
        spy.push(`${table}|${where}`);
        return { content: [] };
      },
    );

    const { canonicalizeToString } = await import('@vouch-protocol-official/sdk');
    const resource = canonicalizeToString({ table: 'a', where: 'x' });
    const credential = JSON.stringify(
      await fx.signer.sign({ action: 'run_query', target: TARGET, resource }),
    );

    expect((await call(s, 'run_query', { table: 'a', where: 'x', credential })).status).toBe('ok');
    const changed = await call(s, 'run_query', { table: 'a', where: 'y', credential });
    expect(changed.status).toBe('refused');
    expect(changed.payload?.reason).toBe('credential does not match request');
    expect(spy).toEqual(['a|x']);
  });

  it('lets a resource callback widen the unit to a glob', async () => {
    const fx = await makeFixture([{ action: 'run_query', target: TARGET, resource: 'public.*' }]);
    const spy: string[] = [];
    const s = new McpServer(
      { name: 'files', version: '1.0.0' },
      { rulesPath: fx.rulesPath, trustedIssuers: [fx.did], target: TARGET },
    );
    s.registerTool(
      'run_query',
      {
        inputSchema: { table: z.string() },
        resource: (args: Record<string, unknown>) => args.table as string,
      },
      async ({ table }: { table: string }) => {
        spy.push(table);
        return { content: [] };
      },
    );

    const ok = JSON.stringify(
      await fx.signer.sign({ action: 'run_query', target: TARGET, resource: 'public.customers' }),
    );
    expect((await call(s, 'run_query', { table: 'public.customers', credential: ok })).status).toBe(
      'ok',
    );

    const denied = JSON.stringify(
      await fx.signer.sign({ action: 'run_query', target: TARGET, resource: 'internal.salaries' }),
    );
    const blocked = await call(s, 'run_query', { table: 'internal.salaries', credential: denied });
    expect(blocked.status).toBe('refused');
    expect(blocked.payload?.reason).toBe('resource outside scope');
    expect(spy).toEqual(['public.customers']);
  });
});

describe('configuration', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => undefined));

  it('refuses to start without rules', async () => {
    expect(
      () =>
        new McpServer(
          { name: 'files', version: '1.0.0' },
          { trustedIssuers: ['did:key:z6Mk'], env: {} },
        ),
    ).toThrow(VouchMcpConfigError);
  });

  it('refuses to start without trusted issuers', async () => {
    const fx = await makeFixture();
    expect(
      () =>
        new McpServer({ name: 'files', version: '1.0.0' }, { rulesPath: fx.rulesPath, env: {} }),
    ).toThrow(VouchMcpConfigError);
  });

  it('defaults the target to the server name', async () => {
    const fx = await makeFixture();
    const s = new McpServer(
      { name: 'crm-tools', version: '1.0.0' },
      { rulesPath: fx.rulesPath, trustedIssuers: [fx.did], env: {} },
    );
    expect(s.vouchGuard.config.target).toBe('crm-tools');
  });

  it('refuses everything when the rules will not load', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vouch-mcp-bad-'));
    const rulesPath = join(dir, 'rules.json');
    writeFileSync(rulesPath, JSON.stringify({ version: 1, rules: [] }));
    const identity = makeIdentity();

    const spy: string[] = [];
    const s = new McpServer(
      { name: 'files', version: '1.0.0' },
      { rulesPath, trustedIssuers: [identity.did], target: TARGET },
    );
    s.registerTool(
      'read_file',
      { inputSchema: { path: z.string() }, resource: (a: Record<string, unknown>) => a.path as string },
      async ({ path }: { path: string }) => {
        spy.push(path);
        return { content: [] };
      },
    );

    const credential = JSON.stringify(
      await identity.signer.sign({
        action: 'read_file',
        target: TARGET,
        resource: 'reports/q3.txt',
      }),
    );
    const result = await call(s, 'read_file', { path: 'reports/q3.txt', credential });
    expect(result.status).toBe('refused');
    expect(result.payload?.reason).toBe('malformed rules');
    expect(spy).toEqual([]);
  });
});
