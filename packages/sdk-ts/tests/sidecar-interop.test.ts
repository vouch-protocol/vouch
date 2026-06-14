import { readFileSync } from 'node:fs';
import { type AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createSidecarServer } from '../src/sidecar/server';
import { verifyProofPortable } from '../src/data-integrity-portable';

// @noble/ed25519 v3 sync APIs need sha512 wired in (same as the SDK does).
(ed25519 as { hashes: { sha512?: (m: Uint8Array) => Uint8Array } }).hashes.sha512 = sha512;

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = resolve(
  __dirname,
  '../../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json'
);

interface InteropVector {
  ed25519: { seed_b64: string };
  verificationMethod: string;
  created: string;
  unsigned_credential: Record<string, unknown>;
  proofValue: string;
}

const vector: InteropVector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const seed = new Uint8Array(Buffer.from(vector.ed25519.seed_b64, 'base64'));
const publicKey = ed25519.getPublicKey(seed);
const DID = 'did:web:test.example.com';

let server: ReturnType<typeof createSidecarServer>;
let baseUrl: string;

beforeAll(async () => {
  server = createSidecarServer({ did: DID, seed });
  await new Promise<void>((res) => server.listen(0, res));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((res, rej) =>
    server.close((err) => (err ? rej(err) : res()))
  );
});

async function postSign(body: unknown): Promise<Record<string, unknown>> {
  const resp = await fetch(`${baseUrl}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  expect(resp.status).toBe(200);
  expect(resp.headers.get('content-type')).toContain('application/json');
  return (await resp.json()) as Record<string, unknown>;
}

describe('TS sidecar eddsa-jcs-2022 interop', () => {
  it('reproduces the shared vector proofValue EXACTLY', async () => {
    const signed = await postSign({
      credential: vector.unsigned_credential,
      created: vector.created,
    });
    const proof = signed.proof as { proofValue: string };
    expect(proof.proofValue).toBe(vector.proofValue);
  });

  it('round-trips an intent-built credential that verifies', async () => {
    const signed = await postSign({
      intent: {
        action: 'read_database',
        target: 'users_table',
        resource: 'https://api.example.com/v1/users',
      },
    });
    const proof = signed.proof as { type: string; cryptosuite: string };
    expect(proof.type).toBe('DataIntegrityProof');
    expect(proof.cryptosuite).toBe('eddsa-jcs-2022');
    expect(verifyProofPortable(signed, publicKey)).toBe(true);
  });

  it('/health reports operational', async () => {
    const resp = await fetch(`${baseUrl}/health`);
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as {
      status: string;
      did: string;
      mode: string;
    };
    expect(body.status).toBe('operational');
    expect(body.did).toBe(DID);
    expect(body.mode).toBe('standard (eddsa-jcs-2022)');
  });
});
