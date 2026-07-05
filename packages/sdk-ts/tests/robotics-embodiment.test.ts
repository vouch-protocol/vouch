/**
 * Cross-embodiment identity continuity tests (TypeScript). Mirrors the Python
 * embodiment.py module: signed embodiment credentials, continuity-chain
 * verification across bodies, and software fork detection.
 *
 * The cross-language interop case verifies the Python-signed embodiment chain
 * pinned in the shared interop vector: the TypeScript verifier accepts what the
 * Python module produced, and the fork check clears it.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  buildEmbodiment,
  verifyEmbodiment,
  verifyContinuityChain,
  checkNoFork,
  EMBODIMENT_TYPE,
} from '../src';

const VECTOR = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../../../test-vectors/robotics/vector.json'),
    'utf8'
  )
);

function publicKeyFromJwk(jwk: unknown): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
}

async function newSigner(did: string) {
  const keys = await generateIdentity('example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, pub };
}

const AGENT = 'did:web:agent.example.com';
const BODY_A = 'did:web:body-a.example.com';
const BODY_B = 'did:web:body-b.example.com';

describe('embodiment continuity (cross-language interop)', () => {
  it('verifies the Python-signed continuity chain under one agent key', () => {
    const agentKey = publicKeyFromJwk(VECTOR.embodiment_agent_key);
    const res = verifyContinuityChain(VECTOR.embodiment_chain, agentKey);
    expect(res.ok).toBe(true);
    expect(res.currentBody).toBe(BODY_B);
  });

  it('clears the Python-signed chain of any fork', () => {
    const res = checkNoFork(VECTOR.embodiment_chain);
    expect(res.ok).toBe(true);
  });
});

describe('embodiment round-trip', () => {
  it('builds and verifies an embodiment signed by the agent', async () => {
    const agent = await newSigner(AGENT);
    const cred = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
    });
    expect(cred.type as string[]).toContain(EMBODIMENT_TYPE);
    expect(cred.issuer).toBe(AGENT);
    const subject = cred.credentialSubject as Record<string, unknown>;
    expect(subject.id).toBe(AGENT);
    expect(subject.body).toBe(BODY_A);
    expect(subject.bodyHardwareRoot).toBe('uROOTA');
    const res = verifyEmbodiment(cred, agent.pub);
    expect(res.ok).toBe(true);
  });

  it('rejects an embodiment whose issuer is not the agent subject', async () => {
    // The signer issues under AGENT but the subject claims a different agent id,
    // so a mind is not authorizing its own embodiment. Verification must fail.
    const agent = await newSigner(AGENT);
    const cred = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
    });
    (cred.credentialSubject as Record<string, unknown>).id = 'did:web:other.example.com';
    const res = verifyEmbodiment(cred, agent.pub);
    expect(res.ok).toBe(false);
  });
});

describe('continuity chain', () => {
  it('accepts an ordered chain that walks A -> B under one agent key', async () => {
    const agent = await newSigner(AGENT);
    const e1 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
      validSeconds: 3600,
    });
    const e2 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_B,
      bodyHardwareRoot: 'uROOTB',
      fromBody: BODY_A,
    });
    const res = verifyContinuityChain([e1, e2], agent.pub);
    expect(res.ok).toBe(true);
    expect(res.currentBody).toBe(BODY_B);
  });

  it('rejects a broken chain where a link does not connect', async () => {
    // e1 leaves the agent on BODY_A, but e2 claims it came from a body it never
    // occupied, so the links do not join.
    const agent = await newSigner(AGENT);
    const e1 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
    });
    const e2 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_B,
      bodyHardwareRoot: 'uROOTB',
      fromBody: 'did:web:body-z.example.com',
    });
    const res = verifyContinuityChain([e1, e2], agent.pub);
    expect(res.ok).toBe(false);
  });

  it('rejects a chain whose links are not all one agent key', async () => {
    // e2 is signed by a different agent key, so the continuity of a single
    // accountable mind is broken even though the bodies connect.
    const agent = await newSigner(AGENT);
    const impostor = await newSigner(AGENT);
    const e1 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
    });
    const e2 = await buildEmbodiment(impostor.signer, {
      agentDid: AGENT,
      bodyDid: BODY_B,
      bodyHardwareRoot: 'uROOTB',
      fromBody: BODY_A,
    });
    const res = verifyContinuityChain([e1, e2], agent.pub);
    expect(res.ok).toBe(false);
  });
});

describe('fork detection', () => {
  it('clears a clean handover where windows do not overlap', async () => {
    const agent = await newSigner(AGENT);
    const start = new Date('2026-01-01T00:00:00Z');
    const e1 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
      embodiedAt: start,
      validSeconds: 3600,
    });
    const e2 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_B,
      bodyHardwareRoot: 'uROOTB',
      fromBody: BODY_A,
      embodiedAt: new Date(start.getTime() + 3600 * 1000),
    });
    const res = checkNoFork([e1, e2]);
    expect(res.ok).toBe(true);
  });

  it('flags two bodies active in overlapping windows as a fork', async () => {
    const agent = await newSigner(AGENT);
    const start = new Date('2026-01-01T00:00:00Z');
    const e1 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_A,
      bodyHardwareRoot: 'uROOTA',
      embodiedAt: start,
      validSeconds: 3600,
    });
    const e2 = await buildEmbodiment(agent.signer, {
      agentDid: AGENT,
      bodyDid: BODY_B,
      bodyHardwareRoot: 'uROOTB',
      embodiedAt: new Date(start.getTime() + 1800 * 1000),
      validSeconds: 3600,
    });
    const res = checkNoFork([e1, e2]);
    expect(res.ok).toBe(false);
    expect(res.conflict).toBeDefined();
    expect([res.conflict?.bodyA, res.conflict?.bodyB].sort()).toEqual([BODY_A, BODY_B]);
  });
});
