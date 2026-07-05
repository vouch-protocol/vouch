/**
 * Physical custody handoff tests (TypeScript). Mirrors the Python custody.py
 * module: signed handoff credentials, custody-chain verification across human
 * and robot actors, a holder-at-time helper, and software condition
 * localization.
 *
 * The cross-language interop case verifies the Python-signed custody chain
 * pinned in the shared interop vector: the TypeScript verifier accepts what the
 * Python module produced, and the condition-change localizer points at the same
 * responsible holder.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  buildHandoff,
  verifyHandoff,
  verifyHandoffChain,
  holderAt,
  locateConditionChange,
  CUSTODY_HANDOFF_TYPE,
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

function actorKeys(jwks: Record<string, unknown>): Record<string, crypto.KeyObject> {
  const keys: Record<string, crypto.KeyObject> = {};
  for (const [did, jwk] of Object.entries(jwks)) {
    keys[did] = publicKeyFromJwk(jwk);
  }
  return keys;
}

async function newSigner(did: string) {
  const keys = await generateIdentity('example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, pub };
}

const TASK = 'tote-42';
const WORKER = 'did:web:worker-jane.example.com';
const ROBOT_A = 'did:web:robot-a.example.com';
const ROBOT_B = 'did:web:robot-b.example.com';

describe('custody handoff (cross-language interop)', () => {
  it('verifies the Python-signed custody chain from the origin actor', () => {
    const keys = actorKeys(VECTOR.custody_actor_keys);
    const res = verifyHandoffChain(VECTOR.custody_chain, keys, {
      originActor: VECTOR.custody_origin_actor,
    });
    expect(res.ok).toBe(true);
    expect(res.currentHolder).toBe(ROBOT_B);
  });

  it('localizes the condition change to the responsible holder', () => {
    const change = locateConditionChange(VECTOR.custody_chain);
    expect(change).not.toBeNull();
    expect(change?.responsibleHolder).toBe(ROBOT_A);
    expect(change?.fromCondition).toBe('intact');
    expect(change?.toCondition).toBe('damaged');
  });
});

describe('custody handoff round-trip', () => {
  it('builds and verifies a handoff signed by the receiver', async () => {
    const robotA = await newSigner(ROBOT_A);
    const cred = await buildHandoff(robotA.signer, {
      taskId: TASK,
      fromActor: WORKER,
      toActor: ROBOT_A,
      condition: 'intact',
    });
    expect(cred.type as string[]).toContain(CUSTODY_HANDOFF_TYPE);
    expect(cred.issuer).toBe(ROBOT_A);
    const subject = cred.credentialSubject as Record<string, unknown>;
    expect(subject.id).toBe(TASK);
    expect(subject.fromActor).toBe(WORKER);
    expect(subject.toActor).toBe(ROBOT_A);
    expect(subject.condition).toBe('intact');
    const res = verifyHandoff(cred, robotA.pub);
    expect(res.ok).toBe(true);
  });

  it('rejects a handoff whose issuer is not the receiving actor', async () => {
    // The signer issues under ROBOT_A but the subject names a different receiver,
    // so the party is not attesting its own acceptance of custody. Verification
    // must fail.
    const robotA = await newSigner(ROBOT_A);
    const cred = await buildHandoff(robotA.signer, {
      taskId: TASK,
      fromActor: WORKER,
      toActor: ROBOT_A,
    });
    (cred.credentialSubject as Record<string, unknown>).toActor = ROBOT_B;
    const res = verifyHandoff(cred, robotA.pub);
    expect(res.ok).toBe(false);
  });
});

describe('custody chain', () => {
  it('accepts an ordered chain worker -> robot-a -> robot-b', async () => {
    const robotA = await newSigner(ROBOT_A);
    const robotB = await newSigner(ROBOT_B);
    const h1 = await buildHandoff(robotA.signer, {
      taskId: TASK,
      fromActor: WORKER,
      toActor: ROBOT_A,
      condition: 'intact',
    });
    const h2 = await buildHandoff(robotB.signer, {
      taskId: TASK,
      fromActor: ROBOT_A,
      toActor: ROBOT_B,
      condition: 'intact',
    });
    const keys = { [ROBOT_A]: robotA.pub, [ROBOT_B]: robotB.pub };
    const res = verifyHandoffChain([h1, h2], keys, { originActor: WORKER });
    expect(res.ok).toBe(true);
    expect(res.currentHolder).toBe(ROBOT_B);
  });

  it('rejects a broken chain where a link does not connect', async () => {
    // h1 leaves the task with ROBOT_A, but h2 claims it came from an actor that
    // never held it, so the links do not join.
    const robotA = await newSigner(ROBOT_A);
    const robotB = await newSigner(ROBOT_B);
    const h1 = await buildHandoff(robotA.signer, {
      taskId: TASK,
      fromActor: WORKER,
      toActor: ROBOT_A,
    });
    const h2 = await buildHandoff(robotB.signer, {
      taskId: TASK,
      fromActor: 'did:web:robot-z.example.com',
      toActor: ROBOT_B,
    });
    const keys = { [ROBOT_A]: robotA.pub, [ROBOT_B]: robotB.pub };
    const res = verifyHandoffChain([h1, h2], keys, { originActor: WORKER });
    expect(res.ok).toBe(false);
  });

  it('rejects a chain missing a receiver key', async () => {
    // The second receiver's key is not supplied, so its handoff cannot be
    // verified and the chain is rejected.
    const robotA = await newSigner(ROBOT_A);
    const robotB = await newSigner(ROBOT_B);
    const h1 = await buildHandoff(robotA.signer, {
      taskId: TASK,
      fromActor: WORKER,
      toActor: ROBOT_A,
    });
    const h2 = await buildHandoff(robotB.signer, {
      taskId: TASK,
      fromActor: ROBOT_A,
      toActor: ROBOT_B,
    });
    const keys = { [ROBOT_A]: robotA.pub };
    const res = verifyHandoffChain([h1, h2], keys, { originActor: WORKER });
    expect(res.ok).toBe(false);
  });
});

describe('holder at time', () => {
  it('names the holder at two points across the Python-signed chain', () => {
    // First handoff validFrom is 00:00:00Z, second is 00:10:00Z.
    expect(holderAt(VECTOR.custody_chain, '2026-01-01T00:05:00Z')).toBe(ROBOT_A);
    expect(holderAt(VECTOR.custody_chain, '2026-01-01T00:15:00Z')).toBe(ROBOT_B);
  });

  it('returns null before the first handoff', () => {
    expect(holderAt(VECTOR.custody_chain, '2025-12-31T23:59:59Z')).toBeNull();
  });
});

describe('condition localization', () => {
  it('returns null when the condition never changes', async () => {
    const robotA = await newSigner(ROBOT_A);
    const robotB = await newSigner(ROBOT_B);
    const h1 = await buildHandoff(robotA.signer, {
      taskId: TASK,
      fromActor: WORKER,
      toActor: ROBOT_A,
      condition: 'intact',
    });
    const h2 = await buildHandoff(robotB.signer, {
      taskId: TASK,
      fromActor: ROBOT_A,
      toActor: ROBOT_B,
      condition: 'intact',
    });
    expect(locateConditionChange([h1, h2])).toBeNull();
  });
});
