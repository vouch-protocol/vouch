/**
 * Delegation lease and physical quorum tests (TypeScript). Mirrors the Python
 * lease.py and physical_quorum.py modules.
 *
 * The cross-language interop cases verify the Python-signed delegation lease and
 * the Python-signed quorum approvals pinned in the shared interop vector: the
 * TypeScript verifier accepts what the Python module produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  buildDelegationLease,
  verifyDelegationLease,
  leasePermits,
  DELEGATION_LEASE_TYPE,
  buildActionApproval,
  verifyActionAuthorization,
  ACTION_APPROVAL_TYPE,
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

const SCOPE = {
  maxForceN: 80,
  maxSpeedMps: 1.5,
  maxSpeedNearHumansMps: 0.25,
  allowedZones: ['cell-3'],
};

async function newSigner(did: string) {
  const keys = await generateIdentity('example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, pub };
}

describe('delegation lease', () => {
  it('verifies the Python-generated interop vector (cross-language)', () => {
    const robotPub = publicKeyFromJwk(VECTOR.robot_public_key_jwk);
    const res = verifyDelegationLease(VECTOR.delegation_lease_credential, robotPub);
    expect(res.ok).toBe(true);
    expect(res.subject?.leaseId).toBe('lease-vector-1');
  });

  it('builds and verifies a lease round-trip', async () => {
    const { signer, pub } = await newSigner('did:web:robot.example.com');
    const cred = await buildDelegationLease(signer, {
      robotDid: 'did:web:robot.example.com',
      leaseId: 'lease-1',
      scope: SCOPE,
      validSeconds: 3600,
    });
    expect(cred.type as string[]).toContain(DELEGATION_LEASE_TYPE);
    const res = verifyDelegationLease(cred, pub);
    expect(res.ok).toBe(true);
    expect(leasePermits(res.subject!, { forceN: 50, zone: 'cell-3' }, cred)).toBe(true);
    expect(leasePermits(res.subject!, { zone: 'cell-9' }, cred)).toBe(false);
  });

  it('rejects an expired lease', async () => {
    const { signer, pub } = await newSigner('did:web:robot.example.com');
    const issued = new Date('2026-01-01T00:00:00Z');
    const cred = await buildDelegationLease(signer, {
      robotDid: 'did:web:robot.example.com',
      leaseId: 'lease-exp',
      scope: SCOPE,
      validSeconds: 60,
      validFrom: issued,
    });
    // One hour after the 60-second window closed.
    const now = new Date('2026-01-01T01:00:00Z');
    expect(verifyDelegationLease(cred, pub, { now }).ok).toBe(false);
  });

  it('rejects a not-yet-valid lease', async () => {
    const { signer, pub } = await newSigner('did:web:robot.example.com');
    const issued = new Date('2026-06-01T00:00:00Z');
    const cred = await buildDelegationLease(signer, {
      robotDid: 'did:web:robot.example.com',
      leaseId: 'lease-future',
      scope: SCOPE,
      validSeconds: 3600,
      validFrom: issued,
    });
    // Well before validFrom.
    const now = new Date('2026-01-01T00:00:00Z');
    expect(verifyDelegationLease(cred, pub, { now }).ok).toBe(false);
  });

  it('accepts a sub-lease that attenuates its parent scope', async () => {
    const { signer, pub } = await newSigner('did:web:integrator.example.com');
    const childScope = {
      maxForceN: 40,
      maxSpeedMps: 1.0,
      maxSpeedNearHumansMps: 0.2,
      allowedZones: ['cell-3'],
    };
    const cred = await buildDelegationLease(signer, {
      robotDid: 'did:web:robot.example.com',
      leaseId: 'sub-lease-1',
      scope: childScope,
      validSeconds: 3600,
      parentLeaseId: 'lease-1',
    });
    expect((cred.credentialSubject as Record<string, unknown>).parentLeaseId).toBe('lease-1');
    expect(verifyDelegationLease(cred, pub, { parentScope: SCOPE }).ok).toBe(true);
  });

  it('rejects a sub-lease that broadens its parent scope', async () => {
    const { signer, pub } = await newSigner('did:web:integrator.example.com');
    const childScope = {
      maxForceN: 200, // broader than parent 80
      maxSpeedMps: 1.5,
      maxSpeedNearHumansMps: 0.25,
      allowedZones: ['cell-3'],
    };
    const cred = await buildDelegationLease(signer, {
      robotDid: 'did:web:robot.example.com',
      leaseId: 'sub-lease-bad',
      scope: childScope,
      validSeconds: 3600,
      parentLeaseId: 'lease-1',
    });
    expect(verifyDelegationLease(cred, pub, { parentScope: SCOPE }).ok).toBe(false);
  });
});

describe('physical quorum', () => {
  it('authorizes the Python-generated interop vector (cross-language)', () => {
    const approverKeys: Record<string, crypto.KeyObject> = {};
    for (const [did, jwk] of Object.entries(VECTOR.quorum_approver_keys)) {
      approverKeys[did] = publicKeyFromJwk(jwk);
    }
    const [authorized, approvers] = verifyActionAuthorization(VECTOR.quorum_approvals, {
      actionId: VECTOR.quorum_action_id,
      robotDid: 'did:web:robot.example.com',
      approverKeys,
      threshold: 2,
    });
    expect(authorized).toBe(true);
    expect(approvers).toEqual([
      'did:web:approver-1.example.com',
      'did:web:approver-2.example.com',
    ]);
  });

  it('builds approvals and authorizes a 2-of-3 quorum', async () => {
    const a1 = await newSigner('did:web:a1.example.com');
    const a2 = await newSigner('did:web:a2.example.com');
    const approverKeys: Record<string, crypto.KeyObject> = {
      'did:web:a1.example.com': a1.pub,
      'did:web:a2.example.com': a2.pub,
    };
    const ap1 = await buildActionApproval(a1.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    const ap2 = await buildActionApproval(a2.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    expect(ap1.type as string[]).toContain(ACTION_APPROVAL_TYPE);
    const [authorized, approvers] = verifyActionAuthorization([ap1, ap2], {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
      approverKeys,
      threshold: 2,
    });
    expect(authorized).toBe(true);
    expect(approvers).toEqual(['did:web:a1.example.com', 'did:web:a2.example.com']);
  });

  it('reports not authorized when the threshold is not met', async () => {
    const a1 = await newSigner('did:web:a1.example.com');
    const approverKeys: Record<string, crypto.KeyObject> = {
      'did:web:a1.example.com': a1.pub,
    };
    const ap1 = await buildActionApproval(a1.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    const [authorized, approvers] = verifyActionAuthorization([ap1], {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
      approverKeys,
      threshold: 2,
    });
    expect(authorized).toBe(false);
    expect(approvers).toEqual(['did:web:a1.example.com']);
  });

  it('counts a duplicate approver only once', async () => {
    const a1 = await newSigner('did:web:a1.example.com');
    const approverKeys: Record<string, crypto.KeyObject> = {
      'did:web:a1.example.com': a1.pub,
    };
    const ap1 = await buildActionApproval(a1.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    const ap1b = await buildActionApproval(a1.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    const [authorized, approvers] = verifyActionAuthorization([ap1, ap1b], {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
      approverKeys,
      threshold: 2,
    });
    expect(authorized).toBe(false);
    expect(approvers).toEqual(['did:web:a1.example.com']);
  });

  it('ignores an approver outside the supplied approver set', async () => {
    const a1 = await newSigner('did:web:a1.example.com');
    const a2 = await newSigner('did:web:a2.example.com');
    const approverKeys: Record<string, crypto.KeyObject> = {
      'did:web:a1.example.com': a1.pub,
      'did:web:a2.example.com': a2.pub,
    };
    const ap1 = await buildActionApproval(a1.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    const ap2 = await buildActionApproval(a2.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    // a2 is not in the attested set, so only a1 counts.
    const [authorized, approvers] = verifyActionAuthorization([ap1, ap2], {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
      approverKeys,
      threshold: 2,
      approverSet: new Set(['did:web:a1.example.com']),
    });
    expect(authorized).toBe(false);
    expect(approvers).toEqual(['did:web:a1.example.com']);
  });

  it('does not count a reject decision toward the quorum', async () => {
    const a1 = await newSigner('did:web:a1.example.com');
    const a2 = await newSigner('did:web:a2.example.com');
    const approverKeys: Record<string, crypto.KeyObject> = {
      'did:web:a1.example.com': a1.pub,
      'did:web:a2.example.com': a2.pub,
    };
    const ap1 = await buildActionApproval(a1.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
    });
    const ap2 = await buildActionApproval(a2.signer, {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
      decision: 'reject',
    });
    const [authorized, approvers] = verifyActionAuthorization([ap1, ap2], {
      actionId: 'act-1',
      robotDid: 'did:web:robot.example.com',
      approverKeys,
      threshold: 2,
    });
    expect(authorized).toBe(false);
    expect(approvers).toEqual(['did:web:a1.example.com']);
  });
});
