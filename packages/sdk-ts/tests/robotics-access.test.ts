/**
 * Robot-to-infrastructure bounded access tests (TypeScript). Mirrors the Python
 * access.py module: signed access grants and requests, an offline authorize
 * decision, and shrink-only attenuation.
 *
 * The cross-language interop case verifies the Python-signed grant and request
 * pinned in the shared interop vector: the TypeScript authorizer accepts what
 * the Python module produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  buildAccessGrant,
  verifyAccessGrant,
  buildAccessRequest,
  authorizeAccess,
  attenuatesGrant,
  ACCESS_GRANT_TYPE,
  ACCESS_REQUEST_TYPE,
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

const T0 = new Date('2026-01-01T00:00:00Z');
const IN_WINDOW = new Date('2026-01-01T00:05:00Z');
const AFTER = new Date('2026-01-01T02:00:00Z');

const ROBOT_A = 'did:web:robot-a.example.com';
const ROBOT_B = 'did:web:robot-b.example.com';

describe('infrastructure access (cross-language interop)', () => {
  it('authorizes the Python-signed grant and request', () => {
    const operatorKey = publicKeyFromJwk(VECTOR.access_operator_key);
    const robotKey = publicKeyFromJwk(VECTOR.access_robot_key);
    const res = authorizeAccess(
      VECTOR.access_grant_credential,
      VECTOR.access_request_credential,
      operatorKey,
      robotKey
    );
    expect(res.ok).toBe(true);
    expect(res.reasons).toEqual([]);
  });
});

describe('access grant round-trip', () => {
  it('builds and verifies a grant in window', async () => {
    const operator = await newSigner('did:web:facility-ops.example.com');
    const grant = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open', 'close'],
      zone: 'cell-3',
      validSeconds: 3600,
      grantedAt: T0,
    });
    expect(grant.type as string[]).toContain(ACCESS_GRANT_TYPE);
    const subject = grant.credentialSubject as Record<string, unknown>;
    expect(subject.id).toBe(ROBOT_A);
    expect(subject.resource).toBe('door-3');
    expect(subject.zone).toBe('cell-3');
    const res = verifyAccessGrant(grant, operator.pub, { now: IN_WINDOW });
    expect(res.ok).toBe(true);
    expect(res.subject?.resource).toBe('door-3');
  });

  it('rejects a grant out of its window', async () => {
    const operator = await newSigner('did:web:facility-ops.example.com');
    const grant = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open', 'close'],
      validSeconds: 3600,
      grantedAt: T0,
    });
    const res = verifyAccessGrant(grant, operator.pub, { now: AFTER });
    expect(res.ok).toBe(false);
  });

  it('rejects a grant under the wrong operator key', async () => {
    const operator = await newSigner('did:web:facility-ops.example.com');
    const stranger = await newSigner('did:web:stranger.example.com');
    const grant = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open', 'close'],
      validSeconds: 3600,
      grantedAt: T0,
    });
    const res = verifyAccessGrant(grant, stranger.pub, { now: IN_WINDOW });
    expect(res.ok).toBe(false);
  });
});

describe('authorize decision', () => {
  async function setup() {
    const operator = await newSigner('did:web:facility-ops.example.com');
    const robot = await newSigner(ROBOT_A);
    const grant = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open', 'close'],
      zone: 'cell-3',
      validSeconds: 3600,
      grantedAt: T0,
    });
    return { operator, robot, grant };
  }

  async function request(
    robot: { signer: Signer },
    robotDid: string,
    operation = 'open',
    resource = 'door-3'
  ) {
    return buildAccessRequest(robot.signer, {
      robotDid,
      resource,
      operation,
      requestedAt: IN_WINDOW,
    });
  }

  it('authorizes a permitted operation', async () => {
    const { operator, robot, grant } = await setup();
    const req = await request(robot, ROBOT_A, 'open');
    const res = authorizeAccess(grant, req, operator.pub, robot.pub, { now: IN_WINDOW });
    expect(res.ok).toBe(true);
    expect(res.reasons).toEqual([]);
  });

  it('refuses an operation not in the grant', async () => {
    const { operator, robot, grant } = await setup();
    const req = await request(robot, ROBOT_A, 'unlock_admin');
    const res = authorizeAccess(grant, req, operator.pub, robot.pub, { now: IN_WINDOW });
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('operation not permitted by the grant');
  });

  it('refuses a request for a different resource', async () => {
    const { operator, robot, grant } = await setup();
    const req = await request(robot, ROBOT_A, 'open', 'door-9');
    const res = authorizeAccess(grant, req, operator.pub, robot.pub, { now: IN_WINDOW });
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('grant and request name different resources');
  });

  it('refuses when the grant is out of window', async () => {
    const { operator, robot, grant } = await setup();
    const req = await request(robot, ROBOT_A, 'open');
    const res = authorizeAccess(grant, req, operator.pub, robot.pub, { now: AFTER });
    expect(res.ok).toBe(false);
  });

  it('refuses a request from a different robot', async () => {
    const { operator, grant } = await setup();
    const other = await newSigner(ROBOT_B);
    const forged = await buildAccessRequest(other.signer, {
      robotDid: ROBOT_B,
      resource: 'door-3',
      operation: 'open',
      requestedAt: IN_WINDOW,
    });
    const res = authorizeAccess(grant, forged, operator.pub, other.pub, { now: IN_WINDOW });
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('grant and request name different robots');
  });
});

describe('attenuation', () => {
  it('accepts a narrower sub-grant and rejects a wider one', async () => {
    const operator = await newSigner('did:web:facility-ops.example.com');
    const parent = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open', 'close'],
      zone: 'cell-3',
      validSeconds: 3600,
    });
    const narrower = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open'],
      zone: 'cell-3',
      validSeconds: 1800,
    });
    const wider = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operations: ['open', 'close', 'unlock_admin'],
      validSeconds: 1800,
    });
    const otherResource = await buildAccessGrant(operator.signer, {
      robotDid: ROBOT_A,
      resource: 'door-9',
      operations: ['open'],
      validSeconds: 1800,
    });
    expect(attenuatesGrant(parent, narrower)).toBe(true);
    expect(attenuatesGrant(parent, wider)).toBe(false);
    expect(attenuatesGrant(parent, otherResource)).toBe(false);
  });
});

describe('request type', () => {
  it('stamps the access request type', async () => {
    const robot = await newSigner(ROBOT_A);
    const req = await buildAccessRequest(robot.signer, {
      robotDid: ROBOT_A,
      resource: 'door-3',
      operation: 'open',
      requestedAt: IN_WINDOW,
    });
    expect(req.type as string[]).toContain(ACCESS_REQUEST_TYPE);
    expect(req.issuer).toBe(ROBOT_A);
  });
});
