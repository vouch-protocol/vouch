/**
 * Physical capability scope tests (TypeScript). Mirrors the Python
 * tests/test_robot_provenance_capability.py and tests/test_attenuation_vectors.py
 * capability cases: enforce force/speed/zone/shift limits before actuation, and
 * require a delegated scope to narrow (never broaden) its parent.
 */

import * as crypto from 'crypto';

import {
  Signer,
  generateIdentity,
  verifyProof,
  buildPhysicalScopeCredential,
  checkPhysicalAction,
  attenuates,
  PHYSICAL_SCOPE_TYPE,
} from '../src';

function pub(jwk: string): crypto.KeyObject {
  return crypto.createPublicKey({ key: JSON.parse(jwk) as crypto.JsonWebKey, format: 'jwk' });
}

const SCOPE = {
  maxForceN: 50,
  maxSpeedMps: 2,
  maxSpeedNearHumansMps: 0.5,
  allowedZones: ['zone-a'],
  shiftWindows: [{ start: '08:00', end: '18:00' }],
};

describe('physical capability scope', () => {
  it('builds and verifies a scope credential', async () => {
    const keys = await generateIdentity('robot.example.com');
    const signer = new Signer({ privateKey: keys.privateKeyJwk, did: 'did:web:robot.example.com' });
    const cred = await buildPhysicalScopeCredential(signer, {
      subjectDid: 'did:web:robot.example.com',
      ...SCOPE,
    });
    expect(cred.type as string[]).toContain(PHYSICAL_SCOPE_TYPE);
    expect(verifyProof(cred, pub(keys.publicKeyJwk))).toBe(true);
  });

  it('checks actions against the scope, including the slower cap near humans', () => {
    expect(checkPhysicalAction(SCOPE, { forceN: 40, speedMps: 1.5, zone: 'zone-a', timeHm: '10:00' }).ok).toBe(true);
    expect(checkPhysicalAction(SCOPE, { forceN: 60 }).ok).toBe(false); // force over cap
    expect(checkPhysicalAction(SCOPE, { speedMps: 1.0, nearHumans: true }).ok).toBe(false); // 1.0 > 0.5 near humans
    expect(checkPhysicalAction(SCOPE, { speedMps: 1.0, nearHumans: false }).ok).toBe(true); // 1.0 <= 2 normal
    expect(checkPhysicalAction(SCOPE, { zone: 'zone-b' }).ok).toBe(false); // zone not allowed
    expect(checkPhysicalAction(SCOPE, { timeHm: '20:00' }).ok).toBe(false); // outside shift window
  });

  it('enforces attenuation: narrow never broaden', () => {
    const parent = {
      maxForceN: 50,
      maxSpeedMps: 2,
      allowedZones: ['zone-a', 'zone-b'],
      shiftWindows: [{ start: '08:00', end: '18:00' }],
    };
    // Strictly narrower child.
    expect(
      attenuates(parent, {
        maxForceN: 30,
        maxSpeedMps: 1,
        allowedZones: ['zone-a'],
        shiftWindows: [{ start: '09:00', end: '17:00' }],
      })
    ).toBe(true);
    expect(attenuates(parent, { maxForceN: 80, maxSpeedMps: 1 })).toBe(false); // broader force
    expect(attenuates(parent, { maxForceN: 30 })).toBe(false); // drops a parent cap
    expect(attenuates(parent, { maxForceN: 30, maxSpeedMps: 1, allowedZones: ['zone-c'] })).toBe(false); // zone not a subset
    expect(
      attenuates(parent, {
        maxForceN: 30,
        maxSpeedMps: 1,
        allowedZones: ['zone-a'],
        shiftWindows: [{ start: '07:00', end: '19:00' }],
      })
    ).toBe(false); // shift window wider than parent
  });
});
