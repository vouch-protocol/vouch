/**
 * Robot wear and degradation attestation tests (TypeScript). Mirrors the Python
 * wear.py module: a signed, hash-linked wear history and a physical scope
 * narrowed for the attested wear level.
 *
 * The cross-language interop case verifies the Python-signed wear chain under the
 * robot key and reproduces the attenuated scope pinned in the shared interop
 * vector: the TypeScript module reproduces byte for byte what the Python module
 * produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  attenuates,
  buildWearAttestation,
  verifyWearAttestation,
  verifyWearChain,
  attenuateForWear,
  RoboticsError,
  WEAR_ATTESTATION_TYPE,
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

async function newRobot(did = 'did:web:robot-a.example.com') {
  const keys = await generateIdentity('robot-a.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, pub, did };
}

const T0 = new Date('2026-01-01T00:00:00Z');
const T1 = new Date('2026-06-01T00:00:00Z');

const SCOPE: Record<string, unknown> = {
  maxForceN: 80.0,
  maxSpeedMps: 1.5,
  maxSpeedNearHumansMps: 0.25,
  allowedZones: ['cell-3'],
  shiftWindows: [{ start: '08:00', end: '18:00' }],
};

describe('wear attestation (cross-language interop)', () => {
  it('verifies the Python-signed wear chain under the robot key', () => {
    const robotKey = publicKeyFromJwk(VECTOR.robot_public_key_jwk);
    const res = verifyWearChain(VECTOR.wear_chain, robotKey);
    expect(res.ok).toBe(true);
    expect(res.latest?.wearLevel).toBe(0.3);
  });

  it('reproduces the pinned attenuated scope', () => {
    const narrowed = attenuateForWear(VECTOR.wear_input_scope, VECTOR.wear_attenuation_level);
    expect(narrowed).toEqual(VECTOR.expected_attenuated_scope);
  });
});

describe('wear attestation round-trip', () => {
  async function attest(
    robot: { signer: Signer; did: string },
    level = 0.2,
    prev?: string
  ) {
    return buildWearAttestation(robot.signer, {
      robotDid: robot.did,
      wearLevel: level,
      metrics: { actuatorWear: level, cycleCount: 120000 },
      prevProof: prev,
      attestedAt: T0,
    });
  }

  it('verifies and carries the wear level and metrics', async () => {
    const robot = await newRobot();
    const att = await attest(robot, 0.2);
    expect(att.type as string[]).toContain(WEAR_ATTESTATION_TYPE);
    const res = verifyWearAttestation(att, robot.pub);
    expect(res.ok).toBe(true);
    expect(res.subject?.wearLevel).toBe(0.2);
    expect((res.subject?.metrics as Record<string, unknown>).cycleCount).toBe(120000);
  });

  it('rejects the wrong key', async () => {
    const robot = await newRobot();
    const other = await newRobot();
    const att = await attest(robot);
    const res = verifyWearAttestation(att, other.pub);
    expect(res.ok).toBe(false);
  });

  it('rejects an out-of-range wear level at build time', async () => {
    const robot = await newRobot();
    await expect(attest(robot, 1.5)).rejects.toThrow(RoboticsError);
  });

  it('rejects a tampered wear level', async () => {
    const robot = await newRobot();
    const att = await attest(robot, 0.2);
    (att.credentialSubject as Record<string, unknown>).wearLevel = 0.9;
    const res = verifyWearAttestation(att, robot.pub);
    expect(res.ok).toBe(false);
  });
});

describe('wear chain', () => {
  it('links attestations by proof value', async () => {
    const robot = await newRobot();
    const a = await buildWearAttestation(robot.signer, {
      robotDid: robot.did,
      wearLevel: 0.1,
      attestedAt: T0,
    });
    const b = await buildWearAttestation(robot.signer, {
      robotDid: robot.did,
      wearLevel: 0.3,
      prevProof: (a.proof as Record<string, unknown>).proofValue as string,
      attestedAt: T1,
    });
    const res = verifyWearChain([a, b], robot.pub);
    expect(res.ok).toBe(true);
    expect(res.latest?.wearLevel).toBe(0.3);
  });

  it('rejects a broken link', async () => {
    const robot = await newRobot();
    const a = await buildWearAttestation(robot.signer, {
      robotDid: robot.did,
      wearLevel: 0.1,
      attestedAt: T0,
    });
    const b = await buildWearAttestation(robot.signer, {
      robotDid: robot.did,
      wearLevel: 0.3,
      prevProof: 'uWRONG',
      attestedAt: T1,
    });
    const res = verifyWearChain([a, b], robot.pub);
    expect(res.ok).toBe(false);
  });
});

describe('auto-attenuation for wear', () => {
  it('narrows caps and stays a valid attenuation', () => {
    const narrowed = attenuateForWear(SCOPE, 0.25);
    expect(narrowed.maxForceN).toBe(60.0);
    expect(narrowed.maxSpeedMps).toBe(1.125);
    expect(narrowed.maxSpeedNearHumansMps).toBe(0.1875);
    expect(narrowed.allowedZones).toEqual(['cell-3']);
    expect(attenuates(SCOPE, narrowed)).toBe(true);
  });

  it('is identity on caps at zero wear', () => {
    const narrowed = attenuateForWear(SCOPE, 0.0);
    expect(narrowed.maxForceN).toBe(80.0);
    expect(attenuates(SCOPE, narrowed)).toBe(true);
  });

  it('still attenuates at full wear', () => {
    const narrowed = attenuateForWear(SCOPE, 1.0);
    expect(narrowed.maxForceN).toBe(0.0);
    expect(attenuates(SCOPE, narrowed)).toBe(true);
  });

  it('rejects an out-of-range wear level', () => {
    expect(() => attenuateForWear(SCOPE, 1.5)).toThrow(RoboticsError);
  });
});
