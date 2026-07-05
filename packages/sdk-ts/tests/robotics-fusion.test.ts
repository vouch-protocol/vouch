/**
 * Fused-sensor provenance tests (TypeScript). Mirrors the Python fusion.py
 * module: a signed attestation binding a fused output to its input frame hashes
 * and a fusion method, with a deterministic digest over the ordered inputs.
 *
 * The cross-language interop case reproduces the input digest and the fused
 * output hash pinned in the shared interop vector and verifies the Python-signed
 * attestation under the robot key: the TypeScript module reproduces byte for byte
 * what the Python module produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  buildFusedAttestation,
  fusionInputsDigest,
  hashFusedOutput,
  hashFrame,
  PerceptionLog,
  verifyFusedAttestation,
  verifyFusionInputs,
  FUSED_PERCEPTION_TYPE,
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
const FRAMES = [Buffer.from('cam-front-0'), Buffer.from('lidar-top-0'), Buffer.from('radar-0')];
const INPUT_HASHES = FRAMES.map((f) => hashFrame(f));
const FUSED_OUTPUT = Buffer.from('world-model-0');

async function attest(robot: { signer: Signer }, robotDid: string, inputs = INPUT_HASHES) {
  return buildFusedAttestation(robot.signer, {
    robotDid,
    fusionMethod: 'occupancy-grid-v1',
    inputFrameHashes: inputs,
    fusedOutput: FUSED_OUTPUT,
    capturedAt: T0,
  });
}

describe('fused-sensor provenance (cross-language interop)', () => {
  it('reproduces the pinned inputs digest byte for byte', () => {
    expect(fusionInputsDigest(VECTOR.fused_input_frame_hashes)).toBe(
      VECTOR.expected_fusion_inputs_digest
    );
  });

  it('verifies the Python-signed attestation under the robot key', () => {
    const robotKey = publicKeyFromJwk(VECTOR.robot_public_key_jwk);
    const res = verifyFusedAttestation(VECTOR.fused_perception_attestation, robotKey);
    expect(res.ok).toBe(true);
    expect(res.subject?.inputFrameHashes).toEqual(VECTOR.fused_input_frame_hashes);
    expect(res.subject?.fusedOutputHash).toBe(VECTOR.expected_fused_output_hash);
  });
});

describe('fused attestation round-trip', () => {
  it('verifies and carries the inputs', async () => {
    const robot = await newRobot();
    const att = await attest(robot, robot.did);
    expect(att.type as string[]).toContain(FUSED_PERCEPTION_TYPE);
    const res = verifyFusedAttestation(att, robot.pub);
    expect(res.ok).toBe(true);
    expect(res.subject?.fusionMethod).toBe('occupancy-grid-v1');
    expect(res.subject?.inputFrameHashes).toEqual(INPUT_HASHES);
    expect(res.subject?.fusedOutputHash).toBe(hashFusedOutput(FUSED_OUTPUT));
  });

  it('verifies with the raw fused output supplied', async () => {
    const robot = await newRobot();
    const att = await attest(robot, robot.did);
    const res = verifyFusedAttestation(att, robot.pub, { fusedOutput: FUSED_OUTPUT });
    expect(res.ok).toBe(true);
  });

  it('rejects a wrong raw fused output', async () => {
    const robot = await newRobot();
    const att = await attest(robot, robot.did);
    const res = verifyFusedAttestation(att, robot.pub, {
      fusedOutput: Buffer.from('tampered-world-model'),
    });
    expect(res.ok).toBe(false);
  });

  it('rejects the wrong key', async () => {
    const robot = await newRobot();
    const other = await newRobot();
    const att = await attest(robot, robot.did);
    const res = verifyFusedAttestation(att, other.pub);
    expect(res.ok).toBe(false);
  });

  it('rejects tampered inputs whose digest no longer matches', async () => {
    const robot = await newRobot();
    const att = await attest(robot, robot.did);
    const subject = att.credentialSubject as Record<string, unknown>;
    (subject.inputFrameHashes as string[])[0] = hashFrame(Buffer.from('substituted-frame'));
    const res = verifyFusedAttestation(att, robot.pub);
    expect(res.ok).toBe(false);
  });
});

describe('inputs digest', () => {
  it('is order-sensitive', () => {
    const forward = fusionInputsDigest(INPUT_HASHES);
    const reversed = fusionInputsDigest([...INPUT_HASHES].reverse());
    expect(forward).not.toBe(reversed);
  });

  it('throws on an empty list', () => {
    expect(() => fusionInputsDigest([])).toThrow();
  });

  it('throws on an empty element', () => {
    expect(() => fusionInputsDigest([INPUT_HASHES[0], ''])).toThrow();
  });
});

describe('fusion inputs against the perception log', () => {
  async function setup() {
    const robot = await newRobot();
    const log = new PerceptionLog();
    const modalities = ['camera', 'lidar', 'radar'];
    FRAMES.forEach((f, i) => {
      log.record({
        sensorId: `sensor-${i}`,
        modality: modalities[i],
        frame: f,
        timestamp: '2026-01-01T00:00:00Z',
      });
    });
    return { robot, log };
  }

  it('confirms every input was recorded', async () => {
    const { robot, log } = await setup();
    const att = await attest(robot, robot.did, INPUT_HASHES);
    const res = verifyFusionInputs(att, log.entries());
    expect(res.ok).toBe(true);
    expect(res.missing).toEqual([]);
  });

  it('names an unrecorded input', async () => {
    const { robot, log } = await setup();
    const phantom = hashFrame(Buffer.from('never-captured'));
    const att = await attest(robot, robot.did, [...INPUT_HASHES, phantom]);
    const res = verifyFusionInputs(att, log.entries());
    expect(res.ok).toBe(false);
    expect(res.missing).toEqual([phantom]);
  });
});
