/**
 * Perception-provenance tests (TypeScript).
 *
 * Mirrors `vouch/robotics/perception.py` and the shared interop vector. The
 * cross-language test reconstructs the exact inputs from
 * test-vectors/robotics/generate.py and asserts the frame hash, the hash-linked
 * perception log, and its head deep-equal the pinned fields in vector.json. The
 * remaining tests cover build and verify round-trips, wrong-frame rejection,
 * and tamper rejection.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  PerceptionLog,
  hashFrame,
  verifyPerceptionLog,
  buildPerceptionAttestation,
  verifyPerceptionAttestation,
  PERCEPTION_TYPE,
  RoboticsError,
} from '../src';

const VECTOR = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../../../test-vectors/robotics/vector.json'), 'utf8')
);

function publicKeyFromJwk(jwk: unknown): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
}

async function newRobot(did = 'did:web:robot.example.com') {
  const keys = await generateIdentity('robot.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const robotPub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, robotPub };
}

// generate.py inputs: sample_frame = bytes(range(64)).
const SAMPLE_FRAME = Uint8Array.from(Array.from({ length: 64 }, (_, i) => i));

// ---------------------------------------------------------------------------
// Cross-language interop: reproduce generate.py inputs, match vector.json.
// ---------------------------------------------------------------------------

describe('perception interop vector (cross-language)', () => {
  it('reproduces the frame hash byte-for-byte', () => {
    expect(hashFrame(SAMPLE_FRAME)).toEqual(VECTOR.expected_frame_hash);
  });

  it('reproduces the hash-linked perception log and head', () => {
    const plog = new PerceptionLog();
    plog.record({
      sensorId: 'cam-front',
      modality: 'camera',
      frame: SAMPLE_FRAME,
      timestamp: '2026-01-01T00:00:00Z',
    });
    plog.record({
      sensorId: 'lidar-top',
      modality: 'lidar',
      frameHash: hashFrame(Buffer.from('scan-0')),
      timestamp: '2026-01-01T00:00:01Z',
    });

    expect(plog.entries()).toEqual(VECTOR.perception_log_entries);
    expect(plog.head()).toEqual(VECTOR.expected_perception_log_head);
    expect(verifyPerceptionLog(plog.entries()).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Perception attestation
// ---------------------------------------------------------------------------

describe('robot perception attestation', () => {
  it('builds and verifies an attestation round-trip', async () => {
    const { signer, robotPub } = await newRobot();
    const frameHash = hashFrame(SAMPLE_FRAME);
    const cred = await buildPerceptionAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      sensorId: 'cam-front',
      modality: 'camera',
      frameHash,
    });
    expect(cred.type as string[]).toContain(PERCEPTION_TYPE);
    const res = verifyPerceptionAttestation(cred, robotPub);
    expect(res.ok).toBe(true);
    expect((res.subject as Record<string, unknown>).frameHash).toBe(frameHash);
  });

  it('verifies when the supplied frame reproduces the attested hash', async () => {
    const { signer, robotPub } = await newRobot();
    const cred = await buildPerceptionAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      sensorId: 'cam-front',
      modality: 'camera',
      frameHash: hashFrame(SAMPLE_FRAME),
    });
    expect(verifyPerceptionAttestation(cred, robotPub, { frame: SAMPLE_FRAME }).ok).toBe(true);
  });

  it('rejects a wrong frame', async () => {
    const { signer, robotPub } = await newRobot();
    const cred = await buildPerceptionAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      sensorId: 'cam-front',
      modality: 'camera',
      frameHash: hashFrame(SAMPLE_FRAME),
    });
    const wrongFrame = Uint8Array.from(Array.from({ length: 64 }, (_, i) => i + 1));
    expect(verifyPerceptionAttestation(cred, robotPub, { frame: wrongFrame }).ok).toBe(false);
  });

  it('rejects a tampered attestation', async () => {
    const { signer, robotPub } = await newRobot();
    const cred = (await buildPerceptionAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      sensorId: 'cam-front',
      modality: 'camera',
      frameHash: hashFrame(SAMPLE_FRAME),
    })) as Record<string, any>;
    cred.credentialSubject.frameHash = hashFrame(Buffer.from('other'));
    expect(verifyPerceptionAttestation(cred, robotPub).ok).toBe(false);
  });

  it('anchors a log segment via logHead when supplied', async () => {
    const { signer, robotPub } = await newRobot();
    const plog = new PerceptionLog();
    plog.record({ sensorId: 'cam-front', modality: 'camera', frame: SAMPLE_FRAME });
    const cred = await buildPerceptionAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      sensorId: 'cam-front',
      modality: 'camera',
      frameHash: hashFrame(SAMPLE_FRAME),
      logHead: plog.head(),
    });
    const res = verifyPerceptionAttestation(cred, robotPub);
    expect(res.ok).toBe(true);
    expect((res.subject as Record<string, unknown>).logHead).toBe(plog.head());
  });
});

// ---------------------------------------------------------------------------
// Perception log
// ---------------------------------------------------------------------------

describe('robot perception log', () => {
  it('detects log tampering via the hash chain', () => {
    const plog = new PerceptionLog();
    plog.record({ sensorId: 'cam-front', modality: 'camera', frame: SAMPLE_FRAME });
    plog.record({ sensorId: 'lidar-top', modality: 'lidar', frameHash: hashFrame(Buffer.from('s')) });
    const entries = plog.entries();
    expect(verifyPerceptionLog(entries).ok).toBe(true);
    (entries[1] as Record<string, unknown>).sensorId = 'spoofed';
    expect(verifyPerceptionLog(entries).ok).toBe(false);
  });

  it('rejects an unknown modality', () => {
    const plog = new PerceptionLog();
    expect(() => plog.record({ sensorId: 'x', modality: 'sonar', frame: SAMPLE_FRAME })).toThrow(
      RoboticsError
    );
  });

  it('rejects providing both frame and frameHash', () => {
    const plog = new PerceptionLog();
    expect(() =>
      plog.record({
        sensorId: 'x',
        modality: 'camera',
        frame: SAMPLE_FRAME,
        frameHash: hashFrame(SAMPLE_FRAME),
      })
    ).toThrow(RoboticsError);
  });

  it('rejects a record with neither frame nor frameHash', () => {
    const plog = new PerceptionLog();
    expect(() => plog.record({ sensorId: 'x', modality: 'camera' })).toThrow(RoboticsError);
  });
});
