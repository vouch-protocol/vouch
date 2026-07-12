/**
 * Adversarial tests for the Halos safety-evidence recorder (TypeScript).
 *
 * Mirrors the Python tests/test_halos_evidence.py suite: a robot records the
 * Halos safety-event stream into the tamper-evident black-box, seals the chain
 * head and entry count into a signed HalosSafetyEvidenceCredential, and a
 * verifier confirms the record is unaltered, untruncated, unextended, and
 * attributable to that robot, all without the black-box key.
 *
 * The cross-language case loads a credential, black-box entries, and robot
 * public key produced by the Python reference from a fixed Ed25519 seed and a
 * fixed proof timestamp, and confirms the TypeScript verifier accepts it and
 * rejects a tampered entry.
 */

import * as crypto from 'crypto';

import {
  Signer,
  generateIdentity,
  HALOS_SAFETY_EVIDENCE_TYPE,
  HalosError,
  SafetyEventRecorder,
  buildSafetyEvidence,
  verifySafetyEvidence,
} from '../src';

const KEY = new Uint8Array(32).fill(9);
const HALOS_STACK = {
  igxSom: 'IGX-Thor-SoM',
  halosCore: 'Halos Core Linux 1.0',
  blueprint: ['SAIM', 'SEI', 'SDM'],
};
const WINDOW = { from: '2026-07-12T00:00:00Z', to: '2026-07-12T01:00:00Z' };

function publicKeyFromJwk(jwk: unknown): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
}

async function robotParty() {
  const keys = await generateIdentity('robot.example.com');
  const did = 'did:web:robot.example.com';
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, pub, did };
}

async function scenario() {
  const robot = await robotParty();
  const rec = new SafetyEventRecorder(KEY);
  rec.record('SAIM', 'camera_blockage_cleared', { cam: 2 });
  rec.record('SEI', 'multi_camera_fused', { objects: 3 });
  rec.record('SDM', 'slow_stop', { reason: 'out_of_distribution' });
  rec.record('estop', 'emergency_stop', { by: 'operator-7' });
  const evidence = await buildSafetyEvidence(robot.signer, {
    halosStack: HALOS_STACK,
    window: WINDOW,
    recorder: rec,
    robotIdentity: 'urn:uuid:robot-id',
  });
  return { robot, rec, evidence };
}

describe('Halos safety evidence', () => {
  it('seals and verifies (happy path)', async () => {
    const s = await scenario();
    const { ok, subject } = verifySafetyEvidence(s.evidence, s.robot.pub, {
      entries: s.rec.entries(),
    });
    expect(ok).toBe(true);
    expect(subject?.id).toBe(s.robot.did);
    expect(subject?.entryCount).toBe(4);
    expect(subject?.blackboxHead).toBe(s.rec.head());
    expect((subject?.halosStack as { blueprint: string[] }).blueprint).toEqual([
      'SAIM',
      'SEI',
      'SDM',
    ]);
    expect(subject?.robotIdentity).toBe('urn:uuid:robot-id');
    expect(s.evidence.type as string[]).toContain(HALOS_SAFETY_EVIDENCE_TYPE);
  });

  it('verifies on the signature-only path without entries', async () => {
    const s = await scenario();
    const { ok, subject } = verifySafetyEvidence(s.evidence, s.robot.pub);
    expect(ok).toBe(true);
    expect(subject?.entryCount).toBe(4);
  });

  it('rejects an unknown event source', () => {
    const rec = new SafetyEventRecorder(KEY);
    expect(() => rec.record('bogus', 'whatever', {})).toThrow(HalosError);
  });

  it('rejects a tampered entry', async () => {
    const s = await scenario();
    const entries = s.rec.entries();
    entries[1].event = 'forged_event';
    expect(verifySafetyEvidence(s.evidence, s.robot.pub, { entries }).ok).toBe(false);
  });

  it('rejects a truncated record', async () => {
    const s = await scenario();
    const entries = s.rec.entries().slice(0, -1);
    expect(verifySafetyEvidence(s.evidence, s.robot.pub, { entries }).ok).toBe(false);
  });

  it('rejects a record appended after the seal', async () => {
    const s = await scenario();
    // Seal, then keep recording: the presented log no longer matches the seal.
    s.rec.record('operator', 'resume', { by: 'operator-7' });
    expect(
      verifySafetyEvidence(s.evidence, s.robot.pub, { entries: s.rec.entries() }).ok
    ).toBe(false);
  });

  it('rejects reordered entries', async () => {
    const s = await scenario();
    const entries = s.rec.entries();
    const tmp = entries[0];
    entries[0] = entries[2];
    entries[2] = tmp;
    expect(verifySafetyEvidence(s.evidence, s.robot.pub, { entries }).ok).toBe(false);
  });

  it('rejects the wrong robot key', async () => {
    const s = await scenario();
    const other = await robotParty();
    expect(
      verifySafetyEvidence(s.evidence, other.pub, { entries: s.rec.entries() }).ok
    ).toBe(false);
  });

  it('rejects forged evidence not attributable to the robot', async () => {
    // An attacker seals the robot's real head under its own key. Verifying with
    // the robot's key fails, so the evidence cannot be attributed to the robot.
    const s = await scenario();
    const attacker = await robotParty();
    const forged = await buildSafetyEvidence(attacker.signer, {
      halosStack: HALOS_STACK,
      window: WINDOW,
      blackboxHead: s.rec.head(),
      entryCount: s.rec.count(),
    });
    expect(
      verifySafetyEvidence(forged, s.robot.pub, { entries: s.rec.entries() }).ok
    ).toBe(false);
  });

  it('rejects a sealed head that does not match the entries', async () => {
    const s = await scenario();
    const bad = await buildSafetyEvidence(s.robot.signer, {
      halosStack: HALOS_STACK,
      window: WINDOW,
      blackboxHead: 'uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      entryCount: s.rec.count(),
    });
    expect(
      verifySafetyEvidence(bad, s.robot.pub, { entries: s.rec.entries() }).ok
    ).toBe(false);
  });

  it('rejects a missing stack or window at build time', async () => {
    const robot = await robotParty();
    await expect(
      buildSafetyEvidence(robot.signer, {
        halosStack: {},
        window: WINDOW,
        blackboxHead: 'u',
        entryCount: 0,
      })
    ).rejects.toThrow(HalosError);
    await expect(
      buildSafetyEvidence(robot.signer, {
        halosStack: HALOS_STACK,
        window: {} as { from: string; to: string },
        blackboxHead: 'u',
        entryCount: 0,
      })
    ).rejects.toThrow(HalosError);
  });

  it('keeps payloads confidential while the chain stays public', async () => {
    // The chain verifies from the encrypted entries without the key, while the
    // payloads open only with the black-box key.
    const s = await scenario();
    const entries = s.rec.entries();
    expect(JSON.stringify(entries)).not.toContain('operator-7'); // payload is encrypted
    const opened = s.rec.openEntry(entries[3]);
    expect(opened.source).toBe('estop');
    expect((opened.detail as { by: string }).by).toBe('operator-7');
  });
});

// A credential, black-box entries, and robot public key produced by the Python
// reference (vouch/robotics/halos.py) from a fixed Ed25519 seed (bytes 0..31)
// and a fixed proof timestamp. The TypeScript verifier reproduces the Python
// verifier's decision byte for byte.
const PY_VECTOR = {
  robot_public_key_jwk: {
    crv: 'Ed25519',
    kty: 'OKP',
    x: 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  },
  credential: {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://vouch-protocol.com/contexts/v1',
    ],
    credentialSubject: {
      blackboxHead: 'urYXkiOGIdmxj57LWsU_9Zv_D694V18SCdkEfEq_NO2A',
      entryCount: 4,
      halosStack: {
        blueprint: ['SAIM', 'SEI', 'SDM'],
        halosCore: 'Halos Core Linux 1.0',
        igxSom: 'IGX-Thor-SoM',
      },
      id: 'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd',
      robotIdentity: 'urn:uuid:robot-id',
      window: { from: '2026-07-12T00:00:00Z', to: '2026-07-12T01:00:00Z' },
    },
    issuer: 'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd',
    proof: {
      created: '2026-07-12T00:00:00Z',
      cryptosuite: 'eddsa-jcs-2022',
      proofPurpose: 'assertionMethod',
      proofValue:
        'zfDfsG4FnFFmtrC1SvmT1AJznggTXKhqrHuHv57nHDNEb34HEN73nJNLxntHV27JMtMwuin5QfEgdVwM7XYCzE4C',
      type: 'DataIntegrityProof',
      verificationMethod:
        'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd#key-1',
    },
    type: ['VerifiableCredential', 'HalosSafetyEvidenceCredential'],
    validFrom: '2026-07-12T05:40:47Z',
  },
  entries: [
    {
      ciphertext:
        'ugIc9Kox7w0ywai3RIUSeKxwRKSONEZg2nfyf4z2ozayOXVa8GDfgWvxjwEFxU2iu4TiH5PgaZsms5jqTZezgEQ',
      entryHash: 'u4ggbbwZRrSzKbWY-BI5npkqc-_tU75fueRjCR5S28Q8',
      event: 'camera_blockage_cleared',
      prevHash: 'uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      seq: 0,
      timestamp: '2026-07-12T00:10:00Z',
      version: '1.0',
    },
    {
      ciphertext:
        'ui8ENxqwT-h6hGT96Fi13l0YEcf6vKaJnHwaedWwfu2jhjefp1V0SjHSXLQqxCMDYu80B2nlWFFxHAV-torzX2R-LXQ',
      entryHash: 'uwIOJ3t8Kl5JETt4pj0onfFE0PupYFbhAO5KOyiVGl_M',
      event: 'multi_camera_fused',
      prevHash: 'u4ggbbwZRrSzKbWY-BI5npkqc-_tU75fueRjCR5S28Q8',
      seq: 1,
      timestamp: '2026-07-12T00:20:00Z',
      version: '1.0',
    },
    {
      ciphertext:
        'uS6bJimEWxw0MGltkiicoZ0_-yEeBa_8256fIOg7WtndgMTWx4jV8o2O1MIrVRrhyeUxKtHMy3DgN6I5pr-3f4Kg77ep5Tssec0uBRYuTPXagfOry0Ik',
      entryHash: 'uTLIUUCFFAWYSmX9785rlAtQ23tTc80JX-UHcA-v-IzY',
      event: 'slow_stop',
      prevHash: 'uwIOJ3t8Kl5JETt4pj0onfFE0PupYFbhAO5KOyiVGl_M',
      seq: 2,
      timestamp: '2026-07-12T00:30:00Z',
      version: '1.0',
    },
    {
      ciphertext:
        'uPdmT-fJj869X4ahq4eLRUcYP-CwovN0j0gDmQRtO8VwTI-ZNiV3_rt424NpyLFj46XrLUzJabp23HGf0e1tTph260TqIO5YR4IJm',
      entryHash: 'urYXkiOGIdmxj57LWsU_9Zv_D694V18SCdkEfEq_NO2A',
      event: 'emergency_stop',
      prevHash: 'uTLIUUCFFAWYSmX9785rlAtQ23tTc80JX-UHcA-v-IzY',
      seq: 3,
      timestamp: '2026-07-12T00:40:00Z',
      version: '1.0',
    },
  ],
};

describe('Halos safety evidence (cross-language interop)', () => {
  it('verifies a Python-produced credential with its entries', () => {
    const robotKey = publicKeyFromJwk(PY_VECTOR.robot_public_key_jwk);
    const { ok, subject } = verifySafetyEvidence(PY_VECTOR.credential, robotKey, {
      entries: PY_VECTOR.entries.map((e) => ({ ...e })),
    });
    expect(ok).toBe(true);
    expect(subject?.entryCount).toBe(4);
    expect(subject?.blackboxHead).toBe(
      PY_VECTOR.entries[PY_VECTOR.entries.length - 1].entryHash
    );
  });

  it('rejects a Python-produced credential when an entry is tampered', () => {
    const robotKey = publicKeyFromJwk(PY_VECTOR.robot_public_key_jwk);
    const entries = PY_VECTOR.entries.map((e) => ({ ...e }));
    entries[2].event = 'tampered_event';
    expect(verifySafetyEvidence(PY_VECTOR.credential, robotKey, { entries }).ok).toBe(
      false
    );
  });
});
