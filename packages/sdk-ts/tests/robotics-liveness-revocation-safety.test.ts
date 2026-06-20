/**
 * Liveness, revocation, and safety-record tests (TypeScript).
 *
 * Mirrors the Python robotics modules and the shared interop vector. The
 * cross-language tests reconstruct the exact inputs from
 * test-vectors/robotics/generate.py and assert the motion digest, the
 * hash-linked safety ledger plus its head and summary, and the credentialStatus
 * entry deep-equal the pinned fields in vector.json. The remaining tests cover
 * build and verify round-trips and tamper rejection.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  MotionCollector,
  buildRobotHeartbeat,
  verifyRobotHeartbeat,
  isLive,
  validateMotionDigest,
  ROBOT_HEARTBEAT_TYPE,
  SafetyEventLog,
  verifySafetyLog,
  summarizeEntries,
  buildSafetyRecord,
  verifySafetyRecord,
  SAFETY_RECORD_TYPE,
  attachCredentialStatus,
  checkCredentialStatus,
  buildRoboticsStatusListEntry,
  StatusList,
  buildStatusListCredential,
  RoboticsError,
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

async function newRobot(did = 'did:web:robot.example.com') {
  const keys = await generateIdentity('robot.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const robotPub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, robotPub };
}

// ---------------------------------------------------------------------------
// Cross-language interop: reproduce generate.py inputs, match vector.json.
// ---------------------------------------------------------------------------

describe('robotics interop vector (cross-language)', () => {
  it('reproduces the motion digest byte-for-byte', () => {
    const collector = new MotionCollector(VECTOR.physical_scope);
    collector.record({ forceN: 12.0, speedMps: 0.4, nearHumans: false, zone: 'cell-3' });
    collector.record({ forceN: 20.0, speedMps: 0.2, nearHumans: true, zone: 'cell-3' });
    expect(collector.digest()).toEqual(VECTOR.expected_motion_digest);
  });

  it('reproduces the hash-linked safety ledger, head, and summary', () => {
    const log = new SafetyEventLog();
    log.append('near_miss', {
      severity: 'low',
      details: { zone: 'cell-3' },
      timestamp: '2026-01-01T00:00:00Z',
    });
    log.append('envelope_breach', { severity: 'high', timestamp: '2026-01-01T00:01:00Z' });

    expect(log.entries()).toEqual(VECTOR.safety_log_entries);
    expect(log.head()).toEqual(VECTOR.expected_safety_log_head);
    expect(log.summarize()).toEqual(VECTOR.expected_safety_summary);
    expect(verifySafetyLog(log.entries()).ok).toBe(true);
  });

  it('reproduces the credentialStatus entry', () => {
    const entry = buildRoboticsStatusListEntry({
      statusListCredential: 'https://fleet.example.com/status/1',
      statusListIndex: 42,
    });
    expect(entry).toEqual(VECTOR.expected_credential_status_entry);
  });
});

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

describe('robot liveness', () => {
  it('builds and verifies a heartbeat round-trip', async () => {
    const { signer, robotPub } = await newRobot();
    const collector = new MotionCollector(VECTOR.physical_scope);
    collector.record({ forceN: 12.0, speedMps: 0.4, zone: 'cell-3' });
    const cred = await buildRobotHeartbeat(signer, {
      sessionId: 'sess-1',
      intervalIndex: 0,
      motionDigest: collector.digest(),
      intervalSeconds: 30,
    });
    expect(cred.type as string[]).toContain(ROBOT_HEARTBEAT_TYPE);
    const res = verifyRobotHeartbeat(cred, robotPub);
    expect(res.ok).toBe(true);
    expect((res.subject as Record<string, unknown>).sessionId).toBe('sess-1');
  });

  it('rejects a tampered heartbeat', async () => {
    const { signer, robotPub } = await newRobot();
    const collector = new MotionCollector(VECTOR.physical_scope);
    collector.record({ forceN: 12.0, speedMps: 0.4, zone: 'cell-3' });
    const cred = (await buildRobotHeartbeat(signer, {
      sessionId: 'sess-1',
      intervalIndex: 0,
      motionDigest: collector.digest(),
      intervalSeconds: 30,
    })) as Record<string, any>;
    cred.credentialSubject.sessionId = 'tampered';
    expect(verifyRobotHeartbeat(cred, robotPub).ok).toBe(false);
  });

  it('counts breaches against the physical scope', () => {
    const collector = new MotionCollector(VECTOR.physical_scope);
    // Over the near-humans speed cap and outside the allowed zone.
    collector.record({ speedMps: 1.0, nearHumans: true, zone: 'cell-9' });
    const digest = collector.digest();
    expect(digest.withinEnvelope).toBe(false);
    expect(digest.breachCount).toBe(1);
    expect(digest.zoneBreaches).toBe(1);
  });

  it('is live only when fresh AND in-envelope', async () => {
    const { signer } = await newRobot();
    const issued = new Date('2026-01-01T00:00:00Z');
    const collector = new MotionCollector(VECTOR.physical_scope);
    collector.record({ forceN: 12.0, speedMps: 0.4, zone: 'cell-3' });
    const cred = await buildRobotHeartbeat(signer, {
      sessionId: 'sess-1',
      intervalIndex: 0,
      motionDigest: collector.digest(),
      intervalSeconds: 30,
      issuedAt: issued,
    });

    // Fresh: within grace window.
    expect(isLive(cred, { now: new Date('2026-01-01T00:00:30Z') })).toBe(true);
    // Stale: beyond grace * cadence.
    expect(isLive(cred, { now: new Date('2026-01-01T00:05:00Z') })).toBe(false);

    // Out of envelope: never live even if fresh.
    const breached = new MotionCollector(VECTOR.physical_scope);
    breached.record({ speedMps: 5.0, nearHumans: true, zone: 'cell-9' });
    const credBad = await buildRobotHeartbeat(signer, {
      sessionId: 'sess-1',
      intervalIndex: 1,
      motionDigest: breached.digest(),
      intervalSeconds: 30,
      issuedAt: issued,
    });
    expect(isLive(credBad, { now: new Date('2026-01-01T00:00:30Z') })).toBe(false);
  });

  it('validateMotionDigest rejects malformed input', () => {
    expect(() => validateMotionDigest({} as Record<string, unknown>)).toThrow(RoboticsError);
    expect(() =>
      validateMotionDigest({
        samples: -1,
        maxForceN: 0,
        maxSpeedMps: 0,
        maxSpeedNearHumansMps: 0,
        zoneBreaches: 0,
        breachCount: 0,
        withinEnvelope: true,
      })
    ).toThrow(RoboticsError);
  });
});

// ---------------------------------------------------------------------------
// Safety record
// ---------------------------------------------------------------------------

describe('robot safety record', () => {
  it('builds and verifies a safety-record credential round-trip', async () => {
    const { signer, robotPub } = await newRobot();
    const log = new SafetyEventLog();
    log.append('incident', { severity: 'high', timestamp: '2026-01-01T00:00:00Z' });
    const cred = await buildSafetyRecord(signer, {
      robotDid: 'did:web:robot.example.com',
      summary: log.summarize(),
    });
    expect(cred.type as string[]).toContain(SAFETY_RECORD_TYPE);
    expect(verifySafetyRecord(cred, robotPub).ok).toBe(true);
  });

  it('rejects a tampered safety-record credential', async () => {
    const { signer, robotPub } = await newRobot();
    const log = new SafetyEventLog();
    log.append('incident', { severity: 'high', timestamp: '2026-01-01T00:00:00Z' });
    const cred = (await buildSafetyRecord(signer, {
      robotDid: 'did:web:robot.example.com',
      summary: log.summarize(),
    })) as Record<string, any>;
    cred.credentialSubject.totalEvents = 99;
    expect(verifySafetyRecord(cred, robotPub).ok).toBe(false);
  });

  it('detects ledger tampering via the hash chain', () => {
    const log = new SafetyEventLog();
    log.append('near_miss', { severity: 'low', timestamp: '2026-01-01T00:00:00Z' });
    log.append('incident', { severity: 'critical', timestamp: '2026-01-01T00:01:00Z' });
    const entries = log.entries();
    expect(verifySafetyLog(entries).ok).toBe(true);
    (entries[1] as Record<string, unknown>).severity = 'low';
    expect(verifySafetyLog(entries).ok).toBe(false);
  });

  it('summarizeEntries keys events sorted and severities in band order', () => {
    const summary = summarizeEntries([]);
    expect(Object.keys(summary.eventCounts)).toEqual([
      'envelope_breach',
      'incident',
      'kill_switch',
      'maintenance',
      'manual_override',
      'near_miss',
    ]);
    expect(Object.keys(summary.severityCounts)).toEqual([
      'info',
      'low',
      'medium',
      'high',
      'critical',
    ]);
    expect(summary.totalEvents).toBe(0);
  });

  it('rejects an unknown event type or severity', () => {
    const log = new SafetyEventLog();
    expect(() => log.append('explosion')).toThrow(RoboticsError);
    expect(() => log.append('incident', { severity: 'catastrophic' as never })).toThrow(
      RoboticsError
    );
  });
});

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

describe('robot credential revocation', () => {
  it('attaches a credentialStatus entry and re-signs', async () => {
    const { signer, robotPub } = await newRobot();
    const collector = new MotionCollector(VECTOR.physical_scope);
    collector.record({ forceN: 12.0, speedMps: 0.4, zone: 'cell-3' });
    const cred = await buildRobotHeartbeat(signer, {
      sessionId: 'sess-1',
      intervalIndex: 0,
      motionDigest: collector.digest(),
      intervalSeconds: 30,
    });

    const withStatus = await attachCredentialStatus(cred, signer, {
      statusListCredential: 'https://fleet.example.com/status/1',
      statusListIndex: 7,
    });
    // The new proof covers the status binding, so it still verifies.
    expect(verifyRobotHeartbeat(withStatus, robotPub).ok).toBe(true);
    const status = withStatus.credentialStatus as Record<string, unknown>;
    expect(status.statusListIndex).toBe('7');
  });

  it('checks the credential status bit against a status list', async () => {
    const { signer } = await newRobot();
    const collector = new MotionCollector(VECTOR.physical_scope);
    collector.record({ forceN: 12.0, speedMps: 0.4, zone: 'cell-3' });
    const cred = await buildRobotHeartbeat(signer, {
      sessionId: 'sess-1',
      intervalIndex: 0,
      motionDigest: collector.digest(),
      intervalSeconds: 30,
    });

    const listId = 'https://fleet.example.com/status/1';
    const withStatus = await attachCredentialStatus(cred, signer, {
      statusListCredential: listId,
      statusListIndex: 7,
    });

    // Not revoked yet.
    const list = new StatusList({ statusListId: listId });
    let slc = buildStatusListCredential({ issuerDid: signer.getDid(), statusList: list });
    expect(checkCredentialStatus(withStatus, slc as unknown as Record<string, unknown>)).toBe(false);

    // Revoke index 7 and re-publish.
    list.revoke(7);
    slc = buildStatusListCredential({ issuerDid: signer.getDid(), statusList: list });
    expect(checkCredentialStatus(withStatus, slc as unknown as Record<string, unknown>)).toBe(true);
  });
});
