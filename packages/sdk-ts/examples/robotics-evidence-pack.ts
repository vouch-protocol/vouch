/**
 * Regulatory evidence pack for a robot, assembled from Vouch robotics
 * credentials (TypeScript). Mirrors examples/robotics_ai_act_evidence_pack.py.
 *
 * A robot presents signed credentials -- a hardware-rooted identity, a model
 * provenance attestation, a physical capability scope, a safety record
 * anchored to a tamper-evident ledger, a heartbeat carrying a motion digest,
 * and perception provenance for its sensor frames -- and the conformance
 * checker maps them onto all five built-in regulatory profiles (EU AI Act
 * high-risk, ISO 10218, ISO/TS 15066, EU Machinery Regulation 2023/1230,
 * UL 3300). An assessor then signs one point-in-time conformance attestation
 * per profile that an auditor or notified body can verify offline.
 *
 * Run it:  npx tsx examples/robotics-evidence-pack.ts   (from packages/sdk-ts)
 */

import * as crypto from 'crypto';

import {
  MotionCollector,
  PerceptionLog,
  SafetyEventLog,
  Signer,
  SoftwareRootOfTrust,
  buildConformanceAttestation,
  buildPerceptionAttestation,
  buildPhysicalScopeCredential,
  buildProvenanceAttestation,
  buildRobotHeartbeat,
  buildSafetyRecord,
  checkConformance,
  generateIdentity,
  hashFrame,
  mintRobotIdentity,
  verifyConformanceAttestation,
  type ConformanceReport,
} from '../src';

export const ALL_PROFILE_IDS = [
  'eu-ai-act-high-risk',
  'iso-10218',
  'iso-ts-15066',
  'eu-machinery-2023-1230',
  'ul-3300',
];

export const ROBOT_CONFIG = { temperature: 0.0, max_torque: 12.5 };

export interface Party {
  signer: Signer;
  did: string;
  pub: crypto.KeyObject;
}

/** Generate an identity for one party and wrap it in a Signer. */
export async function makeParty(domain: string): Promise<Party> {
  const keys = await generateIdentity(domain);
  const did = keys.did as string;
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = crypto.createPublicKey({
    key: JSON.parse(keys.publicKeyJwk) as crypto.JsonWebKey,
    format: 'jwk',
  });
  return { signer, did, pub };
}

/** Multibase (base64url) SHA-256, the hash form Vouch credentials carry. */
export function digest(data: Buffer | string): string {
  return 'u' + crypto.createHash('sha256').update(data).digest('base64url');
}

/**
 * Build the four base credentials: identity, model provenance, physical
 * scope, and a safety record over a tamper-evident ledger. These satisfy
 * eu-ai-act-high-risk, iso-10218, and eu-machinery-2023-1230, but leave gaps
 * in iso-ts-15066 (no motion monitoring) and ul-3300 (no perception
 * integrity).
 */
export async function buildBaseCredentials(
  robot: Party,
  authority: Party
): Promise<Array<Record<string, unknown>>> {
  const root = new SoftwareRootOfTrust(undefined, 'TPM'); // reference; use a real TPM in deployment
  const identity = await mintRobotIdentity(robot.signer, root, {
    make: 'Acme Robotics',
    model: 'AR-7',
    serial: 'SN-000123',
  });

  const provenance = await buildProvenanceAttestation(robot.signer, {
    robotDid: robot.did,
    modelName: 'Gemini Robotics ER 2',
    weightsHash: digest('gemini-robotics-er-2-weights'),
    safetyPolicy: digest('factory-floor-safety-policy-v3'),
    config: ROBOT_CONFIG,
    version: '2.0',
  });

  const scope = await buildPhysicalScopeCredential(robot.signer, {
    subjectDid: robot.did,
    maxForceN: 80.0,
    maxSpeedMps: 1.5,
    maxSpeedNearHumansMps: 0.5,
    allowedZones: ['cell-3'],
  });

  const ledger = new SafetyEventLog();
  ledger.append('near_miss', { severity: 'low', details: { note: 'pallet edge proximity' } });
  ledger.append('manual_override', { severity: 'info', actor: 'did:web:operator.example.com' });
  const record = await buildSafetyRecord(authority.signer, {
    robotDid: robot.did,
    summary: ledger.summarize(),
  });

  return [identity, provenance, scope, record];
}

/**
 * Build the two credentials that close the remaining gaps: a heartbeat whose
 * motion digest proves the last interval stayed inside the physical envelope
 * (ISO/TS 15066 continuous monitoring), and perception provenance binding a
 * captured camera frame to the robot's key (UL 3300 sensing integrity).
 */
export async function buildMonitoringCredentials(
  robot: Party,
  scopeCredential: Record<string, unknown>
): Promise<Array<Record<string, unknown>>> {
  const subject = scopeCredential.credentialSubject as Record<string, unknown>;
  const collector = new MotionCollector(subject.physicalScope as Record<string, unknown>);
  collector.record({ forceN: 12.0, speedMps: 0.4, nearHumans: true, zone: 'cell-3' });
  collector.record({ forceN: 25.0, speedMps: 1.1, nearHumans: false, zone: 'cell-3' });
  const heartbeat = await buildRobotHeartbeat(robot.signer, {
    sessionId: 'shift-A',
    intervalIndex: 0,
    motionDigest: collector.digest(),
    intervalSeconds: 30,
  });

  const frame = Buffer.from('\x89frame-bytes-from-the-front-camera', 'binary');
  const log = new PerceptionLog();
  log.record({ sensorId: 'cam-front', modality: 'camera', frame });
  const perception = await buildPerceptionAttestation(robot.signer, {
    robotDid: robot.did,
    sensorId: 'cam-front',
    modality: 'camera',
    frameHash: hashFrame(frame),
    logHead: log.head(),
  });

  return [heartbeat, perception];
}

/** Build the full six-credential evidence pack covering all five profiles. */
export async function buildEvidencePack(
  robot: Party,
  authority: Party
): Promise<Array<Record<string, unknown>>> {
  const base = await buildBaseCredentials(robot, authority);
  const monitoring = await buildMonitoringCredentials(robot, base[2]);
  return [...base, ...monitoring];
}

/** Run the conformance checker over every built-in profile. */
export function checkAllProfiles(
  credentials: Array<Record<string, unknown>>
): Record<string, ConformanceReport> {
  const reports: Record<string, ConformanceReport> = {};
  for (const pid of ALL_PROFILE_IDS) {
    reports[pid] = checkConformance(credentials, pid);
  }
  return reports;
}

/** Sign one point-in-time conformance attestation per profile report. */
export async function signAttestations(
  assessor: Party,
  robotDid: string,
  reports: Record<string, ConformanceReport>
): Promise<Record<string, Record<string, unknown>>> {
  const attestations: Record<string, Record<string, unknown>> = {};
  for (const [pid, report] of Object.entries(reports)) {
    attestations[pid] = await buildConformanceAttestation(assessor.signer, {
      robotDid,
      report,
    });
  }
  return attestations;
}

function printSummary(reports: Record<string, ConformanceReport>): void {
  for (const [pid, report] of Object.entries(reports)) {
    const verdict = report.conforms ? 'CONFORMS' : 'GAPS';
    console.log(
      `  ${pid.padEnd(24)} ${verdict.padEnd(8)} ` +
        `(${report.satisfiedCount}/${report.totalCount})  ${report.regime}`
    );
    for (const req of report.requirements) {
      if (!req.satisfied) console.log(`    gap: ${req.clause}: ${req.title}`);
    }
  }
}

export async function main(): Promise<void> {
  const robot = await makeParty('ar7.example.com');
  const assessor = await makeParty('assessor.example.com');

  // The base credential set leaves gaps in two of the five profiles.
  const base = await buildBaseCredentials(robot, assessor);
  console.log('base credential set (identity, provenance, scope, safety record):');
  printSummary(checkAllProfiles(base));

  // The heartbeat and perception credentials close them.
  const credentials = [...base, ...(await buildMonitoringCredentials(robot, base[2]))];
  console.log(`\nfull evidence pack (${credentials.length} credentials):`);
  const reports = checkAllProfiles(credentials);
  printSummary(reports);

  // One signed, offline-verifiable conformance attestation per profile.
  console.log(`\nsigned attestations (${ALL_PROFILE_IDS.length} profiles):`);
  const attestations = await signAttestations(assessor, robot.did, reports);
  for (const [pid, attestation] of Object.entries(attestations)) {
    const res = verifyConformanceAttestation(attestation, assessor.pub);
    const reportDigest = (res.subject?.reportDigest as string) ?? '';
    console.log(`  ${pid.padEnd(24)} verifies=${res.ok}  reportDigest=${reportDigest.slice(0, 16)}...`);
  }
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
