/**
 * Regulatory conformance profiles for robots (TypeScript).
 *
 * Mirrors `vouch/robotics/conformance.py` with byte-identical output. A
 * conformance profile is a machine-checkable mapping from Vouch robotics
 * credentials to the clauses of a public safety or AI regulation. Given the
 * credentials a robot presents, the checker reports which clauses are satisfied
 * and cites each one, and an issuer can sign a point-in-time conformance
 * attestation an auditor or notified body can consume.
 *
 * The built-in profiles cover ISO 10218-1/-2 (industrial robots), ISO/TS 15066
 * (collaborative, power and force limiting), the EU Machinery Regulation
 * 2023/1230, the EU AI Act high-risk requirements, and UL 3300 (service and
 * mobile robots). They are a reference crosswalk to make conformance verifiable
 * in the open, not legal advice; a deployment confirms the mapping against the
 * current text of each regulation.
 *
 * This is the open layer: declarative profiles, a deterministic checker, and a
 * signed point-in-time attestation over the full report. Hosted continuous
 * monitoring, maintained and certified profiles, and auditor evidence portals
 * are out of scope for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import { canonicalize } from '../jcs';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const CONFORMANCE_ATTESTATION_TYPE = 'RobotConformanceAttestation';

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------
//
// A requirement is satisfied when the presented credential set contains a
// credential whose `type` includes `credential` and whose credentialSubject has
// a non-null value at every path in `fields` (dot-separated, rooted at the
// subject). Profiles are plain data so every language reproduces them
// identically.

export interface Requirement {
  id: string;
  clause: string;
  title: string;
  credential: string;
  fields: string[];
}

export interface Profile {
  regime: string;
  version: string;
  requirements: Requirement[];
}

function req(
  rid: string,
  clause: string,
  title: string,
  credential: string,
  fields?: string[]
): Requirement {
  return {
    id: rid,
    clause,
    title,
    credential,
    fields: fields ?? [],
  };
}

export const PROFILES: Record<string, Profile> = {
  'iso-10218': {
    regime: 'ISO 10218-1/-2 industrial robots',
    version: '2011',
    requirements: [
      req(
        'iso10218-identification',
        'ISO 10218-1:2011, 5.2',
        'Robot identification bound to its hardware',
        'RobotIdentityCredential',
        ['hardwareRoot.kind']
      ),
      req(
        'iso10218-software-integrity',
        'ISO 10218-1:2011, 5.3',
        'Control software and configuration integrity',
        'ModelProvenanceAttestation',
        ['vla.weightsHash']
      ),
      req(
        'iso10218-limits',
        'ISO 10218-1:2011, 5.6',
        'Limiting of speed, force, and workspace',
        'PhysicalCapabilityScope',
        ['physicalScope.maxForceN', 'physicalScope.maxSpeedMps']
      ),
      req(
        'iso10218-records',
        'ISO 10218-2:2011, 5.2',
        'Records of safety-relevant events',
        'RobotSafetyRecordCredential',
        ['totalEvents']
      ),
    ],
  },
  'iso-ts-15066': {
    regime: 'ISO/TS 15066 collaborative robots',
    version: '2016',
    requirements: [
      req(
        'iso15066-power-force-limiting',
        'ISO/TS 15066:2016, 5.5.4',
        'Power and force limiting near humans',
        'PhysicalCapabilityScope',
        ['physicalScope.maxSpeedNearHumansMps', 'physicalScope.maxForceN']
      ),
      req(
        'iso15066-collaborative-workspace',
        'ISO/TS 15066:2016, 5.5.2',
        'Defined collaborative workspace',
        'PhysicalCapabilityScope',
        ['physicalScope.allowedZones']
      ),
      req(
        'iso15066-monitoring',
        'ISO/TS 15066:2016, 5.2',
        'Continuous monitoring of the collaborative operation',
        'RobotHeartbeatCredential',
        ['motionDigest']
      ),
    ],
  },
  'eu-machinery-2023-1230': {
    regime: 'EU Machinery Regulation 2023/1230',
    version: '2023',
    requirements: [
      req(
        'eu-mr-identification',
        'Reg (EU) 2023/1230, Annex III 1.7.4',
        'Machinery identification and traceability',
        'RobotIdentityCredential',
        ['make', 'model', 'serial']
      ),
      req(
        'eu-mr-software-integrity',
        'Reg (EU) 2023/1230, Annex III 1.1.9',
        'Protection against corruption of safety software',
        'ModelProvenanceAttestation',
        ['vla.weightsHash', 'vla.safetyPolicy']
      ),
      req(
        'eu-mr-safe-limits',
        'Reg (EU) 2023/1230, Annex III 1.2.1',
        'Safety and reliability of control systems and limits',
        'PhysicalCapabilityScope',
        ['physicalScope.maxForceN']
      ),
      req(
        'eu-mr-records',
        'Reg (EU) 2023/1230, Annex III 1.2.1',
        'Recording of safety-relevant data',
        'RobotSafetyRecordCredential',
        ['totalEvents']
      ),
    ],
  },
  'eu-ai-act-high-risk': {
    regime: 'EU AI Act high-risk systems',
    version: '2024',
    requirements: [
      req(
        'eu-aia-record-keeping',
        'Reg (EU) 2024/1689, Art. 12',
        'Automatic recording of events (logging)',
        'RobotSafetyRecordCredential',
        ['logHead']
      ),
      req(
        'eu-aia-transparency',
        'Reg (EU) 2024/1689, Art. 13',
        'Model and configuration transparency',
        'ModelProvenanceAttestation',
        ['vla.modelName', 'vla.configHash']
      ),
      req(
        'eu-aia-human-oversight',
        'Reg (EU) 2024/1689, Art. 14',
        'Human oversight through enforced operating limits',
        'PhysicalCapabilityScope',
        ['physicalScope.maxSpeedNearHumansMps']
      ),
      req(
        'eu-aia-accuracy-robustness',
        'Reg (EU) 2024/1689, Art. 15',
        'Accuracy and robustness traceable to a known build',
        'ModelProvenanceAttestation',
        ['vla.weightsHash']
      ),
    ],
  },
  'ul-3300': {
    regime: 'UL 3300 service, communication, and mobile robots',
    version: '2022',
    requirements: [
      req(
        'ul3300-identity',
        'UL 3300, identification',
        'Robot identity bound to its hardware',
        'RobotIdentityCredential',
        ['hardwareRoot.kind']
      ),
      req(
        'ul3300-operating-limits',
        'UL 3300, operating limits',
        'Enforced speed and zone limits',
        'PhysicalCapabilityScope',
        ['physicalScope.maxSpeedMps', 'physicalScope.allowedZones']
      ),
      req(
        'ul3300-perception-integrity',
        'UL 3300, sensing integrity',
        'Integrity of perception used for safe operation',
        'PerceptionProvenanceCredential',
        ['frameHash']
      ),
      req(
        'ul3300-records',
        'UL 3300, incident records',
        'Records of safety-relevant incidents',
        'RobotSafetyRecordCredential',
        ['totalEvents']
      ),
    ],
  },
};

/** Return a built-in profile by id, or throw if it is unknown. */
export function profile(profileId: string): Profile {
  const prof = PROFILES[profileId];
  if (prof === undefined) {
    throw new RoboticsError(`unknown conformance profile: ${profileId}`);
  }
  return prof;
}

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

export interface RequirementResult {
  id: string;
  clause: string;
  title: string;
  satisfied: boolean;
}

export interface ConformanceReport {
  profileId: string;
  regime: string;
  version: string;
  conforms: boolean;
  satisfiedCount: number;
  totalCount: number;
  requirements: RequirementResult[];
}

function types(credential: Record<string, unknown>): string[] {
  const field = credential.type;
  if (typeof field === 'string') return [field];
  if (Array.isArray(field)) return field as string[];
  return [];
}

function pathValue(subject: Record<string, unknown>, path: string): unknown {
  let node: unknown = subject;
  for (const part of path.split('.')) {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) {
      return null;
    }
    if (!(part in (node as Record<string, unknown>))) {
      return null;
    }
    node = (node as Record<string, unknown>)[part];
  }
  return node;
}

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value as object).length === 0;
  return false;
}

function credentialSatisfies(
  credential: Record<string, unknown>,
  requirement: Requirement
): boolean {
  if (!types(credential).includes(requirement.credential)) return false;
  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  for (const path of requirement.fields) {
    if (isEmpty(pathValue(subject, path))) return false;
  }
  return true;
}

/**
 * Check the presented `credentials` against the named profile and return a
 * deterministic report. Each requirement is satisfied when some presented
 * credential matches its type and has every required field. The caller is
 * expected to have verified the credentials' signatures first; this checks
 * structure and coverage, not proofs.
 */
export function checkConformance(
  credentials: Array<Record<string, unknown>>,
  profileId: string
): ConformanceReport {
  const prof = profile(profileId);
  const results: RequirementResult[] = [];
  let satisfied = 0;
  for (const requirement of prof.requirements) {
    const ok = credentials.some((c) => credentialSatisfies(c, requirement));
    if (ok) satisfied += 1;
    results.push({
      id: requirement.id,
      clause: requirement.clause,
      title: requirement.title,
      satisfied: ok,
    });
  }
  const total = prof.requirements.length;
  return {
    profileId,
    regime: prof.regime,
    version: prof.version,
    conforms: satisfied === total,
    satisfiedCount: satisfied,
    totalCount: total,
    requirements: results,
  };
}

/** Multibase SHA-256 of the JCS-canonical report, for binding into an attestation. */
export function reportDigest(report: ConformanceReport): string {
  const digest = crypto
    .createHash('sha256')
    .update(canonicalize(report as unknown as Record<string, unknown>))
    .digest();
  return 'u' + digest.toString('base64url');
}

// ---------------------------------------------------------------------------
// Signed conformance attestation
// ---------------------------------------------------------------------------

export interface BuildConformanceAttestationOptions {
  robotDid: string;
  report: ConformanceReport;
  attestedAt?: Date;
  validSeconds?: number;
}

/**
 * Build a signed point-in-time conformance attestation for `robotDid` over a
 * `report` produced by checkConformance. The signer is the robot, its owner, or
 * an assessing authority. The report is embedded and bound by digest.
 */
export async function buildConformanceAttestation(
  signer: Signer,
  opts: BuildConformanceAttestationOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid) {
    throw new RoboticsError('robotDid is required');
  }
  const report = opts.report;
  if (
    report === null ||
    typeof report !== 'object' ||
    !('profileId' in report) ||
    !('conforms' in report)
  ) {
    throw new RoboticsError('report must come from checkConformance');
  }
  const issued = opts.attestedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    profileId: report.profileId,
    regime: report.regime,
    conforms: report.conforms,
    satisfiedCount: report.satisfiedCount,
    totalCount: report.totalCount,
    reportDigest: reportDigest(report),
    report,
  };

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', CONFORMANCE_ATTESTATION_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

/**
 * Verify a conformance attestation: the issuer's proof and that the embedded
 * report matches its bound digest. Returns { ok, subject }.
 */
export function verifyConformanceAttestation(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  if (!types(credential).includes(CONFORMANCE_ATTESTATION_TYPE)) return { ok: false };
  if (publicKey === null || publicKey === undefined) return { ok: false };

  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const embedded = subject.report;
  if (embedded === null || typeof embedded !== 'object' || Array.isArray(embedded)) {
    return { ok: false };
  }
  if (subject.reportDigest !== reportDigest(embedded as unknown as ConformanceReport)) {
    return { ok: false };
  }
  if (subject.conforms !== (embedded as Record<string, unknown>).conforms) {
    return { ok: false };
  }
  return { ok: true, subject };
}
