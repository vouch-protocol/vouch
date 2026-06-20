/**
 * Robot liveness heartbeat with safety-envelope conformance (TypeScript).
 *
 * Mirrors `vouch/robotics/liveness.py` with byte-identical output. A robot's
 * identity and capability credentials, once minted, stay valid until something
 * revokes them. This module makes robot trust living: the robot periodically
 * re-attests that it is alive and that its actual motion over the last interval
 * stayed inside the physical envelope its capability credential permits. A
 * verifier then treats the robot as trusted only while a fresh, conformant
 * heartbeat exists, inverting the model from "trusted until revoked" to
 * "untrusted until renewed".
 *
 * The per-interval motion digest is the physical analogue of the agent
 * behavioral digest. It carries aggregates of what the robot actually did over
 * the interval (peak force, peak speed, peak speed while a human was near, count
 * of zone breaches) and asserts whether those stayed inside the declared
 * envelope. A RobotHeartbeatCredential is an eddsa-jcs-2022 VC carrying the
 * robot DID, a session id, the interval index, the declared interval length, and
 * the motion digest, signed by the robot's own key.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { checkPhysicalAction, type PhysicalAction } from './capability';
import { RoboticsError } from './identity';

export const ROBOT_HEARTBEAT_TYPE = 'RobotHeartbeatCredential';

// Default number of missed intervals tolerated before trust is considered stale.
export const DEFAULT_GRACE_INTERVALS = 2;

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Parse a "YYYY-MM-DDTHH:MM:SSZ" timestamp. */
function parseIso(s: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)) {
    throw new RoboticsError(`invalid timestamp: ${s}`);
  }
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new RoboticsError(`invalid timestamp: ${s}`);
  return d;
}

/** One observed motion sample, used for testing and audit. */
export interface MotionSample {
  forceN?: number;
  speedMps?: number;
  nearHumans: boolean;
  zone?: string;
  timestampNs: number;
}

export interface MotionDigest {
  samples: number;
  maxForceN: number;
  maxSpeedMps: number;
  maxSpeedNearHumansMps: number;
  zoneBreaches: number;
  breachCount: number;
  withinEnvelope: boolean;
}

export interface RecordMotionOptions {
  forceN?: number;
  speedMps?: number;
  nearHumans?: boolean;
  zone?: string;
  timeHm?: string;
}

/**
 * Collector for per-interval motion telemetry.
 *
 * The collector accumulates aggregates of what the robot physically did over a
 * heartbeat interval and, when given the robot's physical scope, counts how many
 * samples fell outside the declared envelope. When the scope is omitted, the
 * digest still reports observed maxima but cannot judge conformance, so it
 * reports withinEnvelope true with a zero breach count.
 */
export class MotionCollector {
  private scope?: Record<string, unknown>;
  private _samples = 0;
  private _maxForce = 0.0;
  private _maxSpeed = 0.0;
  private _maxSpeedNear = 0.0;
  private _zoneBreaches = 0;
  private _breaches = 0;
  private _audit: MotionSample[] = [];

  constructor(scope?: Record<string, unknown>) {
    this.scope = scope;
  }

  /** Record a single observed motion sample. */
  record(opts: RecordMotionOptions = {}): void {
    const { forceN, speedMps, nearHumans = false, zone, timeHm } = opts;
    if (forceN !== undefined && forceN < 0) {
      throw new RoboticsError(`forceN must be non-negative, got ${forceN}`);
    }
    if (speedMps !== undefined && speedMps < 0) {
      throw new RoboticsError(`speedMps must be non-negative, got ${speedMps}`);
    }

    this._samples += 1;
    if (forceN !== undefined) {
      this._maxForce = Math.max(this._maxForce, forceN);
    }
    if (speedMps !== undefined) {
      this._maxSpeed = Math.max(this._maxSpeed, speedMps);
      if (nearHumans) {
        this._maxSpeedNear = Math.max(this._maxSpeedNear, speedMps);
      }
    }

    if (this.scope !== undefined) {
      const action: PhysicalAction = { forceN, speedMps, nearHumans, zone, timeHm };
      const result = checkPhysicalAction(this.scope, action);
      if (!result.ok) {
        this._breaches += 1;
        if (result.reasons.some((r) => r.startsWith('zone_not_allowed'))) {
          this._zoneBreaches += 1;
        }
      }
    }

    if (this._audit.length < 4096) {
      this._audit.push({
        forceN: forceN !== undefined ? forceN : undefined,
        speedMps: speedMps !== undefined ? speedMps : undefined,
        nearHumans,
        zone,
        timestampNs: nowNs(),
      });
    }
  }

  /** Return a copy of the per-sample audit trail (not part of the digest). */
  snapshotSamples(): MotionSample[] {
    return this._audit.map((s) => ({ ...s }));
  }

  /** Return the motionDigest object for embedding in a heartbeat credential. */
  digest(): MotionDigest {
    return {
      samples: this._samples,
      maxForceN: this._maxForce,
      maxSpeedMps: this._maxSpeed,
      maxSpeedNearHumansMps: this._maxSpeedNear,
      zoneBreaches: this._zoneBreaches,
      breachCount: this._breaches,
      withinEnvelope: this._breaches === 0,
    };
  }

  /** Clear all state. Call after submitting a heartbeat to start fresh. */
  reset(): void {
    this._samples = 0;
    this._maxForce = 0.0;
    this._maxSpeed = 0.0;
    this._maxSpeedNear = 0.0;
    this._zoneBreaches = 0;
    this._breaches = 0;
    this._audit = [];
  }
}

/**
 * Structural validation of a motionDigest object. Throws RoboticsError on
 * malformed input. Does not judge whether the values are acceptable; that is
 * policy, expressed through `isLive` and the verifier's thresholds.
 */
export function validateMotionDigest(digest: Record<string, unknown>): void {
  if (digest === null || typeof digest !== 'object' || Array.isArray(digest)) {
    throw new RoboticsError('motionDigest must be an object');
  }

  for (const name of ['samples', 'zoneBreaches', 'breachCount'] as const) {
    if (!(name in digest)) {
      throw new RoboticsError(`motionDigest.${name} is required`);
    }
    const v = digest[name];
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
      throw new RoboticsError(`motionDigest.${name} must be a non-negative integer`);
    }
  }

  for (const name of ['maxForceN', 'maxSpeedMps', 'maxSpeedNearHumansMps'] as const) {
    if (!(name in digest)) {
      throw new RoboticsError(`motionDigest.${name} is required`);
    }
    const v = digest[name];
    if (typeof v !== 'number') {
      throw new RoboticsError(`motionDigest.${name} must be a number`);
    }
    if (v < 0) {
      throw new RoboticsError(`motionDigest.${name} must be non-negative`);
    }
  }

  if (!('withinEnvelope' in digest)) {
    throw new RoboticsError('motionDigest.withinEnvelope is required');
  }
  if (typeof digest.withinEnvelope !== 'boolean') {
    throw new RoboticsError('motionDigest.withinEnvelope must be a boolean');
  }
}

export interface BuildHeartbeatOptions {
  sessionId: string;
  intervalIndex: number;
  motionDigest: Record<string, unknown>;
  intervalSeconds: number;
  issuedAt?: Date;
}

/**
 * Build a signed RobotHeartbeatCredential. The robot self-issues with its own
 * Vouch key. `motionDigest` is produced by a MotionCollector over the interval;
 * `intervalSeconds` is the declared heartbeat cadence, which a verifier uses to
 * judge freshness.
 */
export async function buildRobotHeartbeat(
  signer: Signer,
  opts: BuildHeartbeatOptions
): Promise<Record<string, unknown>> {
  if (opts.intervalIndex < 0) {
    throw new RoboticsError('intervalIndex must be non-negative');
  }
  if (opts.intervalSeconds <= 0) {
    throw new RoboticsError('intervalSeconds must be positive');
  }
  validateMotionDigest(opts.motionDigest);

  const issued = opts.issuedAt ?? new Date();
  const robotDid = signer.getDid();
  const subject: Record<string, unknown> = {
    id: robotDid,
    sessionId: opts.sessionId,
    intervalIndex: opts.intervalIndex,
    intervalSeconds: opts.intervalSeconds,
    motionDigest: opts.motionDigest,
  };
  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', ROBOT_HEARTBEAT_TYPE],
    issuer: robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  return signer.attachProof(credential);
}

/**
 * Verify a RobotHeartbeatCredential: the credential proof (robot key) and the
 * structural validity of the embedded motion digest. Returns { ok, subject }.
 *
 * This checks authenticity and shape only. Whether the robot is currently
 * trusted is a separate, time-dependent question answered by `isLive`.
 */
export function verifyRobotHeartbeat(
  credential: Record<string, unknown>,
  robotPublicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(ROBOT_HEARTBEAT_TYPE)) return { ok: false };

  try {
    if (!verifyProof(credential, robotPublicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const digest = subject.motionDigest as Record<string, unknown>;
  try {
    validateMotionDigest(digest);
  } catch (e) {
    if (e instanceof RoboticsError) return { ok: false };
    throw e;
  }
  return { ok: true, subject };
}

export interface IsLiveOptions {
  now?: Date;
  intervalSeconds?: number;
  graceIntervals?: number;
}

/**
 * Decide whether a robot is currently trusted, given its most recent heartbeat.
 *
 * A robot is live only if BOTH hold:
 *   1. Freshness: the heartbeat was issued within `graceIntervals` cadence
 *      periods of `now`. A robot that stopped sending heartbeats loses trust.
 *   2. Conformance: the heartbeat's motion digest reports withinEnvelope true.
 *      A robot that exceeded its physical envelope loses trust even if recent.
 *
 * `intervalSeconds` defaults to the value the heartbeat itself declares.
 */
export function isLive(
  credential: Record<string, unknown>,
  opts: IsLiveOptions = {}
): boolean {
  const graceIntervals = opts.graceIntervals ?? DEFAULT_GRACE_INTERVALS;
  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const digest = (subject.motionDigest ?? {}) as Record<string, unknown>;
  if (digest.withinEnvelope !== true) {
    return false;
  }

  const cadence =
    opts.intervalSeconds !== undefined ? opts.intervalSeconds : subject.intervalSeconds;
  if (typeof cadence !== 'number' || !Number.isInteger(cadence) || cadence <= 0) {
    return false;
  }
  if (graceIntervals < 1) {
    throw new RoboticsError('graceIntervals must be at least 1');
  }

  const raw = credential.validFrom;
  if (!raw || typeof raw !== 'string') {
    return false;
  }
  let issued: Date;
  try {
    issued = parseIso(raw);
  } catch {
    return false;
  }

  const moment = opts.now ?? new Date();
  const deadline = new Date(issued.getTime() + cadence * graceIntervals * 1000);
  // A heartbeat from the future (clock skew beyond one cadence) is not trusted.
  if (moment.getTime() + cadence * 1000 < issued.getTime()) {
    return false;
  }
  return moment.getTime() <= deadline.getTime();
}

function nowNs(): number {
  return Number(process.hrtime.bigint());
}
