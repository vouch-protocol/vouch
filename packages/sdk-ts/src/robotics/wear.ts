/**
 * Robot wear and degradation attestation (TypeScript).
 *
 * Mirrors `vouch/robotics/wear.py` with byte-identical output. A robot does not
 * stay as capable as it left the factory. Actuators wear, joints develop
 * backlash, sensors drift out of calibration, and error rates creep up. This
 * module lets a robot sign its own degradation state, bound to its identity and
 * hash-linked over time so the history is tamper-evident, and it derives a
 * narrowed physical capability scope from that state, so a worn robot operates
 * inside a tighter, verifiable envelope instead of trusting the static limit it
 * shipped with.
 *
 * A wear attestation carries a normalized wear level (0 for as-new, 1 for fully
 * worn) and optional detailed metrics (actuator wear, calibration drift, cycle
 * count, fault rate), signed by the robot. Linking each attestation to the
 * previous one by its proof forms a chain a verifier walks to see how the robot
 * degraded over its life. `attenuateForWear` derives a physical scope whose
 * numeric caps are scaled down by the wear level, and the result is a valid
 * attenuation of the original scope, so the same attenuation rule the rest of
 * Vouch uses carries the derating.
 *
 * This is the open layer: the robot signs its wear state and derives the
 * narrowed scope credential in software. Firmware-level enforcement of the
 * narrowed envelope and managed predictive-maintenance modeling are out of scope
 * for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const WEAR_ATTESTATION_TYPE = 'RobotWearAttestation';

// Numeric caps that scale down with wear. Zones and shift windows are preserved
// unchanged, so the derived scope stays a valid attenuation of the original.
const DERATED_CAPS = ['maxForceN', 'maxSpeedMps', 'maxSpeedNearHumansMps'];

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export interface BuildWearAttestationOptions {
  robotDid: string;
  wearLevel: number;
  metrics?: Record<string, unknown>;
  prevProof?: string;
  attestedAt?: Date;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Build a signed RobotWearAttestation: the robot attests its own degradation as
 * a normalized `wearLevel` in [0, 1], optionally with detailed `metrics`. When
 * `prevProof` is the proof value of the previous attestation, the new
 * attestation links to it, forming a tamper-evident wear history. Signed by the
 * robot.
 */
export async function buildWearAttestation(
  signer: Signer,
  opts: BuildWearAttestationOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid) {
    throw new RoboticsError('robotDid is required');
  }
  if (opts.wearLevel < 0.0 || opts.wearLevel > 1.0) {
    throw new RoboticsError('wearLevel must be between 0.0 and 1.0');
  }

  const issued = opts.validFrom ?? new Date();
  const attested = opts.attestedAt ?? issued;
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    wearLevel: opts.wearLevel,
    attestedAt: iso(attested),
  };
  if (opts.metrics !== undefined) {
    subject.metrics = { ...opts.metrics };
  }
  if (opts.prevProof !== undefined) {
    subject.prevProof = opts.prevProof;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', WEAR_ATTESTATION_TYPE],
    issuer: opts.robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

/**
 * Verify a RobotWearAttestation: the robot's proof, that the issuer is the
 * robot, and that the wear level is in range. Returns { ok, subject }.
 */
export function verifyWearAttestation(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(WEAR_ATTESTATION_TYPE)) return { ok: false };

  if (publicKey === null || publicKey === undefined) return { ok: false };
  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  if (credential.issuer !== subject.id) return { ok: false };
  const level = subject.wearLevel;
  if (typeof level !== 'number' || level < 0.0 || level > 1.0) return { ok: false };
  return { ok: true, subject };
}

/**
 * Verify an ordered wear history: each attestation verifies under the robot's
 * key, and each one after the first links to the previous by its proof value.
 * Returns { ok, latest }.
 */
export function verifyWearChain(
  attestations: Array<Record<string, unknown>>,
  publicKey: crypto.KeyObject
): { ok: boolean; latest?: Record<string, unknown> } {
  if (!attestations || attestations.length === 0) return { ok: false };
  let prevProof: string | undefined;
  let latest: Record<string, unknown> | undefined;
  for (const att of attestations) {
    const res = verifyWearAttestation(att, publicKey);
    if (!res.ok || res.subject === undefined) return { ok: false };
    if (prevProof !== undefined && res.subject.prevProof !== prevProof) {
      return { ok: false };
    }
    const proof = (att.proof ?? {}) as Record<string, unknown>;
    prevProof = proof.proofValue as string | undefined;
    latest = res.subject;
  }
  return { ok: true, latest };
}

/**
 * Derive a physical scope narrowed for the given wear level: each numeric cap is
 * scaled by (1 - wearLevel), and the allowed zones and shift windows are carried
 * through unchanged. The result is a valid attenuation of `scope` (never broader
 * on any dimension), so the same attenuation check the rest of Vouch uses
 * accepts it. A wear level of 0 returns the caps unchanged.
 */
export function attenuateForWear(
  scope: Record<string, unknown>,
  wearLevel: number
): Record<string, unknown> {
  if (wearLevel < 0.0 || wearLevel > 1.0) {
    throw new RoboticsError('wearLevel must be between 0.0 and 1.0');
  }
  const factor = 1.0 - wearLevel;
  const narrowed: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(scope)) {
    if (DERATED_CAPS.includes(key) && typeof value === 'number') {
      narrowed[key] = value * factor;
    } else if (key === 'allowedZones') {
      narrowed[key] = [...(value as unknown[])];
    } else if (key === 'shiftWindows') {
      narrowed[key] = (value as Array<Record<string, unknown>>).map((w) => ({ ...w }));
    } else {
      narrowed[key] = value;
    }
  }
  return narrowed;
}
