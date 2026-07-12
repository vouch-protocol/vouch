/**
 * Halos safety-evidence recorder (NVIDIA Halos integration), TypeScript.
 *
 * Mirrors `vouch/robotics/halos.py` with byte-identical output. NVIDIA Halos
 * certifies that a robot's stack is functionally safe and secure by design. It
 * does not, on its own, produce a verifiable record of what a specific robot
 * did, or bind that record to the robot's identity. This module is the evidence
 * layer that sits under a Halos-certified stack.
 *
 * A `SafetyEventRecorder` captures the safety-relevant event stream produced by
 * the Halos Outside-In Safety Blueprint components (the Safety AI Monitor, the
 * Safety Event Integrator, the Safety Decision Maker, and the sensor input
 * pipeline), plus emergency stops and operator actions, into the tamper-evident,
 * encrypted black-box. The robot then signs a `HalosSafetyEvidenceCredential`
 * that seals the black-box chain head and entry count and binds them to the
 * robot's identity and to the exact Halos stack elements it ran on.
 *
 * A verifier that holds the sealed credential and the entries confirms the
 * record is unaltered, that it has not been truncated or extended since it was
 * sealed, that it is attributable to that specific robot, and that it names the
 * certified Halos configuration it was produced on, all without the black-box
 * key. Only a holder of the black-box key can read the payloads, so the record
 * stays confidential while remaining verifiable.
 *
 * This composes the existing black-box and robot-identity primitives and adds no
 * new cryptography.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { GENESIS_PREV_HASH, BlackBoxLog, verifyBlackboxChain } from './blackbox';

export const HALOS_SAFETY_EVIDENCE_TYPE = 'HalosSafetyEvidenceCredential';

/**
 * The safety-relevant event producers in a Halos-certified stack: the four
 * Outside-In Safety Blueprint components, plus an emergency stop and an operator
 * action. A recorder rejects any event from a source outside this set, so the
 * record maps to a known part of the certified stack.
 */
export const HALOS_EVENT_SOURCES: ReadonlySet<string> = new Set([
  'SIPP', // Sensor Input Processing Pipeline
  'SAIM', // Safety AI Monitor
  'SEI', // Safety Event Integrator
  'SDM', // Safety Decision Maker (runs on the IGX Functional Safety Island)
  'estop', // emergency stop
  'operator', // human operator action
]);

export class HalosError extends Error {}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Records the Halos safety-event stream into the tamper-evident black-box.
 *
 * Wraps a `BlackBoxLog`: each recorded event is encrypted and hash-linked, so
 * the stream is confidential yet tamper-evident. `key` is 32 bytes (AES-256).
 */
export class SafetyEventRecorder {
  private log: BlackBoxLog;

  constructor(key: Uint8Array) {
    this.log = new BlackBoxLog(key);
  }

  /** Record one safety event from a named Halos stack source. */
  record(
    source: string,
    event: string,
    detail?: Record<string, unknown>,
    opts: { timestamp?: string } = {}
  ): Record<string, unknown> {
    if (!HALOS_EVENT_SOURCES.has(source)) {
      throw new HalosError(`unknown Halos event source: ${JSON.stringify(source)}`);
    }
    const payload: Record<string, unknown> = { source, detail: detail ?? {} };
    return this.log.append(event, payload, opts);
  }

  head(): string {
    return this.log.head();
  }

  count(): number {
    return this.log.entries().length;
  }

  entries(): Array<Record<string, unknown>> {
    return this.log.entries();
  }

  /** Decrypt one entry with this recorder's black-box key. */
  openEntry(entry: Record<string, unknown>): Record<string, unknown> {
    return this.log.openEntry(entry);
  }
}

export interface BuildSafetyEvidenceOptions {
  halosStack: Record<string, unknown>;
  window: { from: string; to: string };
  recorder?: SafetyEventRecorder;
  blackboxHead?: string;
  entryCount?: number;
  robotIdentity?: string;
  validSeconds?: number;
  validFrom?: Date;
  created?: Date;
}

/**
 * Seal a robot's Halos safety-event record into a signed
 * HalosSafetyEvidenceCredential.
 *
 * The robot signs a credential that binds the black-box chain head and entry
 * count to its identity, to the Halos stack elements it ran on, and to the time
 * window. Pass either a `recorder` or an explicit `blackboxHead` + `entryCount`.
 */
export async function buildSafetyEvidence(
  robotSigner: Signer,
  opts: BuildSafetyEvidenceOptions
): Promise<Record<string, unknown>> {
  const { halosStack, window } = opts;
  if (!halosStack || Object.keys(halosStack).length === 0) {
    throw new HalosError('halosStack is required');
  }
  if (!window || window.from === undefined || window.to === undefined) {
    throw new HalosError("window with 'from' and 'to' is required");
  }

  let head: string;
  let count: number;
  if (opts.recorder !== undefined) {
    head = opts.recorder.head();
    count = opts.recorder.count();
  } else {
    if (opts.blackboxHead === undefined || opts.entryCount === undefined) {
      throw new HalosError('pass a recorder, or both blackboxHead and entryCount');
    }
    head = opts.blackboxHead;
    count = opts.entryCount;
  }
  if (count < 0) {
    throw new HalosError('entryCount cannot be negative');
  }

  const robotDid = robotSigner.getDid();
  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = {
    id: robotDid,
    blackboxHead: head,
    entryCount: count,
    halosStack,
    window: { from: window.from, to: window.to },
  };
  if (opts.robotIdentity !== undefined) subject.robotIdentity = opts.robotIdentity;

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', HALOS_SAFETY_EVIDENCE_TYPE],
    issuer: robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return robotSigner.attachProof(credential, { created: opts.created });
}

/**
 * Verify a HalosSafetyEvidenceCredential.
 *
 * Checks the robot's proof and that the issuer is the robot. When `entries` are
 * supplied, also checks that the black-box chain is intact, that its length
 * matches the sealed entry count, and that its head matches the sealed head, so
 * a truncated, extended, reordered, or tampered record is rejected. Returns
 * `{ ok, subject }`.
 */
export function verifySafetyEvidence(
  credential: Record<string, any>,
  robotPublicKey: crypto.KeyObject,
  opts: { entries?: Array<Record<string, any>> } = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(HALOS_SAFETY_EVIDENCE_TYPE)) return { ok: false };

  if (robotPublicKey === null || robotPublicKey === undefined) return { ok: false };
  try {
    if (!verifyProof(credential, robotPublicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  if (subject.id !== credential.issuer) return { ok: false };

  const entries = opts.entries;
  if (entries !== undefined) {
    if (!verifyBlackboxChain(entries).ok) return { ok: false };
    if (entries.length !== subject.entryCount) return { ok: false };
    const head =
      entries.length > 0 ? (entries[entries.length - 1].entryHash as string) : GENESIS_PREV_HASH;
    if (head !== subject.blackboxHead) return { ok: false };
  }

  return { ok: true, subject };
}
