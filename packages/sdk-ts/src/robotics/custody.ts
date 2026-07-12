/**
 * Physical custody handoff (TypeScript): an accountable chain for a task or
 * object across actors.
 *
 * Mirrors `vouch/robotics/custody.py` with byte-identical output. A physical
 * task or object passes across a chain of actors, human and robot: a person
 * picks an item, hands it to a robot, that robot hands it to another robot,
 * which places it. Each handoff is a signed custody transition, so a
 * physical-world incident (damage, loss, mis-delivery) traces to the exact hop
 * and the actor responsible.
 *
 * A custody handoff credential records that a receiving actor accepted custody
 * of a task or object from a releasing actor, signed by the receiver. Linking
 * each handoff to the previous forms a chain a verifier walks to establish who
 * held the task at any time. A condition attested at each handoff lets a
 * physical state change be localized to the specific hop whose holder was
 * responsible.
 *
 * This is the open layer: signed handoff credentials, chain verification, a
 * holder-at-time helper, and software condition localization. Managed logistics
 * custody orchestration and fleet-scale tracking are out of scope for the open
 * layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const CUSTODY_HANDOFF_TYPE = 'CustodyHandoffCredential';

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function parseIso(value: unknown): Date | undefined {
  if (typeof value !== 'string' || !value) return undefined;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(value);
  if (!m) return undefined;
  const ms = Date.UTC(
    Number(m[1]),
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    Number(m[6])
  );
  if (Number.isNaN(ms)) return undefined;
  return new Date(ms);
}

/**
 * Verify a typed custody credential: the expected type is present and the proof
 * verifies under `publicKey`. Returns { ok, subject }.
 */
function verifyTyped(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject,
  expectedType: string
): { ok: boolean; subject: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(expectedType)) return { ok: false, subject: {} };

  if (publicKey === null || publicKey === undefined) return { ok: false, subject: {} };
  try {
    if (!verifyProof(credential, publicKey)) return { ok: false, subject: {} };
  } catch {
    return { ok: false, subject: {} };
  }
  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  return { ok: true, subject };
}

// ---------------------------------------------------------------------------
// Handoff credential + custody chain
// ---------------------------------------------------------------------------

export interface BuildHandoffOptions {
  taskId: string;
  fromActor: string;
  toActor: string;
  condition?: string;
  handoffAt?: Date;
  validSeconds?: number;
}

/**
 * Build a signed custody handoff: the receiving actor `toActor` accepts custody
 * of `taskId` from `fromActor`, signed by the receiver (the party taking
 * responsibility). `condition` optionally attests the state of the task or
 * object as received (for example a status, a quantity, or a hash of an
 * inspection), which lets a later state change be localized to a hop.
 * `fromActor` and `toActor` may be human or robot DIDs.
 */
export async function buildHandoff(
  receiverSigner: Signer,
  opts: BuildHandoffOptions
): Promise<Record<string, unknown>> {
  if (!opts.taskId || !opts.fromActor || !opts.toActor) {
    throw new RoboticsError('taskId, fromActor, and toActor are required');
  }
  const issued = opts.handoffAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.taskId,
    fromActor: opts.fromActor,
    toActor: opts.toActor,
  };
  if (opts.condition !== undefined) {
    subject.condition = opts.condition;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', CUSTODY_HANDOFF_TYPE],
    issuer: opts.toActor,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return receiverSigner.attachProof(credential);
}

/**
 * Verify a custody handoff: the receiver's proof and that the issuer is the
 * receiving actor (a party attests its own acceptance of custody). Returns
 * { ok, subject }.
 */
export function verifyHandoff(
  credential: Record<string, unknown>,
  receiverPublicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(credential, receiverPublicKey, CUSTODY_HANDOFF_TYPE);
  if (!ok) return { ok: false };
  if (!subject.fromActor || !subject.toActor) return { ok: false };
  if (credential.issuer !== subject.toActor) return { ok: false };
  return { ok: true, subject };
}

export interface VerifyHandoffChainOptions {
  originActor?: string;
}

/**
 * Verify an ordered list of handoff credentials forms a valid custody chain:
 * each handoff verifies under its receiver's key, every link's toActor matches
 * the next link's fromActor, and (when given) the first fromActor is
 * `originActor`. `publicKeys` maps an actor DID (human or robot) to its key.
 * Returns { ok, currentHolder }.
 */
export function verifyHandoffChain(
  handoffs: Array<Record<string, unknown>>,
  publicKeys: Record<string, crypto.KeyObject>,
  opts: VerifyHandoffChainOptions = {}
): { ok: boolean; currentHolder?: string } {
  let expectedFrom = opts.originActor;
  let currentHolder: string | undefined = opts.originActor;
  for (const handoff of handoffs) {
    const receiver = handoff.issuer;
    if (typeof receiver !== 'string' || !(receiver in publicKeys)) return { ok: false };
    const { ok, subject } = verifyHandoff(handoff, publicKeys[receiver]);
    if (!ok || subject === undefined) return { ok: false };
    if (expectedFrom !== undefined && subject.fromActor !== expectedFrom) return { ok: false };
    currentHolder = subject.toActor as string;
    expectedFrom = currentHolder;
  }
  return { ok: true, currentHolder };
}

// ---------------------------------------------------------------------------
// Holder-at-time and condition localization
// ---------------------------------------------------------------------------

/**
 * Return the actor holding the task at ISO time `at`: the receiver (toActor) of
 * the most recent handoff whose handoff time is at or before `at`. Returns null
 * if no handoff had occurred yet. `handoffs` is assumed in chain order.
 */
export function holderAt(
  handoffs: Array<Record<string, unknown>>,
  at: string
): string | null {
  const when = parseIso(at);
  if (when === undefined) return null;
  let holder: string | null = null;
  for (const handoff of handoffs) {
    const start = parseIso(handoff.validFrom);
    const subject = (handoff.credentialSubject ?? {}) as Record<string, unknown>;
    if (start !== undefined && start.getTime() <= when.getTime()) {
      holder = (subject.toActor as string | undefined) ?? null;
    }
  }
  return holder;
}

export interface ConditionChange {
  responsibleHolder: string | null;
  fromCondition: string;
  toCondition: string;
}

/**
 * Find the first hop where the attested condition differs from the previous
 * handoff. The holder responsible for the change is the actor who held the task
 * during it (the previous handoff's receiver). Returns a dict with
 * responsibleHolder, fromCondition, and toCondition, or null if the condition
 * never changed. Handoffs without a condition are skipped for the comparison.
 */
export function locateConditionChange(
  handoffs: Array<Record<string, unknown>>
): ConditionChange | null {
  let prevCondition: string | undefined;
  let prevHolder: string | null = null;
  for (const handoff of handoffs) {
    const subject = (handoff.credentialSubject ?? {}) as Record<string, unknown>;
    const condition = subject.condition;
    if (condition === undefined || condition === null) continue;
    if (prevCondition !== undefined && condition !== prevCondition) {
      return {
        responsibleHolder: prevHolder,
        fromCondition: prevCondition,
        toCondition: condition as string,
      };
    }
    prevCondition = condition as string;
    prevHolder = (subject.toActor as string | undefined) ?? null;
  }
  return null;
}
