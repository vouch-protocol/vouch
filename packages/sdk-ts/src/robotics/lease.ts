/**
 * Robot delegation lease (TypeScript).
 *
 * Mirrors `vouch/robotics/lease.py` with byte-identical output. A robot often
 * has to act where there is no connectivity (a warehouse aisle, a field, a
 * tunnel), so it cannot call home to check whether it is still allowed to do
 * something. A delegation lease is a self-contained grant of authority it can
 * verify and act on entirely offline: an authority issues the robot a credential
 * that bounds what it may physically do (a physical capability scope, including
 * the zones it may operate in), for a fixed, short window. The robot verifies the
 * lease's signature, that the window is current, and that a proposed action fits
 * the scope, with no network call.
 *
 * Leases nest: an authority can grant a lease, and the holder can sub-grant a
 * narrower lease to another party, each link attenuating (never widening) the one
 * above it. That nesting is the open cross-vendor chain, a vendor leases to an
 * integrator, the integrator to an operator, the operator to the robot, and every
 * link is verifiable and bounded.
 *
 * This is the open layer: a plain, offline-verifiable lease.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { attenuates, checkPhysicalAction } from './capability';
import type { PhysicalAction } from './capability';
import { RoboticsError } from './identity';

export const DELEGATION_LEASE_TYPE = 'DelegationLeaseCredential';

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function parseIso(s: string): number {
  // Strict "YYYY-MM-DDTHH:MM:SSZ" parse to a UTC epoch in ms. Throws on a
  // malformed value so the window check can treat it as out of window.
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(s);
  if (!m) throw new RoboticsError(`malformed timestamp: ${s}`);
  return Date.UTC(
    Number(m[1]),
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    Number(m[6])
  );
}

function windowCurrent(credential: Record<string, unknown>, now?: Date): boolean {
  const moment = (now ?? new Date()).getTime();
  const vf = credential.validFrom;
  const vu = credential.validUntil;
  try {
    if (typeof vf === 'string' && vf && moment < parseIso(vf)) return false;
    if (typeof vu === 'string' && vu && moment > parseIso(vu)) return false;
  } catch {
    return false;
  }
  return true;
}

export interface BuildDelegationLeaseOptions {
  robotDid: string;
  leaseId: string;
  scope: Record<string, unknown>;
  validSeconds: number;
  validFrom?: Date;
  parentLeaseId?: string;
}

/**
 * Build a signed DelegationLeaseCredential granting `robotDid` a bounded
 * physical `scope` for a fixed window. `scope` is a physicalScope object (the
 * same shape as a PhysicalCapabilityScope credentialSubject.physicalScope).
 * Leases are short-lived by design, so `validSeconds` is required. Set
 * `parentLeaseId` when sub-granting from another lease.
 */
export async function buildDelegationLease(
  signer: Signer,
  opts: BuildDelegationLeaseOptions
): Promise<Record<string, unknown>> {
  if (opts.validSeconds <= 0) {
    throw new RoboticsError('validSeconds must be positive');
  }
  if (!opts.leaseId) {
    throw new RoboticsError('leaseId is required');
  }
  if (opts.scope === null || typeof opts.scope !== 'object' || Array.isArray(opts.scope)) {
    throw new RoboticsError('scope must be a physicalScope object');
  }

  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    leaseId: opts.leaseId,
    physicalScope: opts.scope,
  };
  if (opts.parentLeaseId !== undefined) {
    subject.parentLeaseId = opts.parentLeaseId;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', DELEGATION_LEASE_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    validUntil: iso(new Date(issued.getTime() + opts.validSeconds * 1000)),
    credentialSubject: subject,
  };
  return signer.attachProof(credential);
}

export interface VerifyDelegationLeaseOptions {
  now?: Date;
  parentScope?: Record<string, unknown>;
}

/**
 * Verify a DelegationLeaseCredential offline: the issuer's proof, that the
 * window is current, and (when `parentScope` is supplied) that this lease's
 * scope attenuates the parent. No network call. Returns { ok, subject }.
 */
export function verifyDelegationLease(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject,
  opts: VerifyDelegationLeaseOptions = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(DELEGATION_LEASE_TYPE)) return { ok: false };

  if (publicKey === null || publicKey === undefined) return { ok: false };
  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  if (!windowCurrent(credential, opts.now)) return { ok: false };

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const scope = subject.physicalScope;
  if (scope === null || typeof scope !== 'object' || Array.isArray(scope)) {
    return { ok: false };
  }
  if (
    opts.parentScope !== undefined &&
    !attenuates(opts.parentScope as Record<string, any>, scope as Record<string, any>)
  ) {
    return { ok: false };
  }

  return { ok: true, subject };
}

export interface LeasePermitsOptions {
  now?: Date;
}

/**
 * Decide whether a verified lease permits a proposed physical action: the
 * action must fit the lease scope, and (when the full `credential` is supplied)
 * the window must still be current.
 */
export function leasePermits(
  subject: Record<string, unknown>,
  action: PhysicalAction,
  credential?: Record<string, unknown>,
  opts: LeasePermitsOptions = {}
): boolean {
  if (credential !== undefined && !windowCurrent(credential, opts.now)) {
    return false;
  }
  const scope = (subject.physicalScope ?? {}) as Record<string, any>;
  return checkPhysicalAction(scope, action).ok;
}
