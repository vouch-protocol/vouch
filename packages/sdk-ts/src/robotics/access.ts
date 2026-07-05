/**
 * Robot-to-infrastructure bounded trust (TypeScript): authenticate a robot to
 * physical resources.
 *
 * Mirrors `vouch/robotics/access.py` with byte-identical output. A robot in a
 * warehouse, hospital, or building needs to open doors, call elevators, dock at
 * chargers, and operate machines. This gives it a bounded, revocable, auditable
 * way to do so. The infrastructure operator issues an access grant naming a
 * resource, the permitted operations, an optional zone, and a time window,
 * signed by the operator. The robot presents a signed access request for a
 * specific operation on a specific resource, and the resource authorizes it
 * offline: the grant must be valid and operator-signed, the request valid and
 * robot-signed, the operation permitted, and the moment inside the window. The
 * grant plus the request is a tamper-evident, attributable record of the access.
 *
 * This is the open layer: signed grants and requests, an offline authorize
 * decision, shrink-only attenuation, and the audit record. Hardware-enforced
 * actuation in the resource and managed fleet access-policy orchestration are
 * out of scope for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const ACCESS_GRANT_TYPE = 'InfrastructureAccessGrant';
export const ACCESS_REQUEST_TYPE = 'InfrastructureAccessRequest';

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
 * Verify a typed access credential: the expected type is present and the proof
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

function withinWindow(credential: Record<string, unknown>, now?: Date): boolean {
  const at = now ?? new Date();
  const start = parseIso(credential.validFrom);
  const end = parseIso(credential.validUntil);
  if (start !== undefined && at.getTime() < start.getTime()) return false;
  if (end !== undefined && at.getTime() > end.getTime()) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Access grant (operator -> robot)
// ---------------------------------------------------------------------------

export interface BuildAccessGrantOptions {
  robotDid: string;
  resource: string;
  operations: string[];
  zone?: string;
  validSeconds: number;
  grantedAt?: Date;
}

/**
 * Build a signed access grant: the infrastructure operator grants `robotDid`
 * permission to perform `operations` on `resource` (optionally within `zone`)
 * for `validSeconds`. Signed by the operator.
 */
export async function buildAccessGrant(
  operatorSigner: Signer,
  opts: BuildAccessGrantOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid || !opts.resource) {
    throw new RoboticsError('robotDid and resource are required');
  }
  if (!opts.operations || opts.operations.length === 0) {
    throw new RoboticsError('operations must be a non-empty list');
  }
  const issued = opts.grantedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    resource: opts.resource,
    operations: [...opts.operations],
  };
  if (opts.zone !== undefined) {
    subject.zone = opts.zone;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', ACCESS_GRANT_TYPE],
    issuer: operatorSigner.getDid(),
    validFrom: iso(issued),
    validUntil: iso(new Date(issued.getTime() + opts.validSeconds * 1000)),
    credentialSubject: subject,
  };
  return operatorSigner.attachProof(credential);
}

/**
 * Verify an access grant: the operator's proof and that the grant is within its
 * validity window at `now`. Returns { ok, subject }.
 */
export function verifyAccessGrant(
  grant: Record<string, unknown>,
  operatorPublicKey: crypto.KeyObject,
  opts: { now?: Date } = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(grant, operatorPublicKey, ACCESS_GRANT_TYPE);
  if (!ok) return { ok: false };
  if (!subject.resource || !subject.operations) return { ok: false };
  if (!withinWindow(grant, opts.now)) return { ok: false };
  return { ok: true, subject };
}

// ---------------------------------------------------------------------------
// Access request (robot) + authorize decision (resource, offline)
// ---------------------------------------------------------------------------

export interface BuildAccessRequestOptions {
  robotDid: string;
  resource: string;
  operation: string;
  requestedAt?: Date;
}

/**
 * Build a signed access request: the robot requests to perform `operation` on
 * `resource`. Signed by the robot.
 */
export async function buildAccessRequest(
  robotSigner: Signer,
  opts: BuildAccessRequestOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid || !opts.resource || !opts.operation) {
    throw new RoboticsError('robotDid, resource, and operation are required');
  }
  const issued = opts.requestedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    resource: opts.resource,
    operation: opts.operation,
  };
  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', ACCESS_REQUEST_TYPE],
    issuer: opts.robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  return robotSigner.attachProof(credential);
}

/**
 * The outcome of an offline access authorization: ok plus any reasons it
 * failed.
 */
export interface AuthorizeResult {
  ok: boolean;
  reasons: string[];
}

/**
 * Decide, offline, whether to allow the requested access. The grant must verify
 * under the operator's key and be in window, the request must verify under the
 * robot's key, the grant and request must name the same robot and resource, and
 * the requested operation must be permitted by the grant. Returns an
 * AuthorizeResult with the reasons for any refusal.
 */
export function authorizeAccess(
  grant: Record<string, unknown>,
  request: Record<string, unknown>,
  operatorPublicKey: crypto.KeyObject,
  robotPublicKey: crypto.KeyObject,
  opts: { now?: Date } = {}
): AuthorizeResult {
  const reasons: string[] = [];

  const grantRes = verifyAccessGrant(grant, operatorPublicKey, { now: opts.now });
  if (!grantRes.ok || grantRes.subject === undefined) {
    reasons.push('grant invalid or out of window');
    return { ok: false, reasons };
  }
  const grantSubject = grantRes.subject;

  const req = verifyTyped(request, robotPublicKey, ACCESS_REQUEST_TYPE);
  if (!req.ok || request.issuer !== req.subject.id) {
    reasons.push('request invalid');
    return { ok: false, reasons };
  }
  const reqSubject = req.subject;

  if (grantSubject.id !== reqSubject.id) {
    reasons.push('grant and request name different robots');
  }
  if (grantSubject.resource !== reqSubject.resource) {
    reasons.push('grant and request name different resources');
  }
  const operations = (grantSubject.operations as string[] | undefined) ?? [];
  if (!operations.includes(reqSubject.operation as string)) {
    reasons.push('operation not permitted by the grant');
  }

  return { ok: reasons.length === 0, reasons };
}

// ---------------------------------------------------------------------------
// Attenuation (a sub-grant may only narrow)
// ---------------------------------------------------------------------------

/**
 * Return true if `child` is a valid attenuation of `parent`: the same resource,
 * a subset of the operations, and the same zone (or the parent had no zone). A
 * sub-grant may only narrow, never widen, the access it inherits.
 */
export function attenuatesGrant(
  parent: Record<string, unknown>,
  child: Record<string, unknown>
): boolean {
  const p = (parent.credentialSubject ?? {}) as Record<string, unknown>;
  const c = (child.credentialSubject ?? {}) as Record<string, unknown>;
  if (p.resource !== c.resource) return false;
  const parentOps = new Set((p.operations as string[] | undefined) ?? []);
  const childOps = (c.operations as string[] | undefined) ?? [];
  if (!childOps.every((op) => parentOps.has(op))) return false;
  if (p.zone !== undefined && p.zone !== null && c.zone !== p.zone) return false;
  return true;
}
