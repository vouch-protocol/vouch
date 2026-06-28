/**
 * Physical quorum (TypeScript).
 *
 * Mirrors `vouch/robotics/physical_quorum.py` with byte-identical output. Some
 * physical actions are serious enough that no single authority should be able to
 * order them alone: applying large force near a person, entering a restricted
 * area, an irreversible cut or weld. A physical quorum requires M approvals out
 * of a set of N approvers before the action is authorized. Each approver signs an
 * approval over the same action, and the action is authorized only when at least
 * the threshold number of distinct, valid approvers from the set have approved
 * it.
 *
 * This is the open layer: a plain M-of-N over distinct approvers.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const ACTION_APPROVAL_TYPE = 'PhysicalActionApprovalCredential';
export const APPROVE = 'approve';
export const REJECT = 'reject';

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function parseIso(s: string): number {
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

function windowCurrent(credential: Record<string, unknown>, moment: number): boolean {
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

export interface BuildActionApprovalOptions {
  actionId: string;
  robotDid: string;
  decision?: string;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Build a signed approval (or rejection) by one approver for a specific physical
 * action, identified by `actionId`, that `robotDid` would perform.
 */
export async function buildActionApproval(
  approverSigner: Signer,
  opts: BuildActionApprovalOptions
): Promise<Record<string, unknown>> {
  const decision = opts.decision ?? APPROVE;
  if (decision !== APPROVE && decision !== REJECT) {
    throw new RoboticsError(
      `decision must be '${APPROVE}' or '${REJECT}', got '${decision}'`
    );
  }
  if (!opts.actionId) {
    throw new RoboticsError('actionId is required');
  }

  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = {
    id: approverSigner.getDid(),
    actionId: opts.actionId,
    robotDid: opts.robotDid,
    decision,
  };
  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', ACTION_APPROVAL_TYPE],
    issuer: approverSigner.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return approverSigner.attachProof(credential);
}

export interface VerifyActionAuthorizationOptions {
  actionId: string;
  robotDid: string;
  approverKeys: Record<string, crypto.KeyObject>;
  threshold: number;
  approverSet?: Set<string>;
  now?: Date;
}

/**
 * Verify that a high-consequence physical action is authorized by a quorum.
 *
 * Each approval must: be the right type, carry an in-date proof signed by the
 * approver's key (looked up in `approverKeys` by issuer DID), match `actionId`
 * and `robotDid`, and carry an `approve` decision. When `approverSet` is
 * supplied, the approver must be in it. The action is authorized when at least
 * `threshold` DISTINCT valid approvers have approved. A single approver counts
 * once even if it submits several approvals. Returns [authorized, sorted list of
 * the distinct approving DIDs].
 */
export function verifyActionAuthorization(
  approvals: Array<Record<string, unknown>>,
  opts: VerifyActionAuthorizationOptions
): [boolean, string[]] {
  if (opts.threshold < 1) {
    throw new RoboticsError('threshold must be at least 1');
  }

  const moment = (opts.now ?? new Date()).getTime();
  const approvers = new Set<string>();

  for (const approval of approvals) {
    const typeField = approval.type;
    const types = Array.isArray(typeField) ? typeField : [typeField];
    if (!types.includes(ACTION_APPROVAL_TYPE)) continue;

    const subject = (approval.credentialSubject ?? {}) as Record<string, unknown>;
    const issuer = approval.issuer;
    if (typeof issuer !== 'string') continue;
    if (subject.actionId !== opts.actionId || subject.robotDid !== opts.robotDid) {
      continue;
    }
    if (subject.decision !== APPROVE) continue;
    if (opts.approverSet !== undefined && !opts.approverSet.has(issuer)) continue;
    if (!(issuer in opts.approverKeys)) continue;
    if (!windowCurrent(approval, moment)) continue;

    const resolved = opts.approverKeys[issuer];
    if (resolved === null || resolved === undefined) continue;
    try {
      if (!verifyProof(approval, resolved)) continue;
    } catch {
      continue;
    }

    approvers.add(issuer);
  }

  return [approvers.size >= opts.threshold, [...approvers].sort()];
}
