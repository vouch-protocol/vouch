/**
 * Scannable robot passport (Phase 5.6), TypeScript.
 *
 * Mirrors `vouch/robotics/passport.py`. A compact, signed RobotPassport that
 * anyone can scan (QR or NFC) to check a robot's owner, authorized actions,
 * certification, and current standing, offline. The QR/NFC payload is a
 * `vouch-passport:` URI carrying the multibase JCS bytes of the credential, so
 * an offline reader verifies the signature with no network round-trip. The URI
 * encoding is deterministic, so a passport encoded by either language decodes
 * and verifies in the other.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import { canonicalize } from '../jcs';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

export const ROBOT_PASSPORT_TYPE = 'RobotPassport';
export const PASSPORT_URI_SCHEME = 'vouch-passport:';
export const STATUS_ACTIVE = 'active';
export const STATUS_SUSPENDED = 'suspended';
export const STATUS_DECOMMISSIONED = 'decommissioned';

export class PassportError extends Error {}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export interface BuildPassportOptions {
  robotDid: string;
  make: string;
  model: string;
  owner: string;
  authorizedActions: string[];
  certification?: string;
  status?: string;
  validSeconds?: number;
  validFrom?: Date;
}

/** Build a signed RobotPassport credential (issued by the robot or an authority). */
export async function buildPassport(
  signer: Signer,
  opts: BuildPassportOptions
): Promise<Record<string, unknown>> {
  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    make: opts.make,
    model: opts.model,
    owner: opts.owner,
    authorizedActions: [...opts.authorizedActions],
    status: opts.status ?? STATUS_ACTIVE,
  };
  if (opts.certification !== undefined) subject.certification = opts.certification;

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', ROBOT_PASSPORT_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

/** Encode a passport into a compact vouch-passport: URI for a QR or NFC tag. */
export function encodePassport(passport: Record<string, unknown>): string {
  const blob = Buffer.from(canonicalize(passport)).toString('base64url');
  return PASSPORT_URI_SCHEME + 'u' + blob;
}

/** Decode a vouch-passport: URI back into the passport credential. */
export function decodePassport(uri: string): Record<string, unknown> {
  if (!uri.startsWith(PASSPORT_URI_SCHEME)) throw new PassportError(`not a ${PASSPORT_URI_SCHEME} URI`);
  const body = uri.slice(PASSPORT_URI_SCHEME.length);
  if (!body.startsWith('u')) throw new PassportError("expected multibase 'u' payload");
  const raw = Buffer.from(body.slice(1), 'base64url');
  return JSON.parse(raw.toString('utf8'));
}

export interface PassportSummary {
  robot?: string;
  make?: string;
  model?: string;
  owner?: string;
  authorizedActions: string[];
  certification?: string;
  status?: string;
}

/**
 * Verify a passport (a credential object or a vouch-passport: URI). A suspended
 * or decommissioned status still verifies but is surfaced in the summary so a
 * scanner can refuse cooperation. An expired passport fails.
 */
export function verifyPassport(
  passport: Record<string, any> | string,
  publicKey: crypto.KeyObject,
  opts: { now?: Date } = {}
): { ok: boolean; summary?: PassportSummary } {
  let p: Record<string, any>;
  if (typeof passport === 'string') {
    try {
      p = decodePassport(passport);
    } catch {
      return { ok: false };
    }
  } else {
    p = passport;
  }

  const types = Array.isArray(p.type) ? p.type : [p.type];
  if (!types.includes(ROBOT_PASSPORT_TYPE)) return { ok: false };
  try {
    if (!verifyProof(p, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const now = opts.now ?? new Date();
  if (p.validUntil) {
    const vu = new Date(p.validUntil);
    if (!Number.isNaN(vu.getTime()) && now > vu) return { ok: false };
  }

  const s = (p.credentialSubject ?? {}) as Record<string, any>;
  return {
    ok: true,
    summary: {
      robot: s.id,
      make: s.make,
      model: s.model,
      owner: s.owner,
      authorizedActions: s.authorizedActions ?? [],
      certification: s.certification,
      status: s.status,
    },
  };
}
