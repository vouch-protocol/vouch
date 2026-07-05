/**
 * Bystander-consent evidence for robot capture (TypeScript).
 *
 * Mirrors `vouch/robotics/consent.py` with byte-identical output. A robot
 * working in a shared or public space captures people incidentally through its
 * cameras and microphones. This lets the robot record, at capture time, the
 * basis on which a capture was permitted, bound to the specific capture and to
 * the robot's identity, and lets a bystander (or their device) sign a consent
 * token bound to that one capture. Only hashes and a consent basis are stored,
 * never an image or a bystander's identifying data, so the evidence is
 * verifiable without retaining anyone's biometrics.
 *
 * A bystander consent token is signed by the bystander over the hash of the
 * capture and the robot's DID, so it verifies only against the capture it was
 * given for and cannot be replayed to a different recording. A bystander-consent
 * evidence credential is signed by the robot, binding the capture hash to a
 * consent basis (an explicit token, posted notice, a legitimate interest, or a
 * redaction that was applied) and, when the basis is explicit consent, to the
 * tokens that cover it.
 *
 * This is the open layer: the cryptographic binding of a consent basis to a
 * capture, and its verification, holding only hashes. On-device biometric
 * detection and redaction, and managed consent-registry orchestration, are out
 * of scope for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const CONSENT_EVIDENCE_TYPE = 'BystanderConsentEvidence';
export const CONSENT_TOKEN_TYPE = 'BystanderConsentToken';

// Accepted consent bases. Implementers MAY use additional values, but these are
// the interoperable set a verifier can rely on.
export const CONSENT_BASES: ReadonlySet<string> = new Set([
  'explicit-consent',
  'posted-notice',
  'legitimate-interest',
  'redacted',
]);

function mb64(b: Uint8Array): string {
  return 'u' + Buffer.from(b).toString('base64url');
}

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

/** Return the multibase (base64url) SHA-256 of a raw capture. */
export function hashCapture(capture: Uint8Array): string {
  if (!(capture instanceof Uint8Array) && !Buffer.isBuffer(capture)) {
    throw new RoboticsError('capture must be bytes');
  }
  return mb64(crypto.createHash('sha256').update(Buffer.from(capture)).digest());
}

/**
 * A privacy-preserving reference to a token: its proof value.
 */
function tokenRef(token: Record<string, unknown>): string {
  const proof = (token.proof ?? {}) as Record<string, unknown>;
  const ref = proof.proofValue;
  if (!ref || typeof ref !== 'string') {
    throw new RoboticsError('consent token is missing a proof value');
  }
  return ref;
}

function withinWindow(credential: Record<string, unknown>, now?: Date): boolean {
  const at = now ?? new Date();
  const start = parseIso(credential.validFrom);
  const end = parseIso(credential.validUntil);
  if (start !== undefined && at.getTime() < start.getTime()) return false;
  if (end !== undefined && at.getTime() > end.getTime()) return false;
  return true;
}

/**
 * Verify a typed consent credential: the expected type is present and the proof
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
// Bystander consent token (signed by the bystander, bound to one capture)
// ---------------------------------------------------------------------------

export interface BuildConsentTokenOptions {
  bystanderDid: string;
  captureHash: string;
  robotDid: string;
  scope?: string;
  grantedAt?: Date;
  validSeconds?: number;
}

/**
 * Build a signed BystanderConsentToken: a bystander grants consent for a
 * specific capture (named by `captureHash`) by a specific robot (`robotDid`),
 * signed by the bystander. Binding the token to the capture hash means it cannot
 * be replayed to a different recording. `scope` optionally records what the
 * consent covers.
 */
export async function buildConsentToken(
  bystanderSigner: Signer,
  opts: BuildConsentTokenOptions
): Promise<Record<string, unknown>> {
  if (!opts.bystanderDid || !opts.captureHash || !opts.robotDid) {
    throw new RoboticsError('bystanderDid, captureHash, and robotDid are required');
  }
  const issued = opts.grantedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.bystanderDid,
    captureHash: opts.captureHash,
    robotDid: opts.robotDid,
  };
  if (opts.scope !== undefined) {
    subject.scope = opts.scope;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', CONSENT_TOKEN_TYPE],
    issuer: opts.bystanderDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return bystanderSigner.attachProof(credential);
}

/**
 * Verify a BystanderConsentToken: the bystander's proof, that the issuer is the
 * bystander, and that the token is bound to this capture and this robot and is
 * within its window. Returns { ok, subject }.
 */
export function verifyConsentToken(
  token: Record<string, unknown>,
  bystanderPublicKey: crypto.KeyObject,
  opts: { captureHash: string; robotDid: string; now?: Date }
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(token, bystanderPublicKey, CONSENT_TOKEN_TYPE);
  if (!ok) return { ok: false };
  if (token.issuer !== subject.id) return { ok: false };
  if (subject.captureHash !== opts.captureHash || subject.robotDid !== opts.robotDid) {
    return { ok: false };
  }
  if (!withinWindow(token, opts.now)) return { ok: false };
  return { ok: true, subject };
}

// ---------------------------------------------------------------------------
// Bystander-consent evidence (signed by the robot)
// ---------------------------------------------------------------------------

export interface BuildConsentEvidenceOptions {
  robotDid: string;
  captureHash: string;
  basis: string;
  consentTokens?: Array<Record<string, unknown>>;
  redactionHash?: string;
  attestedAt?: Date;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Build a signed BystanderConsentEvidence credential: the robot records that a
 * capture (named by `captureHash`) was permitted on `basis`, one of
 * CONSENT_BASES. When the basis is explicit consent, `consentTokens` are the
 * bystander tokens that cover it, and the evidence commits to them by their
 * proof value (never embedding a bystander's identifying data). `redactionHash`
 * optionally records that a redacted output was produced. Signed by the robot.
 */
export async function buildConsentEvidence(
  robotSigner: Signer,
  opts: BuildConsentEvidenceOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid || !opts.captureHash) {
    throw new RoboticsError('robotDid and captureHash are required');
  }
  if (!CONSENT_BASES.has(opts.basis)) {
    const allowed = [...CONSENT_BASES].sort().join(', ');
    throw new RoboticsError(`basis must be one of ${allowed}, got ${opts.basis}`);
  }
  const tokens = opts.consentTokens ?? [];
  if (opts.basis === 'explicit-consent' && tokens.length === 0) {
    throw new RoboticsError('explicit-consent basis requires at least one consent token');
  }

  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    captureHash: opts.captureHash,
    basis: opts.basis,
  };
  if (tokens.length > 0) {
    subject.consentTokenRefs = tokens.map((t) => tokenRef(t));
  }
  if (opts.redactionHash !== undefined) {
    subject.redactionHash = opts.redactionHash;
  }

  const start = opts.validFrom ?? opts.attestedAt ?? new Date();
  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', CONSENT_EVIDENCE_TYPE],
    issuer: opts.robotDid,
    validFrom: iso(start),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(start.getTime() + opts.validSeconds * 1000));
  }
  return robotSigner.attachProof(credential);
}

/**
 * Verify a BystanderConsentEvidence credential: the robot's proof, that the
 * issuer is the robot, and that the basis is accepted. When `capture` is
 * supplied, its hash must reproduce the attested capture hash. When
 * `consentTokens` and `bystanderKeys` (a map of bystander DID to key) are
 * supplied, every token must verify, be bound to this capture and this robot,
 * and match a committed reference, and an explicit-consent evidence must carry
 * at least one token. Returns { ok, subject }.
 */
export function verifyConsentEvidence(
  evidence: Record<string, unknown>,
  robotPublicKey: crypto.KeyObject,
  opts: {
    capture?: Uint8Array;
    consentTokens?: Array<Record<string, unknown>>;
    bystanderKeys?: Record<string, crypto.KeyObject>;
    now?: Date;
  } = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(evidence, robotPublicKey, CONSENT_EVIDENCE_TYPE);
  if (!ok) return { ok: false };
  if (evidence.issuer !== subject.id) return { ok: false };
  if (typeof subject.basis !== 'string' || !CONSENT_BASES.has(subject.basis)) {
    return { ok: false };
  }
  const captureHash = subject.captureHash;
  if (!captureHash || typeof captureHash !== 'string') return { ok: false };

  if (opts.capture !== undefined) {
    try {
      if (hashCapture(opts.capture) !== captureHash) return { ok: false };
    } catch (e) {
      if (e instanceof RoboticsError) return { ok: false };
      throw e;
    }
  }

  const refs = (subject.consentTokenRefs as string[] | undefined) ?? [];
  if (subject.basis === 'explicit-consent' && refs.length === 0) return { ok: false };

  if (opts.consentTokens !== undefined && opts.bystanderKeys !== undefined) {
    for (const token of opts.consentTokens) {
      const issuer = token.issuer;
      const key = typeof issuer === 'string' ? opts.bystanderKeys[issuer] : undefined;
      if (key === undefined) return { ok: false };
      const tokRes = verifyConsentToken(token, key, {
        captureHash,
        robotDid: subject.id as string,
        now: opts.now,
      });
      if (!tokRes.ok || !refs.includes(tokenRef(token))) return { ok: false };
    }
  }

  return { ok: true, subject };
}
