/**
 * Cross-embodiment identity continuity (TypeScript): one accountable agent
 * across robot bodies.
 *
 * Mirrors `vouch/robotics/embodiment.py` with byte-identical output. An AI agent
 * (a "mind": a policy with its own Vouch identity) can run on one robot body
 * today and a different body tomorrow. This makes that continuous and
 * accountable. An embodiment credential binds the agent identity to a specific
 * body (a hardware-rooted robot identity) and that body's hardware root for a
 * period, signed by the agent's own persistent key. Linking each embodiment to
 * the previous forms a continuity chain a verifier walks to confirm the same
 * accountable agent persisted across bodies, re-binding to each body's hardware
 * root as it moved. A fork check confirms the agent was never actively embodied
 * in two bodies at once.
 *
 * This is the inverse of the ownership custody chain: there one body passes
 * between owners; here one mind passes between bodies, and the constant that
 * signs every link is the agent identity itself.
 *
 * This is the open layer: plain signed embodiment credentials, continuity-chain
 * verification, and software fork detection. Managed key custody and fleet-scale
 * migration are out of scope for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const EMBODIMENT_TYPE = 'AgentEmbodimentCredential';

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
 * Verify a typed embodiment credential: the expected type is present and the
 * proof verifies under `publicKey`. Returns { ok, subject }.
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
// Embodiment credential + continuity chain
// ---------------------------------------------------------------------------

export interface BuildEmbodimentOptions {
  agentDid: string;
  bodyDid: string;
  bodyHardwareRoot: string;
  fromBody?: string;
  embodiedAt?: Date;
  validSeconds?: number;
}

/**
 * Build a signed embodiment credential: the agent `agentDid` authorizes running
 * on `bodyDid`, re-binding to that body's hardware root `bodyHardwareRoot`.
 * Signed by the agent's own persistent key, so the whole continuity chain is
 * signed by one accountable identity. `fromBody` links this embodiment to the
 * body the agent left, forming the chain. `validSeconds`, when given, bounds the
 * active window (used by fork detection).
 */
export async function buildEmbodiment(
  agentSigner: Signer,
  opts: BuildEmbodimentOptions
): Promise<Record<string, unknown>> {
  if (!opts.agentDid || !opts.bodyDid || !opts.bodyHardwareRoot) {
    throw new RoboticsError('agentDid, bodyDid, and bodyHardwareRoot are required');
  }
  const issued = opts.embodiedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.agentDid,
    body: opts.bodyDid,
    bodyHardwareRoot: opts.bodyHardwareRoot,
  };
  if (opts.fromBody !== undefined) {
    subject.fromBody = opts.fromBody;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', EMBODIMENT_TYPE],
    issuer: opts.agentDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return agentSigner.attachProof(credential);
}

/**
 * Verify an embodiment credential: the agent's proof and that the issuer is the
 * agent itself (a mind authorizes its own embodiment). Returns { ok, subject }.
 */
export function verifyEmbodiment(
  credential: Record<string, unknown>,
  agentPublicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(credential, agentPublicKey, EMBODIMENT_TYPE);
  if (!ok) return { ok: false };
  if (!subject.body || !subject.bodyHardwareRoot) return { ok: false };
  if (credential.issuer !== subject.id) return { ok: false };
  return { ok: true, subject };
}

export interface VerifyContinuityChainOptions {
  originBody?: string;
}

/**
 * Verify an ordered list of embodiment credentials forms a valid continuity
 * chain for one agent: every link verifies under the SAME agent key (the
 * persistent mind), each link's `fromBody` matches the previous link's `body`,
 * and (when given) the first `fromBody` is `originBody`. Returns
 * { ok, currentBody }.
 */
export function verifyContinuityChain(
  embodiments: Array<Record<string, unknown>>,
  agentPublicKey: crypto.KeyObject,
  opts: VerifyContinuityChainOptions = {}
): { ok: boolean; currentBody?: string } {
  let expectedFrom = opts.originBody;
  let currentBody: string | undefined = opts.originBody;
  for (const embodiment of embodiments) {
    const { ok, subject } = verifyEmbodiment(embodiment, agentPublicKey);
    if (!ok || subject === undefined) return { ok: false };
    if (expectedFrom !== undefined && subject.fromBody !== expectedFrom) return { ok: false };
    currentBody = subject.body as string;
    expectedFrom = currentBody;
  }
  return { ok: true, currentBody };
}

// ---------------------------------------------------------------------------
// Fork detection (a mind cannot be actively embodied in two bodies at once)
// ---------------------------------------------------------------------------

export interface CheckNoForkConflict {
  bodyA: string;
  bodyB: string;
}

/**
 * Half-open intervals [start, end); a missing end is +infinity. A clean handover
 * sets one window's end to the next window's start, which does not overlap.
 */
function overlaps(
  startA: Date,
  endA: Date | undefined,
  startB: Date,
  endB: Date | undefined
): boolean {
  const aBeforeB = endA !== undefined && endA.getTime() <= startB.getTime();
  const bBeforeA = endB !== undefined && endB.getTime() <= startA.getTime();
  return !(aBeforeB || bBeforeA);
}

/**
 * Confirm no two embodiments place the agent in different bodies with
 * overlapping active windows. Each embodiment is active from `validFrom` to
 * `validUntil` (a missing `validUntil` is treated as open-ended). Two
 * embodiments on different bodies whose windows overlap are a fork. Returns
 * { ok, conflict } where conflict, when present, names the two conflicting
 * bodies.
 */
export function checkNoFork(
  embodiments: Array<Record<string, unknown>>
): { ok: boolean; conflict?: CheckNoForkConflict } {
  const windows: Array<{ body: string; start: Date; end: Date | undefined }> = [];
  for (const embodiment of embodiments) {
    const subject = (embodiment.credentialSubject ?? {}) as Record<string, unknown>;
    const body = subject.body;
    const start = parseIso(embodiment.validFrom);
    if (typeof body !== 'string' || start === undefined) return { ok: false };
    const end = parseIso(embodiment.validUntil); // undefined -> open-ended
    windows.push({ body, start, end });
  }

  for (let i = 0; i < windows.length; i++) {
    const wi = windows[i];
    for (let j = i + 1; j < windows.length; j++) {
      const wj = windows[j];
      if (wi.body === wj.body) continue;
      if (overlaps(wi.start, wi.end, wj.start, wj.end)) {
        return { ok: false, conflict: { bodyA: wi.body, bodyB: wj.body } };
      }
    }
  }
  return { ok: true };
}
