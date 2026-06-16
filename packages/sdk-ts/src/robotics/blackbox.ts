/**
 * Robot black-box log and kill-switch credential (Phase 5.5), TypeScript.
 *
 * Mirrors `vouch/robotics/blackbox.py`. The black box is an append-only,
 * AES-256-GCM-encrypted, hash-linked event log: payloads are confidential, the
 * chain is tamper-evident without the key, and only the key opens the payloads.
 * The encrypted blob is `nonce(12) || ciphertext || tag(16)`, the same layout
 * Python's AESGCM produces, so a Python-written entry decrypts here and vice
 * versa, and the JCS hash chain verifies across languages.
 *
 * The kill-switch credential is a verifiable emergency stop proving who issued
 * it and, with an authority allowlist, that only an attested authority can
 * trigger it.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import { canonicalize } from '../jcs';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

export const KILLSWITCH_TYPE = 'KillSwitchCredential';
export const BLACKBOX_VERSION = '1.0';
export const EMERGENCY_STOP = 'emergency_stop';
export const GENESIS_PREV_HASH = 'u' + Buffer.alloc(32).toString('base64url');

export class BlackBoxError extends Error {}

function mb64(b: Uint8Array): string {
  return 'u' + Buffer.from(b).toString('base64url');
}

function unmb64(s: string): Buffer {
  if (!s.startsWith('u')) throw new BlackBoxError("expected multibase 'u' prefix");
  return Buffer.from(s.slice(1), 'base64url');
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function entryHash(body: Record<string, unknown>): string {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) if (k !== 'entryHash') clean[k] = v;
  return mb64(crypto.createHash('sha256').update(canonicalize(clean)).digest());
}

/** Append-only, encrypted, hash-linked event log. `key` is 32 bytes (AES-256). */
export class BlackBoxLog {
  readonly genesisPrevHash: string;
  private key: Buffer;
  private _entries: Array<Record<string, unknown>> = [];
  private _head: string;

  constructor(key: Uint8Array, genesisPrevHash: string = GENESIS_PREV_HASH) {
    if (key.length !== 32) throw new BlackBoxError('key must be 32 bytes (AES-256)');
    this.key = Buffer.from(key);
    this.genesisPrevHash = genesisPrevHash;
    this._head = genesisPrevHash;
  }

  append(
    event: string,
    payload: Record<string, unknown>,
    opts: { timestamp?: string } = {}
  ): Record<string, unknown> {
    const nonce = crypto.randomBytes(12);
    const plaintext = Buffer.from(canonicalize(payload));
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonce);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const body: Record<string, unknown> = {
      version: BLACKBOX_VERSION,
      seq: this._entries.length,
      timestamp: opts.timestamp ?? iso(new Date()),
      event,
      ciphertext: mb64(Buffer.concat([nonce, ct, tag])),
      prevHash: this._head,
    };
    body.entryHash = entryHash(body);
    this._entries.push(body);
    this._head = body.entryHash as string;
    return body;
  }

  head(): string {
    return this._head;
  }

  entries(): Array<Record<string, unknown>> {
    return this._entries.map((e) => ({ ...e }));
  }

  openEntry(entry: Record<string, unknown>): Record<string, unknown> {
    return openEntry(entry, this.key);
  }
}

/** Decrypt a black-box entry payload. Returns the original payload object. */
export function openEntry(entry: Record<string, any>, key: Uint8Array): Record<string, unknown> {
  const blob = unmb64(entry.ciphertext);
  const nonce = blob.subarray(0, 12);
  const ct = blob.subarray(12, blob.length - 16);
  const tag = blob.subarray(blob.length - 16);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), nonce);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(pt.toString('utf8'));
  } catch (e) {
    throw new BlackBoxError(`decryption failed: ${(e as Error).message}`);
  }
}

/** Verify the hash chain over (encrypted) entries. Tamper-evident without the key. */
export function verifyBlackboxChain(
  entries: Array<Record<string, any>>,
  genesisPrevHash: string = GENESIS_PREV_HASH
): { ok: boolean; reason?: string } {
  let prev = genesisPrevHash;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (entry.seq !== i) return { ok: false, reason: `entry ${i} seq mismatch` };
    if (entry.prevHash !== prev) return { ok: false, reason: `entry ${i} prevHash does not link` };
    if (entry.entryHash !== entryHash(entry)) {
      return { ok: false, reason: `entry ${i} entryHash mismatch (tampered)` };
    }
    prev = entry.entryHash;
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Kill-switch credential
// ---------------------------------------------------------------------------

export interface BuildKillswitchOptions {
  target: string;
  reason: string;
  command?: string;
  scope?: string[];
  validSeconds?: number;
  validFrom?: Date;
}

/** Build a signed KillSwitchCredential proving who issued an emergency stop. */
export async function buildKillswitchCredential(
  authoritySigner: Signer,
  opts: BuildKillswitchOptions
): Promise<Record<string, unknown>> {
  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.target,
    command: opts.command ?? EMERGENCY_STOP,
    reason: opts.reason,
    issuedBy: authoritySigner.getDid(),
  };
  if (opts.scope !== undefined) subject.scope = [...opts.scope];

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', KILLSWITCH_TYPE],
    issuer: authoritySigner.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return authoritySigner.attachProof(credential);
}

/**
 * Verify a KillSwitchCredential. When `trustedAuthorities` is supplied, the
 * issuer DID MUST be in it, so only an attested authority can trigger the stop.
 */
export function verifyKillswitchCredential(
  credential: Record<string, any>,
  publicKey: crypto.KeyObject,
  opts: { trustedAuthorities?: Set<string> } = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  if (!types.includes(KILLSWITCH_TYPE)) return { ok: false };
  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }
  if (opts.trustedAuthorities && !opts.trustedAuthorities.has(credential.issuer)) {
    return { ok: false };
  }
  return { ok: true, subject: credential.credentialSubject ?? {} };
}
