/**
 * Robot accountable safety record (TypeScript).
 *
 * Mirrors `vouch/robotics/safety_record.py` with byte-identical output. Where
 * the black box is an encrypted flight recorder for confidential telemetry, the
 * safety ledger is its accountable, readable counterpart: an append-only,
 * hash-linked log of the safety-relevant events in a robot's life (incidents,
 * near-misses, manual overrides, kill-switch triggers, envelope breaches). The
 * entries are plaintext on purpose, because their value is that an owner, an
 * insurer, or a regulator can read and trust them. The chain is tamper-evident,
 * so no entry can be altered or removed without detection.
 *
 * A RobotSafetyRecordCredential is an eddsa-jcs-2022 VC that summarizes a stretch
 * of the ledger (counts by event type and by severity, the period covered, and
 * the ledger head hash that anchors it) into one portable, signed artifact that
 * travels with the robot across owners and across organizations. The ledger
 * reuses the black-box chain semantics so the two logs verify the same way.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { GENESIS_PREV_HASH, entryHash, verifyBlackboxChain } from './blackbox';
import { RoboticsError } from './identity';

export const SAFETY_RECORD_TYPE = 'RobotSafetyRecordCredential';
export const SAFETY_LOG_VERSION = '1.0';

// Standard safety event types. Implementers MAY use additional types, but these
// are the interoperable set a verifier and an insurer can rely on.
export const EVENT_TYPES: ReadonlySet<string> = new Set([
  'incident',
  'near_miss',
  'manual_override',
  'kill_switch',
  'envelope_breach',
  'maintenance',
]);

// Severity bands, ordered from least to most serious.
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export interface SafetySummary {
  eventCounts: Record<string, number>;
  severityCounts: Record<string, number>;
  totalEvents: number;
  logHead?: string;
}

export interface AppendEventOptions {
  severity?: Severity;
  details?: Record<string, unknown>;
  actor?: string;
  timestamp?: string;
}

/**
 * Append-only, plaintext, hash-linked safety event ledger.
 *
 * Each appended entry carries a sequence number, a timestamp, the event type, a
 * severity, optional details, and the hash of the previous entry, so the log is
 * tamper-evident. Unlike the black box, entries are not encrypted: a safety
 * record is meant to be read and trusted by third parties.
 */
export class SafetyEventLog {
  readonly genesisPrevHash: string;
  private _entries: Array<Record<string, unknown>> = [];
  private _head: string;

  constructor(genesisPrevHash: string = GENESIS_PREV_HASH) {
    this.genesisPrevHash = genesisPrevHash;
    this._head = genesisPrevHash;
  }

  /** Append one safety event and return the new entry. */
  append(eventType: string, opts: AppendEventOptions = {}): Record<string, unknown> {
    const severity = opts.severity ?? 'info';
    if (!EVENT_TYPES.has(eventType)) {
      const allowed = [...EVENT_TYPES].sort().join(', ');
      throw new RoboticsError(`eventType must be one of ${allowed}, got ${eventType}`);
    }
    if (!(SEVERITIES as readonly string[]).includes(severity)) {
      throw new RoboticsError(`severity must be one of ${SEVERITIES.join(', ')}, got ${severity}`);
    }

    const body: Record<string, unknown> = {
      version: SAFETY_LOG_VERSION,
      seq: this._entries.length,
      timestamp: opts.timestamp ?? iso(new Date()),
      eventType,
      severity,
      prevHash: this._head,
    };
    if (opts.details !== undefined) body.details = opts.details;
    if (opts.actor !== undefined) body.actor = opts.actor;
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

  /** Produce a summary object for embedding in a safety-record credential. */
  summarize(): SafetySummary {
    return summarizeEntries(this._entries, this._head);
  }
}

/** Verify the hash chain over the ledger entries. Tamper-evident. */
export function verifySafetyLog(
  entries: Array<Record<string, unknown>>,
  genesisPrevHash: string = GENESIS_PREV_HASH
): { ok: boolean; reason?: string } {
  return verifyBlackboxChain(entries, genesisPrevHash);
}

/**
 * Summarize ledger entries into counts by event type and by severity, the total
 * event count, and (when supplied) the ledger head hash that anchors the summary
 * to a specific chain state. Event counts are keyed by sorted event type;
 * severity counts follow the info..critical order.
 */
export function summarizeEntries(
  entries: Array<Record<string, unknown>>,
  head?: string
): SafetySummary {
  const eventCounts: Record<string, number> = {};
  for (const t of [...EVENT_TYPES].sort()) eventCounts[t] = 0;
  const severityCounts: Record<string, number> = {};
  for (const s of SEVERITIES) severityCounts[s] = 0;

  for (const e of entries) {
    const et = e.eventType;
    const sv = e.severity;
    if (typeof et === 'string' && et in eventCounts) {
      eventCounts[et] += 1;
    }
    if (typeof sv === 'string' && sv in severityCounts) {
      severityCounts[sv] += 1;
    }
  }

  const summary: SafetySummary = {
    eventCounts,
    severityCounts,
    totalEvents: entries.length,
  };
  if (head !== undefined) {
    summary.logHead = head;
  }
  return summary;
}

export interface BuildSafetyRecordOptions {
  robotDid: string;
  summary: Record<string, unknown>;
  periodStart?: Date;
  periodEnd?: Date;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Build a signed RobotSafetyRecordCredential summarizing a robot's safety
 * ledger. The issuer (an owner, an auditor, or the robot itself) attests the
 * summary; `summary` is produced by SafetyEventLog.summarize or summarizeEntries.
 */
export async function buildSafetyRecord(
  signer: Signer,
  opts: BuildSafetyRecordOptions
): Promise<Record<string, unknown>> {
  validateSafetySummary(opts.summary);

  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = { id: opts.robotDid, ...opts.summary };
  if (opts.periodStart !== undefined || opts.periodEnd !== undefined) {
    const period: Record<string, unknown> = {};
    if (opts.periodStart !== undefined) period.start = iso(opts.periodStart);
    if (opts.periodEnd !== undefined) period.end = iso(opts.periodEnd);
    subject.period = period;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', SAFETY_RECORD_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

/** Structural validation of a safety summary. Throws RoboticsError if malformed. */
export function validateSafetySummary(summary: Record<string, unknown>): void {
  if (summary === null || typeof summary !== 'object' || Array.isArray(summary)) {
    throw new RoboticsError('summary must be an object');
  }
  for (const name of ['eventCounts', 'severityCounts'] as const) {
    const block = summary[name];
    if (block === null || typeof block !== 'object' || Array.isArray(block)) {
      throw new RoboticsError(`summary.${name} must be an object`);
    }
    for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
      if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
        throw new RoboticsError(`summary.${name}[${k}] must be a non-negative integer`);
      }
    }
  }
  const total = summary.totalEvents;
  if (typeof total !== 'number' || !Number.isInteger(total) || total < 0) {
    throw new RoboticsError('summary.totalEvents must be a non-negative integer');
  }
}

/**
 * Verify a RobotSafetyRecordCredential: the issuer's proof and the structural
 * validity of the embedded summary. Returns { ok, subject }.
 */
export function verifySafetyRecord(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(SAFETY_RECORD_TYPE)) return { ok: false };

  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  try {
    validateSafetySummary(subject);
  } catch (e) {
    if (e instanceof RoboticsError) return { ok: false };
    throw e;
  }
  return { ok: true, subject };
}
