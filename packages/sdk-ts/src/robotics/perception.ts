/**
 * Robot perception provenance (TypeScript).
 *
 * Mirrors `vouch/robotics/perception.py` with byte-identical output. A robot's
 * cameras, lidar, radar, and microphones produce the evidence it acts on, and
 * that evidence is exactly what an operator wants to dispute after the fact.
 * This module lets a robot sign the provenance of each captured frame at
 * capture time: a record binding the frame's hash, the sensor that produced it,
 * the modality, the capture time, and the robot's DID. The records are
 * hash-linked into an append-only chain, so the sequence of what the robot
 * perceived is tamper-evident, and a signed attestation anchors a frame (or a
 * segment of frames, via the chain head) to the robot's key.
 *
 * The frames themselves are not carried here, only their hashes, so the log
 * stays small and the raw sensor data can live wherever the deployment keeps
 * it. A verifier with the frame recomputes its hash and checks it against the
 * record. This is the open layer: the robot signs frame hashes in software,
 * reusing the black-box chain semantics.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { GENESIS_PREV_HASH, entryHash, verifyBlackboxChain } from './blackbox';
import { RoboticsError } from './identity';

export const PERCEPTION_TYPE = 'PerceptionProvenanceCredential';
export const PERCEPTION_LOG_VERSION = '1.0';

// Standard sensor modalities. Implementers MAY use additional values, but these
// are the interoperable set a verifier can rely on.
export const MODALITIES: ReadonlySet<string> = new Set([
  'camera',
  'lidar',
  'radar',
  'depth',
  'audio',
  'thermal',
]);

function mb64(b: Uint8Array): string {
  return 'u' + Buffer.from(b).toString('base64url');
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Return the multibase (base64url) SHA-256 of a raw sensor frame. */
export function hashFrame(frame: Uint8Array): string {
  if (!(frame instanceof Uint8Array) && !Buffer.isBuffer(frame)) {
    throw new RoboticsError('frame must be bytes');
  }
  return mb64(crypto.createHash('sha256').update(Buffer.from(frame)).digest());
}

export interface RecordFrameOptions {
  sensorId: string;
  modality: string;
  frame?: Uint8Array;
  frameHash?: string;
  timestamp?: string;
}

/**
 * Append-only, hash-linked log of sensor-frame provenance records.
 *
 * Each entry carries a sequence number, a timestamp, the sensor id, the
 * modality, the frame hash, and the hash of the previous entry, so the sequence
 * of perceived frames is tamper-evident. The frames are not stored; only their
 * hashes are.
 */
export class PerceptionLog {
  readonly genesisPrevHash: string;
  private _entries: Array<Record<string, unknown>> = [];
  private _head: string;

  constructor(genesisPrevHash: string = GENESIS_PREV_HASH) {
    this.genesisPrevHash = genesisPrevHash;
    this._head = genesisPrevHash;
  }

  /**
   * Append one frame-provenance record and return it. Provide either the raw
   * `frame` (it is hashed) or a precomputed `frameHash`.
   */
  record(opts: RecordFrameOptions): Record<string, unknown> {
    const { sensorId, modality, frame, timestamp } = opts;
    let frameHash = opts.frameHash;

    if (!MODALITIES.has(modality)) {
      const allowed = [...MODALITIES].sort().join(', ');
      throw new RoboticsError(`modality must be one of ${allowed}, got ${modality}`);
    }
    if (!sensorId) {
      throw new RoboticsError('sensorId is required');
    }
    if (frame !== undefined && frameHash !== undefined) {
      throw new RoboticsError('provide either frame or frameHash, not both');
    }
    if (frame !== undefined) {
      frameHash = hashFrame(frame);
    }
    if (!frameHash) {
      throw new RoboticsError('frame or frameHash is required');
    }

    const body: Record<string, unknown> = {
      version: PERCEPTION_LOG_VERSION,
      seq: this._entries.length,
      timestamp: timestamp ?? iso(new Date()),
      sensorId,
      modality,
      frameHash,
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
}

/** Verify the hash chain over the perception log entries. Tamper-evident. */
export function verifyPerceptionLog(
  entries: Array<Record<string, unknown>>,
  genesisPrevHash: string = GENESIS_PREV_HASH
): { ok: boolean; reason?: string } {
  return verifyBlackboxChain(entries, genesisPrevHash);
}

export interface BuildPerceptionAttestationOptions {
  robotDid: string;
  sensorId: string;
  modality: string;
  frameHash: string;
  capturedAt?: Date;
  logHead?: string;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Build a signed PerceptionProvenanceCredential attesting that a robot's sensor
 * captured a specific frame. When `logHead` is supplied, the attestation also
 * anchors the segment of frames up to that chain head.
 */
export async function buildPerceptionAttestation(
  signer: Signer,
  opts: BuildPerceptionAttestationOptions
): Promise<Record<string, unknown>> {
  if (!MODALITIES.has(opts.modality)) {
    const allowed = [...MODALITIES].sort().join(', ');
    throw new RoboticsError(`modality must be one of ${allowed}, got ${opts.modality}`);
  }
  if (!opts.frameHash) {
    throw new RoboticsError('frameHash is required');
  }

  const issued = opts.validFrom ?? new Date();
  const captured = opts.capturedAt ?? issued;
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    sensorId: opts.sensorId,
    modality: opts.modality,
    frameHash: opts.frameHash,
    capturedAt: iso(captured),
  };
  if (opts.logHead !== undefined) {
    subject.logHead = opts.logHead;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', PERCEPTION_TYPE],
    issuer: opts.robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

/**
 * Verify a PerceptionProvenanceCredential: the robot's proof and, when the raw
 * `frame` is supplied, that its hash reproduces the attested frameHash. Returns
 * { ok, subject }.
 */
export function verifyPerceptionAttestation(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject,
  opts: { frame?: Uint8Array } = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(PERCEPTION_TYPE)) return { ok: false };

  if (publicKey === null || publicKey === undefined) return { ok: false };
  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const frameHash = subject.frameHash;
  const modality = subject.modality;
  if (
    typeof frameHash !== 'string' ||
    !frameHash ||
    typeof modality !== 'string' ||
    !MODALITIES.has(modality)
  ) {
    return { ok: false };
  }

  if (opts.frame !== undefined) {
    try {
      if (hashFrame(opts.frame) !== frameHash) return { ok: false };
    } catch (e) {
      if (e instanceof RoboticsError) return { ok: false };
      throw e;
    }
  }

  return { ok: true, subject };
}
