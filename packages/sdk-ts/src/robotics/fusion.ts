/**
 * Fused-sensor provenance (TypeScript).
 *
 * Mirrors `vouch/robotics/fusion.py` with byte-identical output. Perception
 * provenance signs individual sensor frames. A robot rarely acts on one frame,
 * though: it fuses many frames, from cameras, lidar, radar, and other sensors,
 * into a single world model, an object set, an occupancy grid, or a pose
 * estimate, and acts on that. This module binds a fused output to the exact set
 * of input frames that produced it and the fusion method that produced it,
 * signed by the robot, so a manipulated fusion result or a silently dropped or
 * substituted input is detectable at the provenance layer.
 *
 * A fused-perception attestation carries the hash of the fused output, an
 * ordered list of the input frame hashes, a digest over those inputs, and a
 * fusion method identifier, signed by the robot. A verifier reproduces the input
 * digest from the listed inputs and, when it holds the raw fused output,
 * reproduces its hash, so the attestation commits to exactly those inputs and
 * that output. Checking each listed input against the robot's signed perception
 * log confirms every fused input traces to a frame the robot actually recorded.
 *
 * The fused output and the frames themselves are not carried here, only their
 * hashes, so the attestation stays small and the raw data can live wherever the
 * deployment keeps it. This is the open layer: the robot signs the binding of a
 * fused output to its inputs in software, reusing the perception frame hashes.
 * Hardware sensor attestation and managed sensor-fusion orchestration are out of
 * scope for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const FUSED_PERCEPTION_TYPE = 'FusedPerceptionAttestation';

function mb64(b: Uint8Array): string {
  return 'u' + Buffer.from(b).toString('base64url');
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Return the multibase (base64url) SHA-256 of a raw fused output. */
export function hashFusedOutput(output: Uint8Array): string {
  if (!(output instanceof Uint8Array) && !Buffer.isBuffer(output)) {
    throw new RoboticsError('output must be bytes');
  }
  return mb64(crypto.createHash('sha256').update(Buffer.from(output)).digest());
}

/**
 * Return a deterministic multibase digest over an ordered list of input frame
 * hashes. The digest commits to the exact inputs and their order, so adding,
 * removing, or reordering an input changes it. Reproduced byte-identically
 * across language SDKs.
 */
export function fusionInputsDigest(inputFrameHashes: string[]): string {
  if (!inputFrameHashes || inputFrameHashes.length === 0) {
    throw new RoboticsError('inputFrameHashes must be a non-empty list');
  }
  for (const h of inputFrameHashes) {
    if (!h || typeof h !== 'string') {
      throw new RoboticsError('each input frame hash must be a non-empty string');
    }
  }
  const joined = Buffer.from(inputFrameHashes.join('\n'), 'utf-8');
  return mb64(crypto.createHash('sha256').update(joined).digest());
}

export interface BuildFusedAttestationOptions {
  robotDid: string;
  fusionMethod: string;
  inputFrameHashes: string[];
  fusedOutput?: Uint8Array;
  fusedOutputHash?: string;
  capturedAt?: Date;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Build a signed FusedPerceptionAttestation: the robot attests that a fused
 * output was produced by `fusionMethod` from the frames named in
 * `inputFrameHashes`. Provide either the raw `fusedOutput` (it is hashed) or a
 * precomputed `fusedOutputHash`. The attestation carries a digest over the
 * ordered inputs, so the set of inputs is tamper-evident.
 */
export async function buildFusedAttestation(
  signer: Signer,
  opts: BuildFusedAttestationOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid) {
    throw new RoboticsError('robotDid is required');
  }
  if (!opts.fusionMethod) {
    throw new RoboticsError('fusionMethod is required');
  }
  if (!opts.inputFrameHashes || opts.inputFrameHashes.length === 0) {
    throw new RoboticsError('inputFrameHashes must be a non-empty list');
  }
  if (opts.fusedOutput !== undefined && opts.fusedOutputHash !== undefined) {
    throw new RoboticsError('provide either fusedOutput or fusedOutputHash, not both');
  }
  let fusedOutputHash = opts.fusedOutputHash;
  if (opts.fusedOutput !== undefined) {
    fusedOutputHash = hashFusedOutput(opts.fusedOutput);
  }
  if (!fusedOutputHash) {
    throw new RoboticsError('fusedOutput or fusedOutputHash is required');
  }

  const issued = opts.validFrom ?? new Date();
  const captured = opts.capturedAt ?? issued;
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    fusionMethod: opts.fusionMethod,
    fusedOutputHash,
    inputFrameHashes: [...opts.inputFrameHashes],
    inputsDigest: fusionInputsDigest(opts.inputFrameHashes),
    capturedAt: iso(captured),
  };

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', FUSED_PERCEPTION_TYPE],
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
 * Verify a FusedPerceptionAttestation: the robot's proof, that the digest over
 * the listed inputs reproduces the attested `inputsDigest` (so the inputs are
 * internally consistent and tamper-evident), and, when the raw `fusedOutput` is
 * supplied, that its hash reproduces the attested `fusedOutputHash`. Returns
 * { ok, subject }.
 */
export function verifyFusedAttestation(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject,
  opts: { fusedOutput?: Uint8Array } = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(FUSED_PERCEPTION_TYPE)) return { ok: false };

  if (publicKey === null || publicKey === undefined) return { ok: false };
  try {
    if (!verifyProof(credential, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const inputs = subject.inputFrameHashes;
  if (!subject.fusedOutputHash || !Array.isArray(inputs) || inputs.length === 0) {
    return { ok: false };
  }
  try {
    if (fusionInputsDigest(inputs as string[]) !== subject.inputsDigest) return { ok: false };
  } catch (e) {
    if (e instanceof RoboticsError) return { ok: false };
    throw e;
  }

  if (opts.fusedOutput !== undefined) {
    try {
      if (hashFusedOutput(opts.fusedOutput) !== subject.fusedOutputHash) return { ok: false };
    } catch (e) {
      if (e instanceof RoboticsError) return { ok: false };
      throw e;
    }
  }

  return { ok: true, subject };
}

/**
 * Confirm every input frame the attestation names was actually recorded in the
 * robot's perception log. Returns { ok, missing }, where `missing` lists the
 * input frame hashes that do not appear as a recorded frame, so a dropped or
 * substituted fused input is named rather than hidden.
 */
export function verifyFusionInputs(
  credential: Record<string, unknown>,
  logEntries: Array<Record<string, unknown>>
): { ok: boolean; missing: string[] } {
  const recorded = new Set<string>();
  for (const e of logEntries) {
    const fh = e.frameHash;
    if (typeof fh === 'string' && fh) recorded.add(fh);
  }
  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const inputs = (subject.inputFrameHashes as string[] | undefined) ?? [];
  const missing = inputs.filter((h) => !recorded.has(h));
  return { ok: missing.length === 0, missing };
}
