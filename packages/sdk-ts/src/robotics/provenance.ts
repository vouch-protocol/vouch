/**
 * Model-and-config provenance attestation for robots (Phase 5.2), TypeScript.
 *
 * Mirrors `vouch/robotics/provenance.py` with byte-identical output. A
 * ModelProvenanceAttestation is an eddsa-jcs-2022 VC recording the VLA model
 * name, weights hash, safety policy, and a configHash computed over the
 * JCS-canonical config so any verifier reproduces it. Re-signable on an OTA
 * update via `supersedes`, forming a tamper-evident chain.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import { canonicalize } from '../jcs';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

export const MODEL_PROVENANCE_TYPE = 'ModelProvenanceAttestation';

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Multibase SHA-256 of the JCS-canonical config object. */
export function configHash(config: Record<string, unknown>): string {
  const digest = crypto.createHash('sha256').update(canonicalize(config)).digest();
  return 'u' + digest.toString('base64url');
}

export interface BuildProvenanceOptions {
  robotDid: string;
  modelName: string;
  weightsHash: string;
  safetyPolicy: string;
  config?: Record<string, unknown>;
  version?: string;
  supersedes?: string;
  validSeconds?: number;
  validFrom?: Date;
}

/** Build a signed ModelProvenanceAttestation for the software on a robot. */
export async function buildProvenanceAttestation(
  signer: Signer,
  opts: BuildProvenanceOptions
): Promise<Record<string, unknown>> {
  const issued = opts.validFrom ?? new Date();
  const vla: Record<string, unknown> = {
    modelName: opts.modelName,
    weightsHash: opts.weightsHash,
    safetyPolicy: opts.safetyPolicy,
  };
  if (opts.version !== undefined) vla.version = opts.version;
  if (opts.config !== undefined) vla.configHash = configHash(opts.config);

  const subject: Record<string, unknown> = { id: opts.robotDid, vla };
  if (opts.supersedes !== undefined) subject.supersedes = opts.supersedes;

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', MODEL_PROVENANCE_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

/**
 * Verify a ModelProvenanceAttestation. When `config` is supplied, also check
 * that its hash matches the recorded configHash.
 */
export function verifyProvenanceAttestation(
  attestation: Record<string, unknown>,
  publicKey: crypto.KeyObject,
  config?: Record<string, unknown>
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = attestation.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(MODEL_PROVENANCE_TYPE)) return { ok: false };

  try {
    if (!verifyProof(attestation, publicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (attestation.credentialSubject ?? {}) as Record<string, unknown>;
  if (config !== undefined) {
    const vla = (subject.vla ?? {}) as Record<string, unknown>;
    if (vla.configHash !== configHash(config)) return { ok: false };
  }
  return { ok: true, subject };
}
