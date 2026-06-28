/**
 * Robot lifecycle (TypeScript): ownership transfer, key rotation, decommission.
 *
 * Mirrors `vouch/robotics/lifecycle.py` with byte-identical output. A robot
 * outlives its first owner. It is commissioned, resold, repurposed, and
 * eventually scrapped, and each of those transitions needs to be
 * cryptographically accountable so the chain of custody, the key history, and
 * the end of life are verifiable.
 *
 *   - Ownership transfer: the current owner signs a transfer of the robot to a
 *     new owner. Linking each transfer to the previous one forms a chain of
 *     custody.
 *   - Key rotation: the robot's current key authorizes a new key, forming a key
 *     history (for a routine rotation or after a compromise).
 *   - Decommission: an owner or authority signs the retirement of the robot,
 *     after which a verifier should refuse to trust it.
 *
 * This is the open layer: plain, signed lifecycle credentials. Hosted ownership
 * registries, managed rotation pipelines, and fleet decommissioning services are
 * out of scope for the open layer.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { RoboticsError } from './identity';

export const OWNERSHIP_TRANSFER_TYPE = 'RobotOwnershipTransferCredential';
export const KEY_ROTATION_TYPE = 'RobotKeyRotationCredential';
export const DECOMMISSION_TYPE = 'RobotDecommissionCredential';

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Verify a typed lifecycle credential: the expected type is present and the
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
// Ownership transfer (chain of custody)
// ---------------------------------------------------------------------------

export interface BuildOwnershipTransferOptions {
  robotDid: string;
  toOwner: string;
  fromOwner?: string;
  prevTransferId?: string;
  transferredAt?: Date;
}

/**
 * Build a signed transfer of `robotDid` from the current owner to `toOwner`.
 * The signer is the current owner; `fromOwner` defaults to the signer's DID.
 * `prevTransferId` links this transfer to the previous one, forming a chain.
 */
export async function buildOwnershipTransfer(
  currentOwnerSigner: Signer,
  opts: BuildOwnershipTransferOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid || !opts.toOwner) {
    throw new RoboticsError('robotDid and toOwner are required');
  }
  const issued = opts.transferredAt ?? new Date();
  const seller = opts.fromOwner ?? currentOwnerSigner.getDid();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    fromOwner: seller,
    toOwner: opts.toOwner,
  };
  if (opts.prevTransferId !== undefined) {
    subject.prevTransferId = opts.prevTransferId;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', OWNERSHIP_TRANSFER_TYPE],
    issuer: currentOwnerSigner.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  return currentOwnerSigner.attachProof(credential);
}

/**
 * Verify a transfer: the current owner's proof and that the issuer is the
 * fromOwner (only the current owner can transfer the robot). Returns
 * { ok, subject }.
 */
export function verifyOwnershipTransfer(
  credential: Record<string, unknown>,
  currentOwnerPublicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(credential, currentOwnerPublicKey, OWNERSHIP_TRANSFER_TYPE);
  if (!ok) return { ok: false };
  if (!subject.toOwner || !subject.fromOwner) return { ok: false };
  if (credential.issuer !== subject.fromOwner) return { ok: false };
  return { ok: true, subject };
}

export interface VerifyCustodyChainOptions {
  originOwner?: string;
}

/**
 * Verify an ordered list of transfer credentials forms a valid chain of custody:
 * each transfer's proof verifies under the owner who signed it, every link's
 * toOwner matches the next link's fromOwner, and (when given) the first
 * fromOwner is `originOwner`. `publicKeys` maps an owner DID to its key.
 * Returns { ok, currentOwner }.
 */
export function verifyCustodyChain(
  transfers: Array<Record<string, unknown>>,
  publicKeys: Record<string, crypto.KeyObject>,
  opts: VerifyCustodyChainOptions = {}
): { ok: boolean; currentOwner?: string } {
  let expectedFrom = opts.originOwner;
  let currentOwner: string | undefined = opts.originOwner;
  for (const transfer of transfers) {
    const issuer = transfer.issuer;
    if (typeof issuer !== 'string' || !(issuer in publicKeys)) return { ok: false };
    const { ok, subject } = verifyOwnershipTransfer(transfer, publicKeys[issuer]);
    if (!ok || subject === undefined) return { ok: false };
    if (expectedFrom !== undefined && subject.fromOwner !== expectedFrom) return { ok: false };
    currentOwner = subject.toOwner as string;
    expectedFrom = currentOwner;
  }
  return { ok: true, currentOwner };
}

// ---------------------------------------------------------------------------
// Key rotation (key history)
// ---------------------------------------------------------------------------

export interface BuildKeyRotationOptions {
  robotDid: string;
  newKeyMultibase: string;
  reason?: string;
  rotatedAt?: Date;
}

/**
 * Build a key-rotation credential in which the robot's current (old) key
 * authorizes a new key. Signed by the old key, so anyone trusting the old key
 * can trust the new one.
 */
export async function buildKeyRotation(
  oldKeySigner: Signer,
  opts: BuildKeyRotationOptions
): Promise<Record<string, unknown>> {
  if (!opts.newKeyMultibase) {
    throw new RoboticsError('newKeyMultibase is required');
  }
  const issued = opts.rotatedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    previousKey: await oldKeySigner.getPublicKeyMultikey(),
    newKey: opts.newKeyMultibase,
  };
  if (opts.reason !== undefined) {
    subject.reason = opts.reason;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', KEY_ROTATION_TYPE],
    issuer: opts.robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  return oldKeySigner.attachProof(credential);
}

/**
 * Verify a key rotation: the OLD key signed it, binding the new key. Returns
 * { ok, subject } with `newKey` the authorized successor.
 */
export function verifyKeyRotation(
  credential: Record<string, unknown>,
  oldPublicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(credential, oldPublicKey, KEY_ROTATION_TYPE);
  if (!ok) return { ok: false };
  if (!subject.previousKey || !subject.newKey) return { ok: false };
  return { ok: true, subject };
}

/**
 * Verify an ordered list of key rotations forms a valid key history starting
 * from `originKeyMultibase`: each rotation's previousKey matches the current
 * key, and each is signed by the key it rotates from. `publicKeys` maps a key
 * multibase to the corresponding public key. Returns { ok, currentKey }.
 */
export function verifyKeyHistory(
  rotations: Array<Record<string, unknown>>,
  originKeyMultibase: string,
  publicKeys: Record<string, crypto.KeyObject>
): { ok: boolean; currentKey?: string } {
  let currentKey: string | undefined = originKeyMultibase;
  for (const rotation of rotations) {
    const subject = (rotation.credentialSubject ?? {}) as Record<string, unknown>;
    if (subject.previousKey !== currentKey) return { ok: false };
    if (currentKey === undefined || !(currentKey in publicKeys)) return { ok: false };
    const { ok, subject: verified } = verifyKeyRotation(rotation, publicKeys[currentKey]);
    if (!ok || verified === undefined) return { ok: false };
    currentKey = verified.newKey as string;
  }
  return { ok: true, currentKey };
}

// ---------------------------------------------------------------------------
// Decommission (retirement)
// ---------------------------------------------------------------------------

export interface BuildDecommissionOptions {
  robotDid: string;
  reason: string;
  finalDisposition?: string;
  decommissionedAt?: Date;
  validSeconds?: number;
}

/**
 * Build a signed decommission credential retiring `robotDid`. After
 * decommissioning, a verifier should refuse to trust the robot. `signer` is the
 * owner or an authority; `finalDisposition` records the outcome (for example
 * recycled, destroyed, or transferred to parts).
 */
export async function buildDecommission(
  signer: Signer,
  opts: BuildDecommissionOptions
): Promise<Record<string, unknown>> {
  if (!opts.reason) {
    throw new RoboticsError('reason is required');
  }
  const issued = opts.decommissionedAt ?? new Date();
  const subject: Record<string, unknown> = {
    id: opts.robotDid,
    reason: opts.reason,
    decommissionedBy: signer.getDid(),
  };
  if (opts.finalDisposition !== undefined) {
    subject.finalDisposition = opts.finalDisposition;
  }

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', DECOMMISSION_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

export interface VerifyDecommissionOptions {
  trustedAuthorities?: Set<string>;
}

/**
 * Verify a decommission credential. When `trustedAuthorities` is supplied, the
 * issuer DID MUST be in it, so only an attested authority can retire the robot.
 * Returns { ok, subject }.
 */
export function verifyDecommission(
  credential: Record<string, unknown>,
  publicKey: crypto.KeyObject,
  opts: VerifyDecommissionOptions = {}
): { ok: boolean; subject?: Record<string, unknown> } {
  const { ok, subject } = verifyTyped(credential, publicKey, DECOMMISSION_TYPE);
  if (!ok) return { ok: false };
  if (
    opts.trustedAuthorities !== undefined &&
    !(typeof credential.issuer === 'string' && opts.trustedAuthorities.has(credential.issuer))
  ) {
    return { ok: false };
  }
  return { ok: true, subject };
}
