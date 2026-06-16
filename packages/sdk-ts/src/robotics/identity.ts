/**
 * Hardware-rooted robot identity (TypeScript), Phase 5.1.
 *
 * Mirrors `vouch/robotics/identity.py` with byte-identical output. A
 * RobotIdentityCredential is an eddsa-jcs-2022 VC whose subject carries the
 * robot's make, model, and serial, a lifecycle history, and a `hardwareRoot`
 * block. The hardware root signs a binding over (robot DID, robot key), so the
 * software identity key is provably bound to a specific piece of hardware.
 * Verification checks both the credential proof (robot key) and the hardware
 * attestation (root key). Cross-language interop with the Python module is
 * REQUIRED: both produce byte-identical canonical bytes and verify each other.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import { canonicalize } from '../jcs';
import { decode, encodeEd25519Public } from '../multikey';
import type { Signer } from '../signer';

export const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';
export const VOUCH_CONTEXT_V1 = 'https://vouch-protocol.com/contexts/v1';
export const ROBOT_IDENTITY_TYPE = 'RobotIdentityCredential';

export class RoboticsError extends Error {}

// Node needs DER-wrapped keys; raw Ed25519 keys get these fixed prefixes.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function privKeyFromSeed(seed: Uint8Array): crypto.KeyObject {
  if (seed.length !== 32) throw new RoboticsError('Ed25519 seed must be 32 bytes');
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
}

function pubKeyFromRaw(raw: Uint8Array): crypto.KeyObject {
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

function rawPublicOf(key: crypto.KeyObject): Uint8Array {
  const jwk = key.export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new RoboticsError('cannot extract Ed25519 public key bytes');
  return new Uint8Array(Buffer.from(jwk.x, 'base64url'));
}

function mb64(b: Uint8Array): string {
  return 'u' + Buffer.from(b).toString('base64url');
}

function unmb64(s: string): Uint8Array {
  if (!s.startsWith('u')) throw new RoboticsError("expected multibase 'u' prefix");
  return new Uint8Array(Buffer.from(s.slice(1), 'base64url'));
}

/** Canonical bytes the hardware root signs to bind the identity key. */
function bindingBytes(robotDid: string, robotKeyMultibase: string): Uint8Array {
  return canonicalize({ key: robotKeyMultibase, robotDid });
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ---------------------------------------------------------------------------
// Hardware root of trust
// ---------------------------------------------------------------------------

export interface HardwareRootOfTrust {
  readonly kind: string;
  publicKeyRaw(): Uint8Array;
  sign(data: Uint8Array): Uint8Array;
  publicKeyMultibase(): string;
}

/**
 * Reference root of trust backed by a local Ed25519 key. Stands in for a TPM or
 * secure element in development and tests. NOT a hardware root: a real
 * deployment MUST use a hardware-backed implementation.
 */
export class SoftwareRootOfTrust implements HardwareRootOfTrust {
  readonly kind: string;
  private sk: crypto.KeyObject;
  private pkRaw: Uint8Array;

  constructor(seed?: Uint8Array, kind = 'Software') {
    this.sk = seed ? privKeyFromSeed(seed) : crypto.generateKeyPairSync('ed25519').privateKey;
    this.pkRaw = rawPublicOf(crypto.createPublicKey(this.sk));
    this.kind = kind;
  }

  publicKeyRaw(): Uint8Array {
    return this.pkRaw;
  }

  sign(data: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.sign(null, Buffer.from(data), this.sk));
  }

  publicKeyMultibase(): string {
    return encodeEd25519Public(this.pkRaw);
  }
}

// ---------------------------------------------------------------------------
// Mint and verify
// ---------------------------------------------------------------------------

export interface MintRobotIdentityOptions {
  make: string;
  model: string;
  serial: string;
  owner?: string;
  lifecycle?: Array<Record<string, unknown>>;
  validSeconds?: number;
  validFrom?: Date;
}

/**
 * Mint a hardware-attested RobotIdentityCredential. The robot self-issues with
 * its Vouch key (`robotSigner`); the hardware root signs a binding over the
 * robot DID and key, embedded as `hardwareRoot.attestation`.
 */
export async function mintRobotIdentity(
  robotSigner: Signer,
  root: HardwareRootOfTrust,
  opts: MintRobotIdentityOptions
): Promise<Record<string, unknown>> {
  const robotDid = robotSigner.getDid();
  const robotKeyMb = await robotSigner.getPublicKeyMultikey();
  const attestation = root.sign(bindingBytes(robotDid, robotKeyMb));

  const issued = opts.validFrom ?? new Date();
  const subject: Record<string, unknown> = {
    id: robotDid,
    make: opts.make,
    model: opts.model,
    serial: opts.serial,
    hardwareRoot: {
      kind: root.kind,
      publicKeyMultibase: root.publicKeyMultibase(),
      attestation: mb64(attestation),
    },
    lifecycle: opts.lifecycle ?? [{ event: 'commissioned', timestamp: iso(issued) }],
  };
  if (opts.owner !== undefined) subject.owner = opts.owner;

  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', ROBOT_IDENTITY_TYPE],
    issuer: robotDid,
    validFrom: iso(issued),
    credentialSubject: subject,
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return robotSigner.attachProof(credential);
}

/**
 * Verify a RobotIdentityCredential: the credential proof (robot key) AND the
 * hardware-root attestation binding the robot key to the hardware.
 */
export function verifyRobotIdentity(
  credential: Record<string, unknown>,
  robotPublicKey: crypto.KeyObject
): { ok: boolean; subject?: Record<string, unknown> } {
  const typeField = credential.type;
  const types = Array.isArray(typeField) ? typeField : [typeField];
  if (!types.includes(ROBOT_IDENTITY_TYPE)) return { ok: false };

  try {
    if (!verifyProof(credential, robotPublicKey)) return { ok: false };
  } catch {
    return { ok: false };
  }

  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  const hw = (subject.hardwareRoot ?? {}) as Record<string, unknown>;
  const hwMb = hw.publicKeyMultibase as string | undefined;
  const attestation = hw.attestation as string | undefined;
  if (!hwMb || !attestation) return { ok: false };

  try {
    const { algorithm, rawKey } = decode(hwMb);
    if (algorithm !== 'Ed25519') return { ok: false };
    const hwPub = pubKeyFromRaw(rawKey);
    const robotRaw = rawPublicOf(robotPublicKey);
    const robotKeyMb = encodeEd25519Public(robotRaw);
    const binding = bindingBytes((subject.id as string) ?? '', robotKeyMb);
    const ok = crypto.verify(null, Buffer.from(binding), hwPub, Buffer.from(unmb64(attestation)));
    if (!ok) return { ok: false };
  } catch {
    return { ok: false };
  }
  return { ok: true, subject };
}

/** Build a lifecycle history entry. */
export function lifecycleEvent(
  event: string,
  opts: { actor?: string; details?: Record<string, unknown>; timestamp?: Date } = {}
): Record<string, unknown> {
  const entry: Record<string, unknown> = {
    event,
    timestamp: iso(opts.timestamp ?? new Date()),
  };
  if (opts.actor !== undefined) entry.actor = opts.actor;
  if (opts.details !== undefined) entry.details = opts.details;
  return entry;
}
