/**
 * Root of Trust for robot identity (TypeScript): bind a hardware-rooted robot to
 * a recognized manufacturer, anchored to one pinned Vouch Protocol root.
 *
 * The Root of Trust for Machine Identity lets a pinned Vouch root recognize
 * issuers, and a recognized issuer bind a subject DID to attributes, verified
 * offline against the one pinned root. This extends that to robots. A recognized
 * manufacturer (an issuer the root granted the `issueRobotIdentity` action)
 * issues an identity that binds a robot's DID and its hardware-rooted key to
 * attributes such as make, model, serial, and owner. The robot separately holds
 * a hardware-attested RobotIdentityCredential (vouch.robotics.identity) proving
 * its key is bound to a secure element.
 *
 * `verifyRobotIdentityChain` closes the loop: from one pinned root, a verifier
 * confirms both that the robot is a legitimate robot from a recognized
 * manufacturer (the authority chain) and that the key the manufacturer vouched
 * for is genuinely hardware-rooted (the secure-element attestation), and that the
 * two name the same robot and the same key. It follows the anchor-once model and
 * the reason-code style of the underlying root_of_trust.
 *
 * Mirrors `vouch/robotics/root_identity.py` with matching behavior and reason
 * codes.
 */

import * as crypto from 'crypto';

import { encodeEd25519Public } from '../multikey';
import {
  ACTION_ISSUE_ROBOT_IDENTITY,
  buildAgentIdentity,
  verifyIdentityChain,
} from '../root-of-trust';
import type { Signer } from '../signer';

import { verifyRobotIdentity } from './identity';

export { ACTION_ISSUE_ROBOT_IDENTITY };

/** Outcome of {@link verifyRobotIdentityChain}. */
export interface RobotIdentityChainResult {
  /**
   * True only if the authority chain verified against the pinned root AND the
   * vouched key is hardware-rooted for the same robot.
   */
  ok: boolean;
  /** Structured failure reason when `ok` is false, else undefined. */
  reason?: string;
  /** The robot the identity describes. */
  robotDid?: string;
  /** The recognized manufacturer that issued the identity. */
  issuerDid?: string;
  /** The pinned Vouch root the chain anchored to. */
  rootDid?: string;
  /** The identity attributes the manufacturer bound. */
  attributes?: Record<string, unknown>;
  /** True when the vouched key is secure-element-rooted. */
  hardwareRooted: boolean;
}

export interface BuildRobotIdentityOptions {
  /** The robot's DID (the subject of this credential). */
  robotDid: string;
  /** The robot's Ed25519 hardware-rooted key as a Multikey. */
  hardwareKeyMultibase: string;
  /** Identity attributes to bind (make, model, serial, owner, and so on). */
  attributes: Record<string, unknown>;
  /** Validity window. Defaults to one year. */
  validSeconds?: number;
  validFrom?: Date;
  created?: Date;
  /** Optional W3C `credentialStatus` entry for revocation. */
  credentialStatus?: Record<string, unknown>;
  credentialId?: string;
}

export interface VerifyRobotIdentityChainOptions {
  /** The Vouch root DID the verifier pins. */
  trustedRoot: string;
  /** The robot's Ed25519 public key, used to check the hardware credential. */
  robotPublicKey: crypto.KeyObject;
  /** Optional Root of Trust credential to check for self-consistency. */
  rootCredential?: Record<string, unknown>;
  /** Allow network did:web resolution. Defaults false. */
  allowDidResolution?: boolean;
  /** Optional map of DID -> public key (JWK JSON or Multikey) for offline pinning. */
  trustedRoots?: Record<string, string>;
  /** Allowed clock drift for temporal checks. */
  clockSkewSeconds?: number;
  /** Optional callback returning true if a credential is revoked. */
  isRevoked?: (credential: Record<string, unknown>) => boolean;
}

/**
 * Issue an authority robot identity: a recognized manufacturer binds `robotDid`,
 * its hardware-rooted key (`hardwareKeyMultibase`, the robot's Ed25519 key as a
 * Multikey), and identity `attributes` (make, model, serial, owner). The
 * manufacturer must be a recognized issuer for the `issueRobotIdentity` action.
 * The credential is an AgentIdentityCredential so the shared identity-chain
 * verification applies, with the hardware key and a robot marker carried in the
 * bound identity attributes.
 */
export async function buildRobotIdentity(
  issuerSigner: Signer,
  opts: BuildRobotIdentityOptions
): Promise<Record<string, unknown>> {
  if (!opts.robotDid) {
    throw new Error('robotDid is required');
  }
  if (!opts.hardwareKeyMultibase) {
    throw new Error('hardwareKeyMultibase is required');
  }
  if (
    !opts.attributes ||
    typeof opts.attributes !== 'object' ||
    Array.isArray(opts.attributes) ||
    Object.keys(opts.attributes).length === 0
  ) {
    throw new Error('attributes must be a non-empty object');
  }

  const bound: Record<string, unknown> = { ...opts.attributes };
  bound.kind = 'robot';
  bound.hardwareKey = opts.hardwareKeyMultibase;

  return buildAgentIdentity(issuerSigner, {
    subjectDid: opts.robotDid,
    attributes: bound,
    validSeconds: opts.validSeconds,
    validFrom: opts.validFrom,
    created: opts.created,
    credentialStatus: opts.credentialStatus,
    credentialId: opts.credentialId,
  });
}

/**
 * Verify a robot's identity against a single pinned Vouch root, confirming both
 * provenance and hardware-rooting.
 *
 * From `trustedRoot`, the pinned root DID:
 *
 * 1. The authority chain: the recognized manufacturer must be recognized by the
 *    pinned root for the `issueRobotIdentity` action, and the authority identity
 *    must be signed by that manufacturer (via the shared identity-chain verify).
 * 2. The vouched key: the authority identity must carry a hardware key.
 * 3. The hardware root: the robot's own RobotIdentityCredential must verify under
 *    `robotPublicKey` and its secure-element attestation, name the same robot,
 *    and its key must equal the key the manufacturer vouched for.
 *
 * Returns a {@link RobotIdentityChainResult} with a reason code on any failure,
 * matching the anchor-once, reason-code style of the underlying root_of_trust.
 */
export async function verifyRobotIdentityChain(
  authorityIdentity: Record<string, unknown>,
  recognizedIssuerCredential: Record<string, unknown>,
  robotHardwareCredential: Record<string, unknown>,
  opts: VerifyRobotIdentityChainOptions
): Promise<RobotIdentityChainResult> {
  const trustedRoot = opts.trustedRoot;

  const chain = await verifyIdentityChain(authorityIdentity, recognizedIssuerCredential, {
    trustedRoot,
    requiredAction: ACTION_ISSUE_ROBOT_IDENTITY,
    rootCredential: opts.rootCredential,
    allowDidResolution: opts.allowDidResolution,
    trustedRoots: opts.trustedRoots,
    clockSkewSeconds: opts.clockSkewSeconds,
    isRevoked: opts.isRevoked,
  });
  if (!chain.ok) {
    return { ok: false, reason: chain.reason, rootDid: trustedRoot, hardwareRooted: false };
  }

  const attributes =
    chain.attributes && typeof chain.attributes === 'object' && !Array.isArray(chain.attributes)
      ? chain.attributes
      : {};
  const hardwareKey = attributes.hardwareKey;
  if (!hardwareKey) {
    return {
      ok: false,
      reason: 'identity_no_hardware_key',
      rootDid: trustedRoot,
      hardwareRooted: false,
    };
  }

  const hw = verifyRobotIdentity(robotHardwareCredential, opts.robotPublicKey);
  if (!hw.ok || !hw.subject) {
    return {
      ok: false,
      reason: 'hardware_root_invalid',
      rootDid: trustedRoot,
      hardwareRooted: false,
    };
  }
  if (hw.subject.id !== chain.agentDid) {
    return {
      ok: false,
      reason: 'hardware_subject_mismatch',
      rootDid: trustedRoot,
      hardwareRooted: false,
    };
  }

  let robotKeyMb: string;
  try {
    robotKeyMb = encodeEd25519Public(rawPublicOf(opts.robotPublicKey));
  } catch {
    return {
      ok: false,
      reason: 'hardware_key_unresolvable',
      rootDid: trustedRoot,
      hardwareRooted: false,
    };
  }
  if (robotKeyMb !== hardwareKey) {
    return {
      ok: false,
      reason: 'hardware_key_mismatch',
      rootDid: trustedRoot,
      hardwareRooted: false,
    };
  }

  return {
    ok: true,
    robotDid: chain.agentDid,
    issuerDid: chain.issuerDid,
    rootDid: trustedRoot,
    attributes,
    hardwareRooted: true,
  };
}

/** Raw Ed25519 public key bytes from a Node KeyObject (same encoding path as verifyRobotIdentity). */
function rawPublicOf(key: crypto.KeyObject): Uint8Array {
  const jwk = key.export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new Error('cannot extract Ed25519 public key bytes');
  return new Uint8Array(Buffer.from(jwk.x, 'base64url'));
}
