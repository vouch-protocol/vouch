/**
 * Cross-device identity by per-device keys and delegation (the OSS path).
 *
 * The private key never travels. Each device mints its OWN key locally, and the
 * user's root identity delegates scoped, time-bound, revocable authority to that
 * device's DID. A device signs its actions with its own key, chained under the
 * root grant. Losing a device means revoking one delegation, not rotating the
 * whole identity, and no key is ever copied between devices.
 *
 * Mirrors the Python vouch.fleet module. Built on the existing Signer/Verifier;
 * the credential wire format is unchanged.
 */

import * as crypto from 'crypto';

import { Signer } from './signer';
import type { CredentialPassport, CredentialVerificationResult } from './types';
import type { VouchCredential } from './vc';
import { verify } from './verifier';

type RootLike = Signer | { signer: Signer };

function rootSigner(root: RootLike): Signer {
  if (root instanceof Signer) return root;
  if (root && typeof (root as { signer?: unknown }).signer === 'object') {
    return (root as { signer: Signer }).signer;
  }
  throw new TypeError('enrollDevice requires a Signer or an Agent as the root');
}

export interface EnrollDeviceOptions {
  deviceDid: string;
  action: string;
  target: string;
  resource: string;
  validSeconds?: number;
  reputationScore?: number;
}

/**
 * Issue a delegation grant from the root identity to a device's DID. Hand the
 * grant to the device; it signs actions with `parentCredential` set to it.
 */
export async function enrollDevice(
  root: RootLike,
  opts: EnrollDeviceOptions
): Promise<VouchCredential> {
  const signer = rootSigner(root);
  return signer.signCredential({
    intent: {
      action: opts.action,
      target: opts.target,
      resource: opts.resource,
      delegatee: opts.deviceDid,
    },
    validSeconds: opts.validSeconds ?? 86400,
    reputationScore: opts.reputationScore,
  });
}

export interface FleetResult {
  ok: boolean;
  leaf?: CredentialPassport;
  rootDid?: string;
  reason?: string;
}

export interface VerifyDelegatedChainOptions {
  trustedRoots?: Record<string, crypto.KeyObject | string | Record<string, unknown>>;
  allowDidResolution?: boolean;
  revoked?: Iterable<string> | ((id: string) => boolean);
  requireAction?: string;
  requireTarget?: string;
  requireResource?: string;
  clockSkewSeconds?: number;
}

/**
 * Verify a delegation chain from a trusted root down to a leaf action. The
 * `credentials` array is ordered root-first: [rootGrant, ...grants, leafAction].
 */
export async function verifyDelegatedChain(
  credentials: Array<VouchCredential | Record<string, unknown>>,
  opts: VerifyDelegatedChainOptions = {}
): Promise<FleetResult> {
  if (!credentials || credentials.length === 0) {
    return { ok: false, reason: 'empty chain' };
  }
  const trustedRoots = opts.trustedRoots ?? {};
  const isRevoked = revocationOracle(opts.revoked);
  const skew = opts.clockSkewSeconds ?? 30;

  const passports: CredentialPassport[] = [];
  for (let index = 0; index < credentials.length; index++) {
    const cred = credentials[index];
    const issuer = issuerOf(cred);
    if (!issuer) return { ok: false, reason: `credential ${index} has no issuer` };

    const key = trustedRoots[issuer];
    if (index === 0 && key === undefined) {
      return { ok: false, reason: `root issuer ${issuer} is not in trustedRoots` };
    }

    const result: CredentialVerificationResult = await verify(cred, key, {
      clockSkewSeconds: skew,
    });
    if (!result.isValid || !result.passport) {
      return { ok: false, reason: `credential ${index} failed verification` };
    }

    if (isRevoked(result.passport.issuer)) {
      return { ok: false, reason: `credential ${index} issuer ${result.passport.issuer} is revoked` };
    }
    if (result.passport.credentialId && isRevoked(result.passport.credentialId)) {
      return { ok: false, reason: `credential ${index} (${result.passport.credentialId}) is revoked` };
    }
    passports.push(result.passport);
  }

  for (let i = 0; i < passports.length - 1; i++) {
    const parent = passports[i];
    const child = passports[i + 1];

    const delegatee = (parent.intent as Record<string, unknown>)?.delegatee as string | undefined;
    if (!delegatee) {
      return { ok: false, reason: `link ${i} (grant by ${parent.issuer}) names no delegatee` };
    }
    if (isRevoked(delegatee)) {
      return { ok: false, reason: `link ${i}: delegatee ${delegatee} is revoked` };
    }
    if (child.issuer !== delegatee) {
      return {
        ok: false,
        reason: `link ${i}: child issuer ${child.issuer} is not the delegatee ${delegatee}`,
      };
    }

    const parentResource = parent.resource ?? '';
    const childResource = child.resource ?? '';
    if (parentResource && childResource && !isSubResource(childResource, parentResource)) {
      return {
        ok: false,
        reason: `link ${i}: resource ${childResource} is not within the granted ${parentResource}`,
      };
    }

    if (!windowWithin(child, parent)) {
      return { ok: false, reason: `link ${i}: child validity is outside the grant window` };
    }
  }

  const leaf = passports[passports.length - 1];
  const checks: Array<[string, string | undefined, unknown]> = [
    ['action', opts.requireAction, leaf.action],
    ['target', opts.requireTarget, leaf.target],
    ['resource', opts.requireResource, leaf.resource],
  ];
  for (const [field, expected, actual] of checks) {
    if (expected !== undefined && actual !== expected) {
      return { ok: false, leaf, reason: `leaf intent.${field} != ${expected}` };
    }
  }

  return { ok: true, leaf, rootDid: passports[0].issuer };
}

/**
 * A small in-memory record of a root's enrolled and revoked devices. Pass
 * `isRevoked` straight to verifyDelegatedChain, or back it with your own store.
 */
export class DeviceRegistry {
  private enrolled = new Map<string, VouchCredential | undefined>();
  private revokedSet = new Set<string>();

  enroll(deviceDid: string, grant?: VouchCredential): void {
    this.enrolled.set(deviceDid, grant);
    this.revokedSet.delete(deviceDid);
  }

  revoke(deviceDid: string): void {
    this.revokedSet.add(deviceDid);
  }

  isRevoked = (identifier: string): boolean => this.revokedSet.has(identifier);

  activeDevices(): string[] {
    return [...this.enrolled.keys()].filter((d) => !this.revokedSet.has(d));
  }
}

function revocationOracle(
  revoked: Iterable<string> | ((id: string) => boolean) | undefined
): (id: string) => boolean {
  if (revoked === undefined) return () => false;
  if (typeof revoked === 'function') return revoked;
  const set = new Set(revoked);
  return (id) => set.has(id);
}

function issuerOf(cred: VouchCredential | Record<string, unknown>): string | null {
  const issuer = (cred as Record<string, unknown>).issuer;
  if (Array.isArray(issuer)) return (issuer[0] as string) ?? null;
  return (issuer as string) ?? null;
}

function isSubResource(child: string, parent: string): boolean {
  if (child === parent) return true;
  const trimmed = parent.replace(/\/+$/, '');
  return child.startsWith(trimmed + '/');
}

function windowWithin(child: CredentialPassport, parent: CredentialPassport): boolean {
  const cFrom = Date.parse(child.validFrom);
  const cUntil = Date.parse(child.validUntil);
  const pFrom = Date.parse(parent.validFrom);
  const pUntil = Date.parse(parent.validUntil);
  if ([cFrom, cUntil, pFrom, pUntil].some((n) => Number.isNaN(n))) return false;
  return cFrom >= pFrom && cUntil <= pUntil;
}
