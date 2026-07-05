/**
 * A thin, read-friendly wrapper over a Vouch Credential object.
 *
 * The object produced by `sign` (and `sign`) is the canonical, on-the
 * -wire form. This wrapper sits on top so you can read back what a credential
 * authorizes without digging through `credentialSubject.intent` by hand, and
 * verify it in one call. It is sugar only: `toObject()` returns the same object
 * you passed in, so nothing about the wire format changes.
 */

import * as crypto from 'crypto';

import type { CredentialVerificationResult } from './types';
import type { DelegationLink, Intent, VouchCredential } from './vc';
import { verify } from './verifier';

export class Credential {
  private readonly cred: Record<string, unknown>;

  constructor(credential: VouchCredential | Record<string, unknown> | string) {
    let value: unknown = credential;
    if (value instanceof Credential) {
      value = value.cred;
    }
    if (typeof value === 'string') {
      value = JSON.parse(value);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError('Credential expects an object or JSON string');
    }
    this.cred = value as Record<string, unknown>;
  }

  private get subject(): Record<string, unknown> {
    return (this.cred.credentialSubject as Record<string, unknown>) ?? {};
  }

  get intent(): Intent {
    return (this.subject.intent as Intent) ?? ({} as Intent);
  }

  get action(): string | undefined {
    return this.intent.action;
  }

  get target(): string | undefined {
    return this.intent.target;
  }

  get resource(): string | undefined {
    return this.intent.resource;
  }

  get issuer(): string {
    const issuer = this.cred.issuer;
    if (Array.isArray(issuer)) return (issuer[0] as string) || '';
    return (issuer as string) || '';
  }

  get subjectId(): string {
    return (this.subject.id as string) || '';
  }

  get credentialId(): string {
    return (this.cred.id as string) || '';
  }

  get validFrom(): string {
    return (this.cred.validFrom as string) || '';
  }

  get validUntil(): string {
    return (this.cred.validUntil as string) || '';
  }

  get isExpired(): boolean {
    const t = Date.parse(this.validUntil);
    if (Number.isNaN(t)) return false;
    return t < Date.now();
  }

  get reputationScore(): number | undefined {
    const score = this.subject.reputationScore;
    return typeof score === 'number' && Number.isFinite(score) ? score : undefined;
  }

  get delegationChain(): DelegationLink[] {
    const chain = this.subject.delegationChain;
    return Array.isArray(chain) ? (chain as DelegationLink[]) : [];
  }

  /**
   * Verify this credential. With a `publicKey`, verifies offline; without one,
   * resolves a `did:key` issuer (offline). Returns the verification result.
   */
  async verify(
    publicKey?: crypto.KeyObject | string | Record<string, unknown>,
    opts?: { clockSkewSeconds?: number }
  ): Promise<CredentialVerificationResult> {
    return verify(this.cred, publicKey, opts);
  }

  /** Return the underlying credential object (the canonical wire form). */
  toObject(): VouchCredential {
    return this.cred as unknown as VouchCredential;
  }

  /** Return the credential as a compact JSON string for transport. */
  toJsonString(): string {
    return JSON.stringify(this.cred);
  }
}
