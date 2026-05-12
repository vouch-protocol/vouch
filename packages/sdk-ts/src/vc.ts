/**
 * Verifiable Credential envelope for Vouch Protocol.
 *
 * Mirrors `vouch/vc.py`. Builds a `VouchCredential` per Specification §5:
 * a VC Data Model 2.0 credential carrying an agent's intent, optional
 * reputation, and optional delegation chain, secured by a Data Integrity
 * proof (eddsa-jcs-2022).
 */

import * as crypto from 'crypto';

export const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';
export const VOUCH_CONTEXT_V1 = 'https://vouch-protocol.com/contexts/v1';

export const VC_TYPE = 'VerifiableCredential';
export const VOUCH_CREDENTIAL_TYPE = 'VouchCredential';
export const SESSION_VOUCHER_TYPE = 'SessionVoucher';

export const PROTOCOL_VERSION = '1.0';

export interface Intent {
  action: string;
  target: string;
  resource: string;
  [extra: string]: unknown;
}

export interface DelegationLink {
  issuer: string;
  subject: string;
  intent: Intent;
  validFrom?: string;
  validUntil?: string;
  parentProofValue?: string;
}

export interface CredentialSubject {
  id: string;
  vouchVersion: string;
  intent: Intent;
  reputationScore?: number;
  delegationChain?: DelegationLink[];
}

export interface VouchCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: unknown;
  proof?: unknown;
}

export interface BuildVouchCredentialOptions {
  issuerDid: string;
  intent: Intent;
  validSeconds?: number;
  reputationScore?: number;
  delegationChain?: DelegationLink[];
  credentialId?: string;
  validFrom?: Date;
  credentialStatus?: Record<string, unknown>;
}

/**
 * Construct an unsigned Vouch Credential. Caller is responsible for
 * attaching a Data Integrity proof via `buildProof`.
 *
 * `credentialStatus` is typically built via `buildStatusListEntry` to
 * reference a BitstringStatusListCredential (Specification §11.2).
 */
export function buildVouchCredential(
  opts: BuildVouchCredentialOptions
): VouchCredential {
  validateIntent(opts.intent);

  const issuedAt = opts.validFrom ?? new Date();
  const validSeconds = opts.validSeconds ?? 300;
  const expiresAt = new Date(issuedAt.getTime() + validSeconds * 1000);

  const subject: CredentialSubject = {
    id: opts.issuerDid,
    vouchVersion: PROTOCOL_VERSION,
    intent: opts.intent,
  };

  if (opts.reputationScore !== undefined) {
    subject.reputationScore = Math.max(
      0,
      Math.min(100, Math.floor(opts.reputationScore))
    );
  }

  if (opts.delegationChain && opts.delegationChain.length > 0) {
    subject.delegationChain = opts.delegationChain;
  }

  const vc: VouchCredential = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    id: opts.credentialId ?? newUuidUrn(),
    type: [VC_TYPE, VOUCH_CREDENTIAL_TYPE],
    issuer: opts.issuerDid,
    validFrom: iso(issuedAt),
    validUntil: iso(expiresAt),
    credentialSubject: subject,
  };

  if (opts.credentialStatus !== undefined) {
    vc.credentialStatus = opts.credentialStatus;
  }

  return vc;
}

function validateIntent(intent: Intent): void {
  if (!intent || typeof intent !== 'object') {
    throw new TypeError('intent must be an object');
  }
  for (const required of ['action', 'target', 'resource'] as const) {
    const v = intent[required];
    if (v === undefined || v === null || v === '') {
      throw new Error(
        `intent.${required} is REQUIRED (Specification §5.4.1), ` +
        'Vouch credentials MUST bind to a concrete resource'
      );
    }
  }
}

function newUuidUrn(): string {
  // crypto.randomUUID is available on Node 14.17+ and modern browsers.
  const id = crypto.randomUUID();
  return `urn:uuid:${id}`;
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
