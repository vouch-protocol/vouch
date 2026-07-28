/**
 * Authority Freshness: authority state as a first-class input to trust freshness.
 *
 * Mirrors `vouch/authority_state.py` and the Rust core
 * `core/vouch-core/src/authority_state.rs`. Time-decay trust answers "how long
 * ago was this trust established". That is not enough for a high-consequence
 * agent whose mandate can be suspended seconds after a valid credential is
 * issued. This module adds the state axis: a signed `AuthorityState` credential
 * carrying a monotonic `authorityEpoch` and a `status`, plus the collapse rule
 * that rejects a voucher minted under a stale epoch for a state-freshness
 * action, even when its time-decay trust still passes.
 *
 * The credential is a plain VC Data Model 2.0 object signed with the shared
 * `eddsa-jcs-2022` Data Integrity path, so it canonicalizes byte-identically
 * across every language binding. The interop vector is shared under
 * `test-vectors/authority-state/`.
 */

import * as crypto from 'crypto';

import { buildProof, verifyProof, type BuildProofOptions } from './data-integrity';
import { decode as decodeMultikey } from './multikey';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1, VC_TYPE } from './vc';

export const AUTHORITY_STATE_TYPE = 'AuthorityState';

// Authority status vocabulary. `active` is the only value under which a
// state-freshness-requiring action may proceed; every other value is an
// authority-relevant transition that MUST bump `authorityEpoch`.
export const STATUS_ACTIVE = 'active';
export const STATUS_SUSPENDED = 'suspended';
export const STATUS_INCIDENT = 'incident';
export const STATUS_EXPOSURE_BREACHED = 'exposure_breached';
export const STATUS_REVOKED = 'revoked';

export const VALID_AUTHORITY_STATUSES: readonly string[] = [
  STATUS_ACTIVE,
  STATUS_SUSPENDED,
  STATUS_INCIDENT,
  STATUS_EXPOSURE_BREACHED,
  STATUS_REVOKED,
];

// Consequence tiers, ordered by how much a stale authority view is tolerated.
// Shared vocabulary with bounded-staleness revocation.
export const CONSEQUENCE_ROUTINE = 'routine';
export const CONSEQUENCE_SENSITIVE = 'sensitive';
export const CONSEQUENCE_CRITICAL = 'critical';

export const VALID_CONSEQUENCE_TIERS: readonly string[] = [
  CONSEQUENCE_ROUTINE,
  CONSEQUENCE_SENSITIVE,
  CONSEQUENCE_CRITICAL,
];

/** Raised when an AuthorityState credential is malformed. */
export class AuthorityStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorityStateError';
  }
}

function isValidStatus(status: unknown): status is string {
  return typeof status === 'string' && VALID_AUTHORITY_STATUSES.includes(status);
}

// --------------------------------------------------------------------------- //
// The AuthorityState credential
// --------------------------------------------------------------------------- //

export interface AuthorityStateCredentialSubject {
  id: string;
  authorityEpoch: number;
  status: string;
}

export interface AuthorityStateCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: AuthorityStateCredentialSubject;
  proof?: unknown;
}

/**
 * Inputs to build an unsigned AuthorityState credential. Deterministic and
 * clock-free in the style of the Rust core: the caller supplies the id and the
 * validity window. `validUntil` may be given directly, or derived from a
 * `Date` `validFrom` plus `validSeconds` (default 300).
 */
export interface BuildAuthorityStateOptions {
  issuerDid: string;
  authorityEpoch: number;
  status?: string;
  credentialId: string;
  validFrom: string | Date;
  validUntil?: string | Date;
  validSeconds?: number;
  /** The DID the state is about; defaults to `issuerDid` when omitted. */
  subjectDid?: string;
}

/**
 * Construct an unsigned AuthorityState credential.
 *
 * The wire shape is a plain VC Data Model 2.0 credential so it canonicalizes
 * byte-identically across every language binding. The caller attaches a Data
 * Integrity proof (`buildProof`) signed by the authority's key before
 * publishing it.
 */
export function buildAuthorityState(
  opts: BuildAuthorityStateOptions
): AuthorityStateCredential {
  const epoch = opts.authorityEpoch;
  if (!Number.isInteger(epoch)) {
    throw new AuthorityStateError('authorityEpoch must be an integer');
  }
  if (epoch < 0) {
    throw new AuthorityStateError(
      `authorityEpoch must be non-negative, got ${epoch}`
    );
  }
  const status = opts.status ?? STATUS_ACTIVE;
  if (!isValidStatus(status)) {
    throw new AuthorityStateError(
      `status must be one of ${JSON.stringify(VALID_AUTHORITY_STATUSES)}, got ${JSON.stringify(status)}`
    );
  }
  if (!opts.issuerDid) {
    throw new AuthorityStateError('issuerDid is required');
  }

  const validFrom = isoString(opts.validFrom);
  let validUntil: string;
  if (opts.validUntil !== undefined) {
    validUntil = isoString(opts.validUntil);
  } else {
    const base =
      opts.validFrom instanceof Date
        ? opts.validFrom
        : new Date(Date.parse(validFrom));
    const seconds = opts.validSeconds ?? 300;
    validUntil = isoString(new Date(base.getTime() + seconds * 1000));
  }

  // Field insertion order matches the Python and Rust builders. JCS re-sorts
  // keys during canonicalization, so this is cosmetic for the signature, but it
  // keeps the emitted JSON identical to the shared interop vector.
  return {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    id: opts.credentialId,
    type: [VC_TYPE, AUTHORITY_STATE_TYPE],
    issuer: opts.issuerDid,
    validFrom,
    validUntil,
    credentialSubject: {
      id: opts.subjectDid ?? opts.issuerDid,
      authorityEpoch: epoch,
      status,
    },
  };
}

/**
 * Build and sign an AuthorityState credential in one step (eddsa-jcs-2022).
 * Mirrors `sign_vouch_credential`: build, then attach a Data Integrity proof
 * via the shared `buildProof`. Sign with `proofOpts.privateKey` (in process) or
 * `proofOpts.sign` (a callback that keeps the key outside this process).
 */
export function signAuthorityState(
  opts: BuildAuthorityStateOptions,
  proofOpts: BuildProofOptions
): AuthorityStateCredential {
  const credential = buildAuthorityState(opts);
  const proof = buildProof(
    credential as unknown as Record<string, unknown>,
    proofOpts
  );
  return { ...credential, proof };
}

/**
 * The outcome of verifying an AuthorityState credential. Proof validity and
 * temporal validity are reported separately so "bad signature" is
 * distinguished from "expired", mirroring the Rust `VerifyResult`.
 */
export interface AuthorityVerifyResult {
  proofValid: boolean;
  timeValid: boolean;
}

/**
 * Verify an AuthorityState credential's Data Integrity proof and validity
 * window. Same shape as the Rust `verify`: the type MUST include
 * `AuthorityState`, the `eddsa-jcs-2022` proof is checked against `publicKey`,
 * and the temporal window is checked against `nowIso` with `clockSkewSeconds`
 * of tolerance.
 *
 * `publicKey` accepts a Node `KeyObject`, raw 32-byte Ed25519 key bytes, a
 * Multikey (`z`-prefixed) string, a JWK object, or a JWK JSON string.
 */
export function verifyAuthorityState(
  credential: AuthorityStateCredential | Record<string, unknown>,
  publicKey: crypto.KeyObject | Uint8Array | string | Record<string, unknown>,
  nowIso: string,
  clockSkewSeconds = 30
): AuthorityVerifyResult {
  const cred = credential as Record<string, unknown>;
  const typeField = cred.type;
  const types = Array.isArray(typeField)
    ? typeField
    : typeof typeField === 'string'
      ? [typeField]
      : [];
  if (!types.includes(AUTHORITY_STATE_TYPE)) {
    throw new AuthorityStateError('credential is not an AuthorityState');
  }

  const key = coerceEd25519PublicKey(publicKey);
  if (!key) {
    throw new AuthorityStateError('could not coerce public key to Ed25519');
  }

  let proofValid: boolean;
  try {
    proofValid = verifyProof(cred, key);
  } catch {
    proofValid = false;
  }

  const timeValid = verifyTemporal(cred, nowIso, clockSkewSeconds);
  return { proofValid, timeValid };
}

/**
 * Read `credentialSubject.authorityEpoch` without verifying the proof. For
 * deciding which of two credentials is newer; never a substitute for
 * `verifyAuthorityState`.
 */
export function readAuthorityEpoch(
  credential: AuthorityStateCredential | Record<string, unknown>
): number {
  const subject = (credential as Record<string, unknown>).credentialSubject;
  const epoch =
    subject && typeof subject === 'object'
      ? (subject as Record<string, unknown>).authorityEpoch
      : undefined;
  if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 0) {
    throw new AuthorityStateError('missing or invalid authorityEpoch');
  }
  return epoch;
}

/** Read `credentialSubject.status` without verifying the proof. */
export function readAuthorityStatus(
  credential: AuthorityStateCredential | Record<string, unknown>
): string {
  const subject = (credential as Record<string, unknown>).credentialSubject;
  const status =
    subject && typeof subject === 'object'
      ? (subject as Record<string, unknown>).status
      : undefined;
  if (!isValidStatus(status)) {
    throw new AuthorityStateError('missing or invalid status');
  }
  return status;
}

// --------------------------------------------------------------------------- //
// The collapse rule: consequence -> freshness policy
// --------------------------------------------------------------------------- //

/**
 * How a consequence tier treats authority state.
 *
 * - `enforceEpoch`: reject a voucher minted under an epoch older than the
 *   highest epoch the verifier has learned for the authority.
 * - `requireLiveCosign`: do not trust any cached epoch; require a live M-of-N
 *   co-sign read at action time.
 */
export interface FreshnessRule {
  enforceEpoch: boolean;
  requireLiveCosign: boolean;
}

/**
 * The consequence -> policy map. `routine` gets time-decay only; `sensitive`
 * collapses the window on a stale epoch; `critical` additionally demands a live
 * co-sign. Deployments MAY substitute their own map; the tier ordering is the
 * normative part.
 */
export const AUTHORITY_FRESHNESS_POLICY: Record<string, FreshnessRule> = {
  [CONSEQUENCE_ROUTINE]: { enforceEpoch: false, requireLiveCosign: false },
  [CONSEQUENCE_SENSITIVE]: { enforceEpoch: true, requireLiveCosign: false },
  [CONSEQUENCE_CRITICAL]: { enforceEpoch: true, requireLiveCosign: true },
};

/** The outcome of an Authority Freshness evaluation. */
export interface AuthorityFreshnessVerdict {
  allow: boolean;
  tier: string;
  reason: string;
}

/**
 * Decide whether an action passes the Authority Freshness gate.
 *
 * `voucherEpoch` / `lastSeenEpoch` are null or undefined when unknown.
 * `currentStatus` is null or undefined when the verifier holds no current
 * AuthorityState. `liveCosignOk` is the verified-fresh state of a live co-sign,
 * for the `critical` tier only. An unknown tier coerces to `critical`
 * (fail-closed).
 *
 * Decision order (first failure wins):
 *   tier == routine                            -> ALLOW (time-decay only)
 *   currentStatus known and not active         -> DENY  authority_status_not_active
 *   requireLiveCosign and not liveCosignOk     -> DENY  live_cosign_required
 *   enforceEpoch, epoch unavailable            -> DENY  authority_epoch_unknown
 *   enforceEpoch, voucherEpoch < lastSeen      -> DENY  authority_epoch_stale
 *   otherwise                                  -> ALLOW
 */
/**
 * Render an epoch for a reason code; "?" when absent, so the string is
 * identical across every language binding.
 */
function epochStr(epoch: number | null | undefined): string {
  return epoch == null ? '?' : String(epoch);
}

export function evaluateAuthorityFreshness(
  tier: string,
  voucherEpoch: number | null | undefined,
  lastSeenEpoch: number | null | undefined,
  currentStatus?: string | null,
  liveCosignOk?: boolean | null,
  policy: Record<string, FreshnessRule> = AUTHORITY_FRESHNESS_POLICY
): AuthorityFreshnessVerdict {
  const canonicalTier = VALID_CONSEQUENCE_TIERS.includes(tier)
    ? tier
    : CONSEQUENCE_CRITICAL;
  const rule =
    policy[canonicalTier] ?? { enforceEpoch: true, requireLiveCosign: true };
  const mk = (allow: boolean, reason: string): AuthorityFreshnessVerdict => ({
    allow,
    tier: canonicalTier,
    reason,
  });

  if (!rule.enforceEpoch && !rule.requireLiveCosign) {
    return mk(true, 'routine tier: time-decay only');
  }

  if (currentStatus != null && currentStatus !== STATUS_ACTIVE) {
    return mk(false, `authority_status_not_active:status=${currentStatus}`);
  }

  if (rule.requireLiveCosign && liveCosignOk !== true) {
    return mk(false, `live_cosign_required:tier=${canonicalTier}`);
  }

  if (rule.enforceEpoch) {
    if (voucherEpoch == null || lastSeenEpoch == null) {
      // An absent epoch renders as "?" so the reason code is identical in every
      // language binding. Pinned by the interop vector.
      return mk(
        false,
        `authority_epoch_unknown:voucher=${epochStr(voucherEpoch)},seen=${epochStr(lastSeenEpoch)}`
      );
    }
    if (voucherEpoch < lastSeenEpoch) {
      return mk(
        false,
        `authority_epoch_stale:seen=${lastSeenEpoch},voucher=${voucherEpoch}`
      );
    }
  }

  return mk(true, `${canonicalTier} tier: authority state fresh`);
}

// --------------------------------------------------------------------------- //
// helpers
// --------------------------------------------------------------------------- //

function isoString(value: string | Date): string {
  if (typeof value === 'string') return value;
  // RFC 3339 / XML Schema dateTime, second precision with a Z suffix.
  return value.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Check the credential's validity window against `nowIso` with the given clock
 * skew tolerance (seconds). Mirrors the Rust `verify_temporal`: false when the
 * window is missing/unparseable, when now is past `validUntil` beyond skew, or
 * before `validFrom` beyond skew.
 */
function verifyTemporal(
  credential: Record<string, unknown>,
  nowIso: string,
  clockSkewSeconds: number
): boolean {
  const now = Date.parse(nowIso);
  const validFrom = Date.parse(credential.validFrom as string);
  const validUntil = Date.parse(credential.validUntil as string);
  if (Number.isNaN(now) || Number.isNaN(validFrom) || Number.isNaN(validUntil)) {
    return false;
  }
  const skewMs = clockSkewSeconds * 1000;
  if (now - validUntil > skewMs) return false;
  if (validFrom - now > skewMs) return false;
  return true;
}

function coerceEd25519PublicKey(
  publicKey: crypto.KeyObject | Uint8Array | string | Record<string, unknown>
): crypto.KeyObject | null {
  if (publicKey instanceof crypto.KeyObject) {
    return publicKey;
  }
  if (publicKey instanceof Uint8Array || Buffer.isBuffer(publicKey)) {
    return publicKeyFromRaw(new Uint8Array(publicKey as Uint8Array));
  }
  if (typeof publicKey === 'string') {
    if (publicKey.startsWith('z')) {
      try {
        const { algorithm, rawKey } = decodeMultikey(publicKey);
        if (algorithm !== 'Ed25519') return null;
        return publicKeyFromRaw(rawKey);
      } catch {
        return null;
      }
    }
    try {
      return jwkToKeyObject(JSON.parse(publicKey) as Record<string, unknown>);
    } catch {
      return null;
    }
  }
  if (typeof publicKey === 'object' && publicKey !== null) {
    return jwkToKeyObject(publicKey as Record<string, unknown>);
  }
  return null;
}

function publicKeyFromRaw(raw: Uint8Array): crypto.KeyObject | null {
  if (raw.length !== 32) return null;
  const x = Buffer.from(raw).toString('base64url');
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x } as crypto.JsonWebKey,
    format: 'jwk',
  });
}

function jwkToKeyObject(jwk: Record<string, unknown>): crypto.KeyObject | null {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return crypto.createPublicKey({
      key: jwk as crypto.JsonWebKey,
      format: 'jwk',
    });
  }
  return null;
}
