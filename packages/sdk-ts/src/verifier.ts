/**
 * Vouch Protocol Verifier (TypeScript).
 *
 * Verifies W3C Verifiable Credentials with Data Integrity proofs
 * (eddsa-jcs-2022) via Verifier.verify(credential, ...) and
 * verifier.checkVouchCredential(credential) (Specification §8).
 */

import * as crypto from 'crypto';
import * as jose from 'jose';

import { capabilityView, firstBroaderStep } from './attenuation';
import { CRYPTOSUITE_ID, verifyProof } from './data-integrity';
import { decode as decodeMultikey } from './multikey';
import type {
  CredentialPassport,
  CredentialVerificationResult,
  JWKKey,
  Passport,
  VerificationResult,
  VerifierConfig,
} from './types';
import type {
  DelegationLink,
  Intent,
  VouchCredential,
} from './vc';

/** A public key in any form `Verifier.verify` accepts. */
export type PublicKeyInput = crypto.KeyObject | string | Record<string, unknown>;

/** Options for delegation chain verification and the evaluation clock. */
export interface VerifyOptions {
  /** Resolves the key of a chain grant issuer by DID. did:key always resolves offline. */
  keyResolver?: (did: string) => PublicKeyInput | null | undefined | Promise<PublicKeyInput | null | undefined>;
  /**
   * Root anchors for the delegation chain: a `{did: key}` map (keys are also used
   * for resolution) or a list of DIDs. When given, the chain must start at one.
   */
  trustedRoots?: Record<string, PublicKeyInput> | string[];
  /** Evaluation time for validity windows (default: now). */
  now?: Date;
}

export class Verifier {
  private trustedRootsRaw: Map<string, crypto.KeyObject>;
  private clockSkew: number;

  constructor(config: VerifierConfig = {}) {
    this.trustedRootsRaw = new Map();
    this.clockSkew = config.clockSkewSeconds ?? 30;

    if (config.trustedRoots) {
      for (const [did, key] of Object.entries(config.trustedRoots)) {
        this.addTrustedRoot(did, key);
      }
    }
  }

  /**
   * Add a trusted DID and its public key for Data Integrity verification.
   */
  addTrustedRoot(did: string, publicKey: string | JWKKey | Record<string, unknown>): void {
    const jwk =
      typeof publicKey === 'string' ? JSON.parse(publicKey) : publicKey;

    this.trustedRootsRaw.set(
      did,
      crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' })
    );
  }

  // ------------------------------------------------------------------
  // Verify a VC + Data Integrity proof (eddsa-jcs-2022).
  // ------------------------------------------------------------------

  /**
   * Verify a W3C Vouch Credential. Performs the full flow per W3C CG
   * Report §8.1.
   *
   * @param credential A Vouch Credential object OR a JSON-encoded string.
   * @param publicKey Ed25519 public key as a Node KeyObject, JWK string,
   *          JWK object, or Multikey string. If omitted, only
   *          structural and temporal checks run.
   * @param clockSkewSeconds Allowed clock drift (default 30).
   */
  static async verify(
    credential: VouchCredential | Record<string, unknown> | string,
    publicKey?: crypto.KeyObject | string | Record<string, unknown>,
    clockSkewSeconds: number = 30,
    options: VerifyOptions = {}
  ): Promise<CredentialVerificationResult> {
    if (!credential) {
      return { isValid: false, passport: null, error: 'Empty credential' };
    }

    let cred: Record<string, unknown>;
    try {
      cred =
        typeof credential === 'string'
          ? (JSON.parse(credential) as Record<string, unknown>)
          : (credential as Record<string, unknown>);
    } catch (e) {
      return {
        isValid: false,
        passport: null,
        error: 'Invalid credential JSON',
      };
    }

    if (!cred || typeof cred !== 'object' || Array.isArray(cred)) {
      return { isValid: false, passport: null, error: 'Malformed credential' };
    }

    // Cryptographic verification (if a key was provided).
    if (publicKey !== undefined) {
      const resolved = await coerceEd25519PublicKey(publicKey);
      if (!resolved) {
        return {
          isValid: false,
          passport: null,
          error: 'Could not coerce public key to Ed25519',
        };
      }
      try {
        if (!verifyProof(cred, resolved)) {
          return {
            isValid: false,
            passport: null,
            error: 'Data Integrity proof verification failed',
          };
        }
      } catch (e) {
        return {
          isValid: false,
          passport: null,
          error:
            e instanceof Error ? e.message : 'Proof verification error',
        };
      }
    }

    // Temporal validation.
    const now = options.now ?? new Date();
    const validFrom = parseIso8601(cred.validFrom as string | undefined);
    const validUntil = parseIso8601(cred.validUntil as string | undefined);
    if (!validFrom || !validUntil) {
      return {
        isValid: false,
        passport: null,
        error: 'Credential missing validFrom or validUntil',
      };
    }
    const skewMs = clockSkewSeconds * 1000;
    if (now.getTime() - validUntil.getTime() > skewMs) {
      return { isValid: false, passport: null, error: 'Credential expired' };
    }
    if (validFrom.getTime() - now.getTime() > skewMs) {
      return {
        isValid: false,
        passport: null,
        error: 'Credential not yet valid',
      };
    }

    // Required intent.resource binding (§5.4.1, §8.4).
    const subject = cred.credentialSubject as
      | Record<string, unknown>
      | undefined;
    if (!subject || typeof subject !== 'object') {
      return {
        isValid: false,
        passport: null,
        error: 'Missing credentialSubject',
      };
    }
    const intent = subject.intent as Intent | undefined;
    if (!intent || typeof intent !== 'object' || !intent.resource) {
      return {
        isValid: false,
        passport: null,
        error: 'Missing required intent.resource',
      };
    }

    // Delegation chain (Specification 9.3): grant signatures, linkage,
    // expiry, and non-expansion on every dimension.
    if (Array.isArray(subject.delegationChain) && subject.delegationChain.length > 0) {
      const reason = await verifyDelegationChain(cred, {
        ...options,
        now,
        clockSkewSeconds,
      });
      if (reason !== null) {
        return { isValid: false, passport: null, error: `delegation: ${reason}` };
      }
    }

    // Build the passport.
    const chain: DelegationLink[] = Array.isArray(subject.delegationChain)
      ? (subject.delegationChain as DelegationLink[])
      : [];

    let repScore: number | undefined;
    const rawScore = subject.reputationScore;
    if (typeof rawScore === 'number' && Number.isFinite(rawScore)) {
      repScore = rawScore;
    }

    const issuerField = cred.issuer;
    const issuer =
      typeof issuerField === 'string'
        ? issuerField
        : Array.isArray(issuerField)
         ? (issuerField[0] as string) || ''
         : '';

    const passport: CredentialPassport = {
      sub: (subject.id as string) || '',
      iss: issuer,
      issuer: issuer,
      validFrom: cred.validFrom as string,
      validUntil: cred.validUntil as string,
      credentialId: (cred.id as string) || '',
      intent: intent,
      action: intent.action,
      target: intent.target,
      resource: intent.resource,
      isExpired: validUntil.getTime() < Date.now(),
      reputationScore: repScore,
      delegationChain: chain,
      rawCredential: cred as unknown as VouchCredential,
    };
    return { isValid: true, passport };
  }

  /**
   * Verify a W3C Vouch Credential, resolving the issuer key from trusted
   * roots. Mirrors `checkVouch()` for the modern format.
   */
  async checkVouchCredential(
    credential: VouchCredential | Record<string, unknown> | string
  ): Promise<CredentialVerificationResult> {
    if (!credential) {
      return { isValid: false, passport: null, error: 'Empty credential' };
    }

    try {
      const cred =
        typeof credential === 'string'
          ? (JSON.parse(credential) as Record<string, unknown>)
          : (credential as Record<string, unknown>);

      const issuerField = cred.issuer;
      const issuer =
        typeof issuerField === 'string'
          ? issuerField
          : Array.isArray(issuerField)
           ? (issuerField[0] as string) || ''
           : '';

      if (!issuer) {
        return {
          isValid: false,
          passport: null,
          error: 'No issuer in credential',
        };
      }

      // A trusted root wins, so a deployment can pin a key for an issuer.
      // Verifier.verify accepts a KeyObject or a Multikey string, which is what
      // lets the did:key branch below hand it the key straight from the DID.
      let rawKey: crypto.KeyObject | string | undefined =
        this.trustedRootsRaw.get(issuer);

      // did:key is self-certifying: the multikey after the prefix is the key,
      // so it resolves offline with no document to fetch and no root to pin.
      // This mirrors the Python reference, whose check_vouch_credential does
      // the same, and the module-level verify() in this file.
      if (!rawKey && issuer.startsWith('did:key:')) {
        rawKey = issuer.slice('did:key:'.length);
      }

      if (!rawKey) {
        return {
          isValid: false,
          passport: null,
          error: `Unknown issuer: ${issuer}`,
        };
      }

      const roots = this.trustedRootsRaw;
      return await Verifier.verify(
        cred as unknown as VouchCredential,
        rawKey,
        this.clockSkew,
        { keyResolver: (did: string) => roots.get(did) }
      );
    } catch (error) {
      return {
        isValid: false,
        passport: null,
        error:
          error instanceof Error ? error.message : 'Verification failed',
      };
    }
  }
}

/**
 * Verify a Vouch Credential in one line (the receiving-side counterpart to
 * {@link sign}).
 *
 * With a `publicKey`, verifies offline against that key. Without one, the issuer
 * key is resolved from a `did:key` issuer (self-certifying, offline). For
 * `did:web` issuers, pass the public key or use a Verifier with trusted roots.
 */
export async function verify(
  credential: VouchCredential | Record<string, unknown> | string,
  publicKey?: crypto.KeyObject | string | Record<string, unknown>,
  opts?: { clockSkewSeconds?: number } & VerifyOptions
): Promise<CredentialVerificationResult> {
  const skew = opts?.clockSkewSeconds ?? 30;
  const chainOpts: VerifyOptions = {
    keyResolver: opts?.keyResolver,
    trustedRoots: opts?.trustedRoots,
    now: opts?.now,
  };
  if (publicKey !== undefined) {
    return Verifier.verify(credential, publicKey, skew, chainOpts);
  }

  let cred: Record<string, unknown>;
  try {
    cred =
      typeof credential === 'string'
        ? (JSON.parse(credential) as Record<string, unknown>)
        : (credential as Record<string, unknown>);
  } catch {
    return { isValid: false, passport: null, error: 'Invalid credential JSON' };
  }

  const issuerField = cred.issuer;
  const issuer =
    typeof issuerField === 'string'
      ? issuerField
      : Array.isArray(issuerField)
       ? (issuerField[0] as string) || ''
       : '';

  if (issuer.startsWith('did:key:')) {
    // did:key is self-certifying: the multikey after the prefix is the key.
    const multikey = issuer.slice('did:key:'.length);
    return Verifier.verify(cred, multikey, skew, chainOpts);
  }

  return {
    isValid: false,
    passport: null,
    error:
      `Cannot resolve the issuer key for ${issuer || 'this credential'}; ` +
      'pass a publicKey, or use a Verifier configured with trusted roots',
  };
}

// ---------------------------------------------------------------------------
// Delegation chain verification (Specification 9.3)
// ---------------------------------------------------------------------------

type Obj = Record<string, unknown>;

function asObj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}

function issuerDid(cred: Obj): string | null {
  const iss = cred.issuer;
  if (typeof iss === 'string') return iss;
  if (Array.isArray(iss)) return typeof iss[0] === 'string' ? (iss[0] as string) : null;
  const o = asObj(iss);
  return o && typeof o.id === 'string' ? (o.id as string) : null;
}

/** The proof value a link binds to its parent (eddsa-jcs-2022 member of a proof set). */
export function parentProofBinding(grant: Obj): string {
  const proof = grant.proof;
  if (Array.isArray(proof)) {
    for (const p of proof) {
      const o = asObj(p);
      if (o && o.cryptosuite === CRYPTOSUITE_ID) return typeof o.proofValue === 'string' ? o.proofValue : '';
    }
    for (const p of proof) {
      const o = asObj(p);
      if (o && typeof o.proofValue === 'string' && o.proofValue) return o.proofValue;
    }
    return '';
  }
  const o = asObj(proof);
  return o && typeof o.proofValue === 'string' ? o.proofValue : '';
}

function verifyGrantProof(grant: Obj, issuer: string, key: crypto.KeyObject): boolean {
  const raw = grant.proof;
  const proofs = Array.isArray(raw) ? raw : [raw];
  const body: Obj = { ...grant };
  delete body.proof;
  for (const p of proofs) {
    const o = asObj(p);
    if (!o) continue;
    if (o.cryptosuite !== undefined && o.cryptosuite !== null && o.cryptosuite !== CRYPTOSUITE_ID) continue;
    if (o.proofPurpose !== 'assertionMethod') continue;
    const vm = o.verificationMethod;
    if (typeof vm !== 'string' || vm.split('#')[0] !== issuer) continue;
    try {
      if (verifyProof({ ...body, proof: o }, key)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

async function resolveChainKey(
  did: string,
  rootKeys: Record<string, PublicKeyInput>,
  keyResolver: VerifyOptions['keyResolver']
): Promise<crypto.KeyObject | null> {
  if (Object.prototype.hasOwnProperty.call(rootKeys, did)) {
    return coerceEd25519PublicKey(rootKeys[did]);
  }
  if (keyResolver) {
    let candidate: PublicKeyInput | null | undefined;
    try {
      candidate = await keyResolver(did);
    } catch {
      candidate = null;
    }
    if (candidate) return coerceEd25519PublicKey(candidate);
  }
  if (did.startsWith('did:key:')) {
    return coerceEd25519PublicKey(did.slice('did:key:'.length));
  }
  return null;
}

/**
 * Verify a credential's embedded `delegationChain`. Resolves to null when the
 * chain is valid (or absent), otherwise a reason code. A faithful port of
 * `vouch.verifier.verify_delegation_chain` (Python reference); the shared
 * vectors in test-vectors/delegation-chain are the contract.
 */
export async function verifyDelegationChain(
  credential: Obj | string,
  options: VerifyOptions & { clockSkewSeconds?: number } = {}
): Promise<string | null> {
  let cred: Obj | null;
  try {
    cred = typeof credential === 'string' ? asObj(JSON.parse(credential)) : asObj(credential);
  } catch {
    return 'malformed_delegation';
  }
  if (!cred) return 'malformed_delegation';
  const subject = asObj(cred.credentialSubject);
  const chain = subject ? subject.delegationChain : undefined;
  if (chain === undefined || chain === null || (Array.isArray(chain) && chain.length === 0)) return null;
  if (!Array.isArray(chain)) return 'malformed_delegation';

  const skewMs = (options.clockSkewSeconds ?? 30) * 1000;
  const now = (options.now ?? new Date()).getTime();
  let rootKeys: Record<string, PublicKeyInput> = {};
  let rootDids: string[] | null = null;
  if (Array.isArray(options.trustedRoots)) {
    rootDids = options.trustedRoots.map(String);
  } else if (options.trustedRoots) {
    rootKeys = options.trustedRoots;
    rootDids = Object.keys(options.trustedRoots);
  }

  const grants: Obj[] = [];
  for (const raw of chain) {
    const link = asObj(raw);
    if (!link || typeof link.issuer !== 'string' || typeof link.subject !== 'string') {
      return 'malformed_delegation';
    }
    const grant = asObj(link.parentCredential);
    if (!grant || (asObj(grant.proof) === null && !Array.isArray(grant.proof))) {
      return 'delegation_link_unsigned';
    }
    const grantIssuer = issuerDid(grant);
    if (grantIssuer !== link.issuer) return 'delegation_link_issuer_mismatch';
    const key = await resolveChainKey(grantIssuer, rootKeys, options.keyResolver);
    if (!key) return 'delegation_issuer_key_unresolved';
    if (!verifyGrantProof(grant, grantIssuer, key)) return 'delegation_signature_invalid';
    if (
      link.parentProofValue !== undefined &&
      link.parentProofValue !== null &&
      link.parentProofValue !== parentProofBinding(grant).slice(0, 64)
    ) {
      return 'delegation_link_tampered';
    }
    const grantIntent = asObj(asObj(grant.credentialSubject)?.intent);
    const delegatee = grantIntent ? grantIntent.delegatee : undefined;
    if (!delegatee) return 'delegation_no_delegatee';
    if (delegatee !== link.subject) return 'delegation_subject_mismatch';
    const from = parseIso8601(grant.validFrom as string | undefined);
    const until = parseIso8601(grant.validUntil as string | undefined);
    if (!from || !until) return 'malformed_delegation';
    if (now - until.getTime() > skewMs) return 'delegation_expired';
    if (from.getTime() - now > skewMs) return 'delegation_not_yet_valid';
    grants.push(grant);
  }

  const links = chain as Obj[];
  for (let i = 1; i < links.length; i++) {
    if (links[i - 1].subject !== links[i].issuer) return 'delegation_subject_issuer_mismatch';
  }
  if (links[links.length - 1].subject !== issuerDid(cred)) return 'delegation_subject_issuer_mismatch';

  if (rootDids !== null && !rootDids.includes(links[0].issuer as string)) {
    return 'untrusted_principal';
  }

  const views = [...grants.map((g) => capabilityView(g)), capabilityView(cred)];
  const dim = firstBroaderStep(views);
  if (dim !== null) return `scope_exceeds_parent:${dim}`;
  return null;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function coerceEd25519PublicKey(
  publicKey: crypto.KeyObject | string | Record<string, unknown>
): Promise<crypto.KeyObject | null> {
  if (publicKey instanceof crypto.KeyObject) {
    return publicKey;
  }

  // Multikey string (z-prefixed base58btc)
  if (typeof publicKey === 'string' && publicKey.startsWith('z')) {
    try {
      const { algorithm, rawKey } = decodeMultikey(publicKey);
      if (algorithm !== 'Ed25519') return null;
      // Build an OKP JWK from raw bytes.
      const x = uint8ArrayToBase64Url(rawKey);
      return crypto.createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x } as crypto.JsonWebKey,
        format: 'jwk',
      });
    } catch {
      return null;
    }
  }

  let jwk: Record<string, unknown> | null = null;
  if (typeof publicKey === 'string') {
    try {
      jwk = JSON.parse(publicKey) as Record<string, unknown>;
    } catch {
      return null;
    }
  } else if (typeof publicKey === 'object' && publicKey !== null) {
    jwk = publicKey as Record<string, unknown>;
  }

  if (jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return crypto.createPublicKey({
      key: jwk as crypto.JsonWebKey,
      format: 'jwk',
    });
  }
  return null;
}

function parseIso8601(value: string | undefined): Date | null {
  if (!value || typeof value !== 'string') return null;
  const t = Date.parse(value);
  if (Number.isNaN(t)) return null;
  return new Date(t);
}

function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
