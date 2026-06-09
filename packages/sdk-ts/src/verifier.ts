/**
 * Vouch Protocol Verifier (TypeScript).
 *
 * Verifies both legacy JWS-format Vouch-Tokens and modern W3C Verifiable
 * Credentials with Data Integrity proofs (eddsa-jcs-2022).
 *
 * Two coexisting verification paths:
 *
 *   1. Legacy JWS: Verifier.verify(token, ...) and
 *    verifier.checkVouch(token). Operates on JWS Compact Serialization
 *    strings produced by Signer.sign().
 *
 *   2. W3C VC: Verifier.verifyCredential(credential, ...) and
 *    verifier.checkVouchCredential(credential). Operates on credential
 *    objects produced by Signer.signCredential() (Specification §8).
 *
 * Existing callers of the legacy methods continue to work unchanged. New
 * callers should prefer the credential methods.
 */

import * as crypto from 'crypto';
import * as jose from 'jose';

import { verifyProof, CRYPTOSUITE_ID } from './data-integrity';
import {
  verifyHybridProof,
  HYBRID_CRYPTOSUITE_ID,
} from './data-integrity-hybrid';
import { decode as decodeMultikey } from './multikey';
import { validateDelegationChain } from './attenuation';
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

export class Verifier {
  private trustedRoots: Map<string, jose.KeyLike | Uint8Array>;
  private trustedRootsRaw: Map<string, crypto.KeyObject>;
  private clockSkew: number;
  private keyPromises: Map<string, Promise<jose.KeyLike | Uint8Array>>;

  constructor(config: VerifierConfig = {}) {
    this.trustedRoots = new Map();
    this.trustedRootsRaw = new Map();
    this.keyPromises = new Map();
    this.clockSkew = config.clockSkewSeconds ?? 30;

    if (config.trustedRoots) {
      for (const [did, key] of Object.entries(config.trustedRoots)) {
        this.addTrustedRoot(did, key);
      }
    }
  }

  /**
   * Add a trusted DID and its public key. Stores both the jose KeyLike
   * (for legacy JWS verification) and a Node KeyObject (for Data Integrity
   * verification).
   */
  addTrustedRoot(did: string, publicKey: string | JWKKey | Record<string, unknown>): void {
    const jwk =
      typeof publicKey === 'string' ? JSON.parse(publicKey) : publicKey;

    this.keyPromises.set(did, jose.importJWK(jwk as jose.JWK, 'EdDSA'));
    this.trustedRootsRaw.set(
      did,
      crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' })
    );
  }

  // ------------------------------------------------------------------
  // Legacy JWS path. Behavior preserved verbatim.
  // ------------------------------------------------------------------

  /**
   * Verify a JWS-format token using trusted roots.
   */
  async checkVouch(token: string): Promise<VerificationResult> {
    if (!token) {
      return { isValid: false, passport: null, error: 'Empty token' };
    }

    try {
      const payload = jose.decodeJwt(token) as jose.JWTPayload;
      const issuer = payload.iss as string;
      if (!issuer) {
        return {
          isValid: false,
          passport: null,
          error: 'No issuer in token',
        };
      }
      const keyPromise = this.keyPromises.get(issuer);
      if (!keyPromise) {
        return {
          isValid: false,
          passport: null,
          error: `Unknown issuer: ${issuer}`,
        };
      }
      const publicKey = await keyPromise;
      return await Verifier.verify(token, publicKey);
    } catch (error) {
      return {
        isValid: false,
        passport: null,
        error: error instanceof Error ? error.message : 'Verification failed',
      };
    }
  }

  /**
   * Static method to verify a JWS-format token with a public key.
   */
  static async verify(
    token: string,
    publicKey?: string | Record<string, unknown> | jose.KeyLike | Uint8Array
  ): Promise<VerificationResult> {
    if (!token) {
      return { isValid: false, passport: null, error: 'Empty token' };
    }

    try {
      let key: jose.KeyLike | Uint8Array | undefined;

      if (publicKey) {
        if (typeof publicKey === 'string') {
          const jwk = JSON.parse(publicKey);
          key = await jose.importJWK(jwk as jose.JWK, 'EdDSA');
        } else if (
          publicKey !== null &&
          typeof publicKey === 'object' &&
          'kty' in (publicKey as Record<string, unknown>)
        ) {
          key = await jose.importJWK(
            publicKey as unknown as jose.JWK,
            'EdDSA'
          );
        } else {
          key = publicKey as jose.KeyLike | Uint8Array;
        }
      }

      let payload: jose.JWTPayload;
      if (key) {
        const result = await jose.jwtVerify(token, key, {
          clockTolerance: 30,
        });
        payload = result.payload;
      } else {
        payload = jose.decodeJwt(token);
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && now > payload.exp + 30) {
        return { isValid: false, passport: null, error: 'Token expired' };
      }
      if (payload.nbf && now < payload.nbf - 30) {
        return {
          isValid: false,
          passport: null,
          error: 'Token not yet valid',
        };
      }

      const vouch = payload.vouch as
        | { payload?: Record<string, unknown> }
        | undefined;

      const passport: Passport = {
        sub: (payload.sub as string) || '',
        iss: (payload.iss as string) || '',
        iat: (payload.iat as number) || 0,
        exp: (payload.exp as number) || 0,
        jti: (payload.jti as string) || '',
        payload: vouch?.payload || {},
        rawClaims: payload as Record<string, unknown>,
      };
      return { isValid: true, passport };
    } catch (error) {
      return {
        isValid: false,
        passport: null,
        error: error instanceof Error ? error.message : 'Verification failed',
      };
    }
  }

  // ------------------------------------------------------------------
  // Modern path: VC + Data Integrity (eddsa-jcs-2022).
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
  static async verifyCredential(
    credential: VouchCredential | Record<string, unknown> | string,
    publicKey?: crypto.KeyObject | string | Record<string, unknown>,
    clockSkewSeconds: number = 30,
    options: {
      /** ML-DSA-44 public key, required to verify a hybrid PQ proof. */
      mldsa44PublicKey?: Uint8Array;
      /**
       * If set, the proof's cryptosuite MUST equal this value. Use
       * HYBRID_CRYPTOSUITE_ID to require post-quantum protection and refuse a
       * downgrade to the Ed25519-only suite.
       */
      requiredCryptosuite?: string;
    } = {}
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

    // Determine the proof and its cryptosuite up front so we can both dispatch
    // verification correctly and refuse a post-quantum downgrade.
    const proofObj = (cred.proof as Record<string, unknown> | undefined);
    const cryptosuite =
      proofObj && typeof proofObj === 'object'
        ? (proofObj.cryptosuite as string | undefined)
        : undefined;

    // Downgrade protection: if the caller requires a specific cryptosuite
    // (e.g. the hybrid PQ suite), reject anything else. This is what stops an
    // attacker stripping the ML-DSA-44 half of a hybrid proof and presenting
    // it as plain Ed25519.
    if (options.requiredCryptosuite && cryptosuite !== options.requiredCryptosuite) {
      return {
        isValid: false,
        passport: null,
        error: `Required cryptosuite ${options.requiredCryptosuite}, got ${cryptosuite ?? 'none'}`,
      };
    }

    // Cryptographic verification (if a key was provided). Dispatch on the
    // cryptosuite: the Ed25519-only path and the hybrid path are NOT
    // interchangeable, and an unknown suite is rejected rather than ignored.
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
        let proofOk: boolean;
        if (cryptosuite === HYBRID_CRYPTOSUITE_ID) {
          if (!options.mldsa44PublicKey) {
            return {
              isValid: false,
              passport: null,
              error: 'Hybrid proof requires an ML-DSA-44 public key',
            };
          }
          proofOk = verifyHybridProof(cred, resolved, options.mldsa44PublicKey);
        } else if (cryptosuite === CRYPTOSUITE_ID) {
          proofOk = verifyProof(cred, resolved);
        } else {
          return {
            isValid: false,
            passport: null,
            error: `Unsupported cryptosuite: ${cryptosuite ?? 'none'}`,
          };
        }
        if (!proofOk) {
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

    // Bind the proof to the issuer and enforce its purpose. A key trusted for
    // one issuer must not validate a credential claiming a different issuer,
    // and a proof made for another purpose must not be replayed as an
    // assertion.
    if (proofObj && typeof proofObj === 'object') {
      if (proofObj.proofPurpose !== 'assertionMethod') {
        return {
          isValid: false,
          passport: null,
          error: 'Proof proofPurpose is not assertionMethod',
        };
      }
      const issuerField = cred.issuer;
      const issuerDid =
        typeof issuerField === 'string'
          ? issuerField
          : Array.isArray(issuerField)
           ? (issuerField[0] as string) || ''
           : '';
      if (issuerDid) {
        const vm = proofObj.verificationMethod;
        if (typeof vm !== 'string' || !vm) {
          return {
            isValid: false,
            passport: null,
            error: 'Proof missing verificationMethod',
          };
        }
        if (vm.split('#', 1)[0] !== issuerDid) {
          return {
            isValid: false,
            passport: null,
            error: 'verificationMethod does not belong to issuer',
          };
        }
      }
    }

    // Temporal validation.
    const now = new Date();
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

    // v1.7 (CH-001): verifier-side capability-attenuation check. Each link must
    // be a proper subset of the prior link across at least one of
    // action/target/resource/time/rate/policy, and broader on none. There is no
    // fixed depth limit; depth is a verifier-side cost budget (Section 9.4).
    const attenuation = validateDelegationChain(cred);
    if (!attenuation.ok) {
      return {
        isValid: false,
        passport: null,
        error: `Delegation chain rejected: ${attenuation.reason} (${attenuation.detail})`,
      };
    }

    // Each delegation link must carry a non-empty parentProofValue binding it
    // to its parent credential. The chain lives inside the signed
    // credentialSubject, so a present value is tamper-evident; a missing one
    // indicates a forged or spliced chain claiming unearned parent authority.
    const rawChain = (subject.delegationChain as Array<Record<string, unknown>> | undefined) ?? [];
    for (const link of rawChain) {
      if (link && typeof link === 'object' && !link.parentProofValue) {
        return {
          isValid: false,
          passport: null,
          error: 'Delegation link missing parentProofValue',
        };
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
      validFrom: cred.validFrom as string,
      validUntil: cred.validUntil as string,
      credentialId: (cred.id as string) || '',
      intent: intent,
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

      const rawKey = this.trustedRootsRaw.get(issuer);
      if (!rawKey) {
        return {
          isValid: false,
          passport: null,
          error: `Unknown issuer: ${issuer}`,
        };
      }

      return await Verifier.verifyCredential(
        cred as unknown as VouchCredential,
        rawKey,
        this.clockSkew
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
