/**
 * Vouch Protocol Verifier - TypeScript Implementation
 *
 * Verifies JWS tokens using Ed25519 (EdDSA).
 */

import * as jose from 'jose';
import { Passport, VerificationResult, VerifierConfig, JWKKey } from './types';

/**
 * Verifier for validating Vouch-Tokens.
 *
 * @example
 * ```typescript
 * // Static verification with public key
 * const { isValid, passport } = await Verifier.verify(token, publicKeyJwk);
 *
 * // Instance with trusted roots
 * const verifier = new Verifier({
 *   trustedRoots: { 'did:web:agent.com': publicKeyJwk }
 * });
 * const result = await verifier.checkVouch(token);
 * ```
 */
export class Verifier {
    private trustedRoots: Map<string, jose.KeyLike | Uint8Array>;
    private clockSkew: number;
    private keyPromises: Map<string, Promise<jose.KeyLike | Uint8Array>>;

    constructor(config: VerifierConfig = {}) {
        this.trustedRoots = new Map();
        this.keyPromises = new Map();
        this.clockSkew = config.clockSkewSeconds ?? 30;

        if (config.trustedRoots) {
            for (const [did, key] of Object.entries(config.trustedRoots)) {
                this.addTrustedRoot(did, key);
            }
        }
    }

    /**
     * Add a trusted DID and its public key.
     */
    addTrustedRoot(did: string, publicKey: string | JsonWebKey): void {
        const jwk = typeof publicKey === 'string'
            ? JSON.parse(publicKey)
            : publicKey;

        this.keyPromises.set(did, jose.importJWK(jwk as jose.JWK, 'EdDSA'));
    }

    /**
     * Verify a token using trusted roots.
     *
     * @param token - The JWS token to verify
     * @returns Verification result with passport
     */
    async checkVouch(token: string): Promise<VerificationResult> {
        if (!token) {
            return { isValid: false, passport: null, error: 'Empty token' };
        }

        try {
            // Decode without verification to get issuer
            const { payload } = jose.decodeJwt(token);
            const issuer = payload.iss as string;

            if (!issuer) {
                return { isValid: false, passport: null, error: 'No issuer in token' };
            }

            // Get public key for issuer
            const keyPromise = this.keyPromises.get(issuer);
            if (!keyPromise) {
                return { isValid: false, passport: null, error: `Unknown issuer: ${issuer}` };
            }

            const publicKey = await keyPromise;
            return await Verifier.verify(token, publicKey);
        } catch (error) {
            return {
                isValid: false,
                passport: null,
                error: error instanceof Error ? error.message : 'Verification failed'
            };
        }
    }

    /**
     * Static method to verify a token with a public key.
     *
     * @param token - The JWS token to verify
     * @param publicKey - Public key (JWK string, object, or KeyLike)
     * @returns Verification result with passport
     */
    static async verify(
        token: string,
        publicKey?: string | JsonWebKey | jose.KeyLike | Uint8Array
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
                } else if ('kty' in (publicKey as any)) {
                    key = await jose.importJWK(publicKey as jose.JWK, 'EdDSA');
                } else {
                    key = publicKey as jose.KeyLike | Uint8Array;
                }
            }

            let payload: jose.JWTPayload;

            if (key) {
                // Full verification
                const result = await jose.jwtVerify(token, key, {
                    clockTolerance: 30
                });
                payload = result.payload;
            } else {
                // Structure-only validation (no signature check)
                payload = jose.decodeJwt(token);
            }

            // Check expiry
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp && now > payload.exp + 30) {
                return { isValid: false, passport: null, error: 'Token expired' };
            }

            // Check not-before
            if (payload.nbf && now < payload.nbf - 30) {
                return { isValid: false, passport: null, error: 'Token not yet valid' };
            }

            // Build passport
            const vouch = payload.vouch as { payload?: Record<string, unknown> } | undefined;

            const passport: Passport = {
                sub: (payload.sub as string) || '',
                iss: (payload.iss as string) || '',
                iat: (payload.iat as number) || 0,
                exp: (payload.exp as number) || 0,
                jti: (payload.jti as string) || '',
                payload: vouch?.payload || {},
                rawClaims: payload as Record<string, unknown>
            };

            return { isValid: true, passport };
        } catch (error) {
            return {
                isValid: false,
                passport: null,
                error: error instanceof Error ? error.message : 'Verification failed'
            };
        }
    }
}
