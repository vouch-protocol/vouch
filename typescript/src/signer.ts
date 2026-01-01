/**
 * Vouch Protocol Signer - TypeScript Implementation
 *
 * Signs payloads using Ed25519 (EdDSA) and produces JWS compact serialization.
 */

import * as jose from 'jose';
import { SignerConfig, JWKKey } from './types';

/**
 * Signer for creating Vouch-Tokens.
 *
 * @example
 * ```typescript
 * const signer = new Signer({
 *   privateKey: '{"kty":"OKP","crv":"Ed25519","x":"...","d":"..."}',
 *   did: 'did:web:my-agent.com'
 * });
 *
 * const token = await signer.sign({ action: 'read_database' });
 * // Use token in Vouch-Token header
 * ```
 */
export class Signer {
    private privateKey: jose.KeyLike | Uint8Array;
    private did: string;
    private defaultExpiry: number;
    private keyPromise: Promise<jose.KeyLike | Uint8Array>;

    constructor(config: SignerConfig) {
        if (!config.privateKey) {
            throw new Error('privateKey is required');
        }
        if (!config.did) {
            throw new Error('did is required');
        }

        this.did = config.did;
        this.defaultExpiry = config.defaultExpirySeconds ?? 300;
        this.privateKey = null as any; // Will be set by keyPromise

        // Parse JWK and import key
        const jwk = typeof config.privateKey === 'string'
            ? JSON.parse(config.privateKey) as JWKKey
            : config.privateKey as JWKKey;

        if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
            throw new Error('Key must be Ed25519 (OKP with crv Ed25519)');
        }

        this.keyPromise = jose.importJWK(jwk as jose.JWK, 'EdDSA');
    }

    /**
     * Get the DID associated with this signer.
     */
    getDid(): string {
        return this.did;
    }

    /**
     * Sign a payload and return a JWS compact token.
     *
     * @param payload - The payload to sign
     * @param expirySeconds - Optional override for token expiry
     * @returns JWS compact serialization (Vouch-Token)
     */
    async sign(
        payload: Record<string, unknown>,
        expirySeconds?: number
    ): Promise<string> {
        const key = await this.keyPromise;
        const now = Math.floor(Date.now() / 1000);
        const exp = now + (expirySeconds ?? this.defaultExpiry);

        const claims = {
            jti: crypto.randomUUID(),
            iss: this.did,
            sub: this.did,
            iat: now,
            nbf: now,
            exp: exp,
            vouch: {
                payload: payload
            }
        };

        const token = await new jose.SignJWT(claims)
            .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: this.did })
            .sign(key);

        return token;
    }

    /**
     * Get the public key in JWK format.
     */
    async getPublicKeyJwk(): Promise<string> {
        const key = await this.keyPromise;
        const publicJwk = await jose.exportJWK(key);

        // Remove private component
        delete (publicJwk as any).d;

        return JSON.stringify(publicJwk);
    }
}

/**
 * Generate a new Ed25519 keypair for Vouch signing.
 *
 * @param domain - Optional domain for did:web generation
 * @returns Object containing privateKey, publicKey, and optional did
 */
export async function generateIdentity(domain?: string): Promise<{
    privateKeyJwk: string;
    publicKeyJwk: string;
    did: string | null;
}> {
    const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA', {
        crv: 'Ed25519'
    });

    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);

    return {
        privateKeyJwk: JSON.stringify(privateJwk),
        publicKeyJwk: JSON.stringify(publicJwk),
        did: domain ? `did:web:${domain}` : null
    };
}
