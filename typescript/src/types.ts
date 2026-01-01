/**
 * Vouch Protocol TypeScript SDK Types
 */

/**
 * Passport returned after successful verification
 */
export interface Passport {
    /** Subject DID */
    sub: string;
    /** Issuer DID */
    iss: string;
    /** Issued at timestamp */
    iat: number;
    /** Expiration timestamp */
    exp: number;
    /** Unique token ID */
    jti: string;
    /** Signed payload */
    payload: Record<string, unknown>;
    /** Raw JWT claims */
    rawClaims: Record<string, unknown>;
}

/**
 * Result of verification
 */
export interface VerificationResult {
    isValid: boolean;
    passport: Passport | null;
    error?: string;
}

/**
 * Configuration for Signer
 */
export interface SignerConfig {
    /** Private key in JWK format (JSON string or object) */
    privateKey: string | JsonWebKey;
    /** DID identifier for the signer */
    did: string;
    /** Default token expiry in seconds (default: 300) */
    defaultExpirySeconds?: number;
}

/**
 * Configuration for Verifier
 */
export interface VerifierConfig {
    /** Map of trusted DIDs to their public keys */
    trustedRoots?: Record<string, string | JsonWebKey>;
    /** Clock skew tolerance in seconds (default: 30) */
    clockSkewSeconds?: number;
}

/**
 * JWK Key structure
 */
export interface JWKKey {
    kty: string;
    crv?: string;
    x?: string;
    d?: string;
    kid?: string;
}
