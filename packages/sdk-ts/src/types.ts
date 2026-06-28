/**
 * Vouch Protocol TypeScript SDK Types
 */

import type { VouchCredential, Intent, DelegationLink } from './vc';

export type { VouchCredential, Intent, DelegationLink };

/**
 * Passport returned after successful verification of a legacy JWS token.
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
 * Result of legacy JWS verification.
 */
export interface VerificationResult {
  isValid: boolean;
  passport: Passport | null;
  error?: string;
}

/**
 * Verified Verifiable Credential under Vouch Protocol v1.0.
 *
 * Returned by `Verifier.verifyCredential()` and
 * `Verifier.checkVouchCredential()`. Parallel to the legacy `Passport`,
 * new code should prefer this type.
 */
export interface CredentialPassport {
  /** credentialSubject.id, the agent's DID */
  sub: string;
  /** issuer DID */
  iss: string;
  /** ISO 8601 timestamp string */
  validFrom: string;
  /** ISO 8601 timestamp string */
  validUntil: string;
  /** Credential id, e.g. "urn:uuid:..." */
  credentialId: string;
  /** Intent payload (action, target, resource) */
  intent: Intent;
  /** Convenience accessor: intent.action. */
  action?: string;
  /** Convenience accessor: intent.target. */
  target?: string;
  /** Convenience accessor: intent.resource. */
  resource?: string;
  /** Issuer DID. Alias for `iss`. */
  issuer: string;
  /** True if the credential's validity window has passed (no skew). */
  isExpired: boolean;
  /** Optional self-reported reputation score in [0, 100] */
  reputationScore?: number;
  /** Ordered delegation chain from root to current */
  delegationChain: DelegationLink[];
  /** Full verified credential */
  rawCredential: VouchCredential;
}

/**
 * Result of credential verification (modern path).
 */
export interface CredentialVerificationResult {
  isValid: boolean;
  passport: CredentialPassport | null;
  error?: string;
}

/**
 * Configuration for Signer
 */
export interface SignerConfig {
  /** Private key in JWK format (JSON string or object) */
  privateKey: string | JWKKey;
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
  trustedRoots?: Record<string, string | JWKKey>;
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

/**
 * Options for issuing a Vouch Credential (modern path).
 */
export interface SignCredentialOptions {
  /**
   * Intent payload. MUST contain action, target, resource once merged with the
   * named fields below. Pass the whole intent here, or use the
   * action/target/resource shortcuts, or combine them (named fields win).
   */
  intent?: Intent;
  /** Intent action (alternative to intent.action). */
  action?: string;
  /** Intent target (alternative to intent.target). */
  target?: string;
  /** Intent resource (alternative to intent.resource). */
  resource?: string;
  /** Override the default validity window in seconds. */
  validSeconds?: number;
  /** Optional self-reported reputation score in [0, 100]. */
  reputationScore?: number;
  /** Override the issued-at moment (default: now). */
  validFrom?: Date;
  /** Optional credential id, defaults to a fresh UUID URN. */
  credentialId?: string;
  /**
   * If provided, this signer is acting as a sub-agent. The issuer extends
   * the parent's delegation chain with a new link from the parent's
   * subject to this signer's DID, enforcing depth and resource-narrowing
   * rules (Specification §9.3, §9.4).
   */
  parentCredential?: VouchCredential;
  /** Pre-built delegation chain to attach (advanced). */
  delegationChain?: DelegationLink[];
}
