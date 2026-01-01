/**
 * Vouch Protocol - TypeScript SDK
 *
 * The Identity & Reputation Standard for AI Agents
 */

export { Signer, generateIdentity } from './signer';
export { Verifier } from './verifier';
export {
    Passport,
    VerificationResult,
    SignerConfig,
    VerifierConfig,
    JWKKey
} from './types';

/**
 * Package version
 */
export const VERSION = '1.2.0';
