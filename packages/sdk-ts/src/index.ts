/**
 * Vouch SDK - TypeScript
 * 
 * Official client library for the Vouch Protocol.
 * 
 * @packageDocumentation
 */

export {
    VouchClient,
    VouchClientConfig,
    DaemonStatus,
    PublicKeyInfo,
    SignMetadata,
    SignResult,
    MediaSignResult,
    UserDeniedSignatureError,
    DaemonNotAvailableError,
    NoKeysConfiguredError,
} from './vouch-client';

export { VouchClient as default } from './vouch-client';
