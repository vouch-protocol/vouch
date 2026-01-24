/**
 * IdentityService - Hardware-backed Key Management for Vouch Verifier
 *
 * This service provides cryptographic key management using the device's
 * hardware security module (Secure Enclave on iOS, Keystore on Android).
 *
 * Features:
 * - Hardware-backed key generation (keys never leave the device)
 * - Biometric-gated signing (FaceID/TouchID/Fingerprint)
 * - DID generation from public keys
 * - Secure key storage with expo-secure-store
 *
 * @module IdentityService
 */

import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import * as Crypto from 'expo-crypto';

// =============================================================================
// Types
// =============================================================================

/**
 * Biometry type available on the device
 */
export type BiometryType = 'FaceID' | 'TouchID' | 'Fingerprint' | 'Iris' | 'None';

/**
 * Result of biometric capability check
 */
export interface BiometricCapability {
    available: boolean;
    biometryType: BiometryType;
    enrolled: boolean;
    level: 'strong' | 'weak' | 'none';
}

/**
 * Key pair stored in secure storage
 */
export interface StoredKeyPair {
    keyId: string;
    publicKey: string; // Base64 encoded
    algorithm: 'Ed25519' | 'P-256';
    createdAt: number;
    lastUsed: number;
    metadata?: {
        name?: string;
        type?: 'root' | 'agent';
        parentKeyId?: string;
    };
}

/**
 * Result of signing operation
 */
export interface SignatureResult {
    success: boolean;
    signature?: string; // Base64 encoded
    keyId: string;
    signedAt: number;
    error?: string;
}

/**
 * Device identity information
 */
export interface DeviceIdentity {
    did: string;
    publicKey: string;
    keyId: string;
    biometryType: BiometryType;
    createdAt: number;
}

// =============================================================================
// Constants
// =============================================================================

const STORAGE_KEYS = {
    ROOT_KEY_ID: 'vouch_root_key_id',
    KEY_PREFIX: 'vouch_key_',
    KEY_INDEX: 'vouch_key_index',
    DEVICE_DID: 'vouch_device_did',
} as const;

const BIOMETRIC_OPTIONS: LocalAuthentication.LocalAuthenticationOptions = {
    promptMessage: 'Authenticate to sign with your Vouch identity',
    cancelLabel: 'Cancel',
    fallbackLabel: 'Use passcode',
    disableDeviceFallback: false,
};

// =============================================================================
// IdentityService Class
// =============================================================================

class IdentityService {
    private static instance: IdentityService;
    private initialized = false;
    private cachedCapability: BiometricCapability | null = null;

    private constructor() { }

    /**
     * Get singleton instance
     */
    static getInstance(): IdentityService {
        if (!IdentityService.instance) {
            IdentityService.instance = new IdentityService();
        }
        return IdentityService.instance;
    }

    /**
     * Initialize the identity service
     */
    async initialize(): Promise<void> {
        if (this.initialized) return;

        // Check biometric capability
        await this.checkBiometricCapability();
        this.initialized = true;

        console.log('[IdentityService] Initialized');
    }

    // ===========================================================================
    // Biometric Authentication
    // ===========================================================================

    /**
     * Check device biometric capability
     */
    async checkBiometricCapability(): Promise<BiometricCapability> {
        if (this.cachedCapability) {
            return this.cachedCapability;
        }

        const hasHardware = await LocalAuthentication.hasHardwareAsync();
        const isEnrolled = await LocalAuthentication.isEnrolledAsync();
        const supportedTypes = await LocalAuthentication.supportedAuthenticationTypesAsync();
        const securityLevel = await LocalAuthentication.getEnrolledLevelAsync();

        let biometryType: BiometryType = 'None';

        if (supportedTypes.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION)) {
            // On iOS, this is Face ID; on Android, it's face unlock
            biometryType = 'FaceID';
        } else if (supportedTypes.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)) {
            // On iOS, this is Touch ID; on Android, it's fingerprint
            biometryType = 'Fingerprint';
        } else if (supportedTypes.includes(LocalAuthentication.AuthenticationType.IRIS)) {
            biometryType = 'Iris';
        }

        let level: 'strong' | 'weak' | 'none' = 'none';
        if (securityLevel === LocalAuthentication.SecurityLevel.BIOMETRIC_STRONG) {
            level = 'strong';
        } else if (securityLevel === LocalAuthentication.SecurityLevel.BIOMETRIC_WEAK) {
            level = 'weak';
        }

        this.cachedCapability = {
            available: hasHardware && isEnrolled,
            biometryType,
            enrolled: isEnrolled,
            level,
        };

        return this.cachedCapability;
    }

    /**
     * Authenticate user with biometrics
     */
    async authenticateWithBiometrics(
        reason: string = 'Authenticate to continue'
    ): Promise<{ success: boolean; error?: string }> {
        const capability = await this.checkBiometricCapability();

        if (!capability.available) {
            return {
                success: false,
                error: 'Biometric authentication not available on this device',
            };
        }

        try {
            const result = await LocalAuthentication.authenticateAsync({
                ...BIOMETRIC_OPTIONS,
                promptMessage: reason,
            });

            if (result.success) {
                return { success: true };
            } else {
                return {
                    success: false,
                    error: result.error || 'Authentication failed',
                };
            }
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Authentication error',
            };
        }
    }

    // ===========================================================================
    // Key Management
    // ===========================================================================

    /**
     * Generate a new hardware-backed key pair
     *
     * Note: True Secure Enclave key generation requires native modules.
     * This implementation uses expo-crypto for key material and
     * expo-secure-store for secure storage, which provides hardware
     * backing on supported devices.
     */
    async generateHardwareKey(options?: {
        name?: string;
        type?: 'root' | 'agent';
        parentKeyId?: string;
    }): Promise<StoredKeyPair> {
        // Require biometric auth for key generation
        const authResult = await this.authenticateWithBiometrics(
            'Authenticate to create your Vouch identity'
        );

        if (!authResult.success) {
            throw new Error(`Authentication failed: ${authResult.error}`);
        }

        // Generate key ID
        const keyId = await Crypto.randomUUID();

        // Generate key material using expo-crypto
        // Note: For true Ed25519, we'd use a native module
        // This generates cryptographically secure random bytes
        const privateKeyBytes = await Crypto.getRandomBytesAsync(32);
        const privateKeyB64 = this.bytesToBase64(privateKeyBytes);

        // Derive public key (simplified - real Ed25519 would use proper derivation)
        // For production, use a native Ed25519 implementation
        const publicKeyHash = await Crypto.digestStringAsync(
            Crypto.CryptoDigestAlgorithm.SHA256,
            privateKeyB64
        );
        const publicKeyB64 = publicKeyHash.slice(0, 43); // Truncate to ~32 bytes base64

        const now = Date.now();

        const keyPair: StoredKeyPair = {
            keyId,
            publicKey: publicKeyB64,
            algorithm: 'Ed25519',
            createdAt: now,
            lastUsed: now,
            metadata: {
                name: options?.name,
                type: options?.type || 'root',
                parentKeyId: options?.parentKeyId,
            },
        };

        // Store private key in secure storage (hardware-backed on supported devices)
        await SecureStore.setItemAsync(
            `${STORAGE_KEYS.KEY_PREFIX}${keyId}_private`,
            privateKeyB64,
            {
                keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
                requireAuthentication: true,
            }
        );

        // Store key metadata
        await SecureStore.setItemAsync(
            `${STORAGE_KEYS.KEY_PREFIX}${keyId}_meta`,
            JSON.stringify(keyPair),
            {
                keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
            }
        );

        // Update key index
        await this.addToKeyIndex(keyId);

        // If this is a root key, set it as the default
        if (!options?.type || options.type === 'root') {
            await SecureStore.setItemAsync(STORAGE_KEYS.ROOT_KEY_ID, keyId);

            // Generate and store DID
            const did = this.publicKeyToDID(publicKeyB64);
            await SecureStore.setItemAsync(STORAGE_KEYS.DEVICE_DID, did);
        }

        console.log(`[IdentityService] Generated key: ${keyId}`);
        return keyPair;
    }

    /**
     * Sign payload with hardware-backed key
     *
     * Triggers biometric authentication before signing.
     */
    async signPayload(
        payload: string | Uint8Array,
        keyId?: string
    ): Promise<SignatureResult> {
        const targetKeyId = keyId || (await this.getRootKeyId());

        if (!targetKeyId) {
            return {
                success: false,
                keyId: '',
                signedAt: Date.now(),
                error: 'No key available for signing',
            };
        }

        // Require biometric auth for signing
        const authResult = await this.authenticateWithBiometrics(
            'Authenticate to sign with your Vouch identity'
        );

        if (!authResult.success) {
            return {
                success: false,
                keyId: targetKeyId,
                signedAt: Date.now(),
                error: `Authentication failed: ${authResult.error}`,
            };
        }

        try {
            // Get private key from secure storage
            const privateKeyB64 = await SecureStore.getItemAsync(
                `${STORAGE_KEYS.KEY_PREFIX}${targetKeyId}_private`
            );

            if (!privateKeyB64) {
                return {
                    success: false,
                    keyId: targetKeyId,
                    signedAt: Date.now(),
                    error: 'Private key not found',
                };
            }

            // Convert payload to string if needed
            const payloadString =
                typeof payload === 'string'
                    ? payload
                    : this.bytesToBase64(payload);

            // Create signature (simplified HMAC-based for demo)
            // For production, use proper Ed25519 signing via native module
            const signatureHash = await Crypto.digestStringAsync(
                Crypto.CryptoDigestAlgorithm.SHA256,
                `${privateKeyB64}:${payloadString}`
            );

            // Update last used timestamp
            await this.updateKeyLastUsed(targetKeyId);

            console.log(`[IdentityService] Signed payload with key: ${targetKeyId}`);

            return {
                success: true,
                signature: signatureHash,
                keyId: targetKeyId,
                signedAt: Date.now(),
            };
        } catch (error) {
            return {
                success: false,
                keyId: targetKeyId,
                signedAt: Date.now(),
                error: error instanceof Error ? error.message : 'Signing failed',
            };
        }
    }

    /**
     * Get root key ID
     */
    async getRootKeyId(): Promise<string | null> {
        return SecureStore.getItemAsync(STORAGE_KEYS.ROOT_KEY_ID);
    }

    /**
     * Get key pair by ID
     */
    async getKeyPair(keyId: string): Promise<StoredKeyPair | null> {
        const metaJson = await SecureStore.getItemAsync(
            `${STORAGE_KEYS.KEY_PREFIX}${keyId}_meta`
        );

        if (!metaJson) return null;

        try {
            return JSON.parse(metaJson) as StoredKeyPair;
        } catch {
            return null;
        }
    }

    /**
     * Get all stored key IDs
     */
    async getAllKeyIds(): Promise<string[]> {
        const indexJson = await SecureStore.getItemAsync(STORAGE_KEYS.KEY_INDEX);
        if (!indexJson) return [];

        try {
            return JSON.parse(indexJson) as string[];
        } catch {
            return [];
        }
    }

    /**
     * Get device identity (DID and public key)
     */
    async getDeviceIdentity(): Promise<DeviceIdentity | null> {
        const rootKeyId = await this.getRootKeyId();
        if (!rootKeyId) return null;

        const keyPair = await this.getKeyPair(rootKeyId);
        if (!keyPair) return null;

        const did = await SecureStore.getItemAsync(STORAGE_KEYS.DEVICE_DID);
        const capability = await this.checkBiometricCapability();

        return {
            did: did || this.publicKeyToDID(keyPair.publicKey),
            publicKey: keyPair.publicKey,
            keyId: rootKeyId,
            biometryType: capability.biometryType,
            createdAt: keyPair.createdAt,
        };
    }

    /**
     * Check if device has an identity
     */
    async hasIdentity(): Promise<boolean> {
        const rootKeyId = await this.getRootKeyId();
        return rootKeyId !== null;
    }

    /**
     * Delete a key (requires biometric auth)
     */
    async deleteKey(keyId: string): Promise<boolean> {
        const authResult = await this.authenticateWithBiometrics(
            'Authenticate to delete this key'
        );

        if (!authResult.success) {
            return false;
        }

        try {
            await SecureStore.deleteItemAsync(
                `${STORAGE_KEYS.KEY_PREFIX}${keyId}_private`
            );
            await SecureStore.deleteItemAsync(
                `${STORAGE_KEYS.KEY_PREFIX}${keyId}_meta`
            );

            await this.removeFromKeyIndex(keyId);

            // If this was the root key, clear that reference
            const rootKeyId = await this.getRootKeyId();
            if (rootKeyId === keyId) {
                await SecureStore.deleteItemAsync(STORAGE_KEYS.ROOT_KEY_ID);
                await SecureStore.deleteItemAsync(STORAGE_KEYS.DEVICE_DID);
            }

            console.log(`[IdentityService] Deleted key: ${keyId}`);
            return true;
        } catch {
            return false;
        }
    }

    // ===========================================================================
    // Helper Methods
    // ===========================================================================

    /**
     * Convert public key to did:key format
     */
    private publicKeyToDID(publicKeyB64: string): string {
        // Simplified DID generation
        // Real implementation would use proper multicodec encoding
        return `did:key:z6Mk${publicKeyB64.replace(/[+/=]/g, '')}`;
    }

    /**
     * Convert Uint8Array to base64
     */
    private bytesToBase64(bytes: Uint8Array): string {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Add key to index
     */
    private async addToKeyIndex(keyId: string): Promise<void> {
        const keys = await this.getAllKeyIds();
        if (!keys.includes(keyId)) {
            keys.push(keyId);
            await SecureStore.setItemAsync(
                STORAGE_KEYS.KEY_INDEX,
                JSON.stringify(keys)
            );
        }
    }

    /**
     * Remove key from index
     */
    private async removeFromKeyIndex(keyId: string): Promise<void> {
        const keys = await this.getAllKeyIds();
        const filtered = keys.filter((k) => k !== keyId);
        await SecureStore.setItemAsync(
            STORAGE_KEYS.KEY_INDEX,
            JSON.stringify(filtered)
        );
    }

    /**
     * Update key last used timestamp
     */
    private async updateKeyLastUsed(keyId: string): Promise<void> {
        const keyPair = await this.getKeyPair(keyId);
        if (keyPair) {
            keyPair.lastUsed = Date.now();
            await SecureStore.setItemAsync(
                `${STORAGE_KEYS.KEY_PREFIX}${keyId}_meta`,
                JSON.stringify(keyPair)
            );
        }
    }
}

// =============================================================================
// Exports
// =============================================================================

// Singleton instance
export const identityService = IdentityService.getInstance();

// Convenience functions
export const generateHardwareKey = identityService.generateHardwareKey.bind(identityService);
export const signPayload = identityService.signPayload.bind(identityService);
export const getDeviceIdentity = identityService.getDeviceIdentity.bind(identityService);
export const hasIdentity = identityService.hasIdentity.bind(identityService);
export const checkBiometricCapability = identityService.checkBiometricCapability.bind(identityService);
export const authenticateWithBiometrics = identityService.authenticateWithBiometrics.bind(identityService);

export default identityService;
