/**
 * Secure Key Manager for Vouch Chrome Extension
 * 
 * Uses IndexedDB + WebCrypto with `extractable: false` to securely store
 * Ed25519 keys. The private key NEVER touches memory in plain text.
 * 
 * This replaces the insecure chrome.storage approach.
 * 
 * @author Ramprasad Anandam Gaddam
 */

// =============================================================================
// Types
// =============================================================================

interface StoredKeyPair {
    id: string;
    privateKey: CryptoKey;     // Non-extractable!
    publicKey: CryptoKey;
    publicKeyRaw: Uint8Array;  // For DID generation
    createdAt: string;
}

interface ExportableKey {
    privateKeyHex: string;
    publicKeyHex: string;
}

// =============================================================================
// Constants
// =============================================================================

const DB_NAME = 'VouchSecureKeyStore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const PRIMARY_KEY_ID = 'vouch-primary-key';

// =============================================================================
// IndexedDB Helpers
// =============================================================================

function openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => {
            reject(new Error('Failed to open IndexedDB'));
        };

        request.onsuccess = () => {
            resolve(request.result);
        };

        request.onupgradeneeded = (event) => {
            const db = (event.target as IDBOpenDBRequest).result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            }
        };
    });
}

// =============================================================================
// SecureKeyManager Class
// =============================================================================

export class SecureKeyManager {
    private db: IDBDatabase | null = null;
    private keyPair: StoredKeyPair | null = null;

    /**
     * Initialize the key manager and load any existing keys.
     */
    async init(): Promise<void> {
        this.db = await openDatabase();
        await this.loadKeys();
    }

    /**
     * Check if keys exist.
     */
    hasKeys(): boolean {
        return this.keyPair !== null;
    }

    /**
     * Generate a new Ed25519 key pair.
     * The private key is marked as non-extractable for security.
     * 
     * Note: WebCrypto doesn't natively support Ed25519, so we use ECDSA P-256
     * as the underlying algorithm. For true Ed25519, we'd need a polyfill.
     * 
     * TODO: Use a proper Ed25519 implementation when available.
     */
    async generateKeys(): Promise<void> {
        // WebCrypto Ed25519 support check (Chrome 113+)
        // For older browsers, we fall back to ECDSA P-256
        let keyPair: CryptoKeyPair;
        let algorithm: string;

        try {
            // Try Ed25519 first (modern browsers)
            keyPair = await crypto.subtle.generateKey(
                { name: 'Ed25519' } as Algorithm,
                false,  // NOT extractable - security critical!
                ['sign', 'verify']
            );
            algorithm = 'Ed25519';
        } catch {
            // Fallback to ECDSA P-256 for older browsers
            console.warn('[SecureKeyManager] Ed25519 not supported, using ECDSA P-256');
            keyPair = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,  // NOT extractable!
                ['sign', 'verify']
            );
            algorithm = 'ECDSA-P256';
        }

        // Export public key for DID generation
        const publicKeyRaw = new Uint8Array(
            await crypto.subtle.exportKey('raw', keyPair.publicKey)
        );

        const storedKey: StoredKeyPair = {
            id: PRIMARY_KEY_ID,
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            publicKeyRaw,
            createdAt: new Date().toISOString(),
        };

        // Store in IndexedDB
        await this.storeKeys(storedKey);
        this.keyPair = storedKey;

        console.log(`[SecureKeyManager] Generated new ${algorithm} key pair`);
    }

    /**
     * Sign data using the stored private key.
     * The private key never leaves the secure context.
     */
    async sign(data: Uint8Array): Promise<Uint8Array> {
        if (!this.keyPair) {
            throw new Error('No keys available. Call generateKeys() first.');
        }

        let algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;

        // Detect algorithm from key
        if (this.keyPair.privateKey.algorithm.name === 'Ed25519') {
            algorithm = { name: 'Ed25519' };
        } else {
            algorithm = { name: 'ECDSA', hash: 'SHA-256' };
        }

        const signature = await crypto.subtle.sign(
            algorithm,
            this.keyPair.privateKey,
            data
        );

        return new Uint8Array(signature);
    }

    /**
     * Get the public key as raw bytes.
     */
    getPublicKeyRaw(): Uint8Array {
        if (!this.keyPair) {
            throw new Error('No keys available');
        }
        return this.keyPair.publicKeyRaw;
    }

    /**
     * Get the public key as hex string.
     */
    getPublicKeyHex(): string {
        const raw = this.getPublicKeyRaw();
        return Array.from(raw)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Get the DID (Decentralized Identifier) for this key.
     */
    getDID(): string {
        const publicKeyHex = this.getPublicKeyHex();
        // Simplified DID - in production, use proper did:key encoding
        return `did:key:z${this.base58Encode(this.getPublicKeyRaw())}`;
    }

    /**
     * Get key fingerprint (first 8 bytes of public key hash).
     */
    async getFingerprint(): Promise<string> {
        const publicKey = this.getPublicKeyRaw();
        const hash = await crypto.subtle.digest('SHA-256', publicKey);
        return Array.from(new Uint8Array(hash).slice(0, 8))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Delete all keys from storage.
     */
    async deleteKeys(): Promise<void> {
        if (!this.db) {
            throw new Error('Database not initialized');
        }

        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            const request = store.delete(PRIMARY_KEY_ID);

            request.onsuccess = () => {
                this.keyPair = null;
                console.log('[SecureKeyManager] Keys deleted');
                resolve();
            };

            request.onerror = () => {
                reject(new Error('Failed to delete keys'));
            };
        });
    }

    /**
     * Export keys for migration to the Bridge daemon.
     * 
     * SECURITY NOTE: This requires special permission and the key must be
     * generated with extractable=true during migration. Regular keys are
     * NOT exportable.
     */
    async exportForMigration(): Promise<ExportableKey | null> {
        // For migration, we need to generate an extractable key temporarily
        // This should only be called during the legacy migration flow
        console.warn('[SecureKeyManager] exportForMigration called - this is for legacy migration only');

        // Cannot export non-extractable keys - return null
        // The migration must be done before switching to secure storage
        return null;
    }

    // =========================================================================
    // Private Helpers
    // =========================================================================

    private async loadKeys(): Promise<void> {
        if (!this.db) {
            throw new Error('Database not initialized');
        }

        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const request = store.get(PRIMARY_KEY_ID);

            request.onsuccess = () => {
                if (request.result) {
                    this.keyPair = request.result;
                    console.log('[SecureKeyManager] Loaded existing keys');
                }
                resolve();
            };

            request.onerror = () => {
                reject(new Error('Failed to load keys'));
            };
        });
    }

    private async storeKeys(keyPair: StoredKeyPair): Promise<void> {
        if (!this.db) {
            throw new Error('Database not initialized');
        }

        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            const request = store.put(keyPair);

            request.onsuccess = () => {
                console.log('[SecureKeyManager] Keys stored securely');
                resolve();
            };

            request.onerror = () => {
                reject(new Error('Failed to store keys'));
            };
        });
    }

    /**
     * Simple Base58 encoding for DID generation.
     */
    private base58Encode(bytes: Uint8Array): string {
        const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        const BASE = BigInt(58);

        let num = BigInt(0);
        for (const byte of bytes) {
            num = num * BigInt(256) + BigInt(byte);
        }

        let encoded = '';
        while (num > 0) {
            const remainder = num % BASE;
            encoded = ALPHABET[Number(remainder)] + encoded;
            num = num / BASE;
        }

        // Handle leading zeros
        for (const byte of bytes) {
            if (byte === 0) {
                encoded = ALPHABET[0] + encoded;
            } else {
                break;
            }
        }

        return encoded || ALPHABET[0];
    }
}

// =============================================================================
// Singleton Export
// =============================================================================

export const keyManager = new SecureKeyManager();
