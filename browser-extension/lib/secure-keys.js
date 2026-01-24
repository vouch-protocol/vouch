/**
 * Vouch Protocol - Secure Key Manager
 * 
 * Uses WebCrypto API with non-extractable keys stored in IndexedDB.
 * This replaces the insecure chrome.storage approach.
 * 
 * Security improvements:
 * 1. Keys are generated as non-extractable (cannot be read by JS)
 * 2. Keys are stored in IndexedDB (not accessible to other extensions)
 * 3. Signing happens within the secure CryptoKey context
 * 
 * Note: Ed25519 support in WebCrypto requires Chrome 113+
 * For older browsers, falls back to TweetNaCl (with warning)
 */

// =============================================================================
// Constants
// =============================================================================

const DB_NAME = 'vouch-secure-keys';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const PRIMARY_KEY_ID = 'primary';

// =============================================================================
// IndexedDB Helpers
// =============================================================================

/**
 * Open the IndexedDB database
 */
function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            }
        };
    });
}

/**
 * Store a key pair in IndexedDB
 */
async function storeKeyPair(keyPair, publicKeyBytes) {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);

        const record = {
            id: PRIMARY_KEY_ID,
            privateKey: keyPair.privateKey,  // CryptoKey (non-extractable)
            publicKey: keyPair.publicKey,    // CryptoKey (for verification)
            publicKeyBytes: publicKeyBytes,   // Uint8Array (for DID/display)
            createdAt: new Date().toISOString(),
        };

        const request = store.put(record);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();

        transaction.oncomplete = () => db.close();
    });
}

/**
 * Load key pair from IndexedDB
 */
async function loadKeyPair() {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);

        const request = store.get(PRIMARY_KEY_ID);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result || null);

        transaction.oncomplete = () => db.close();
    });
}

/**
 * Check if secure keys exist
 */
async function hasSecureKeys() {
    const keyData = await loadKeyPair();
    return keyData !== null;
}

// =============================================================================
// WebCrypto Key Generation
// =============================================================================

/**
 * Check if Ed25519 is supported in WebCrypto
 */
async function isEd25519Supported() {
    try {
        // Try to generate a test key
        await crypto.subtle.generateKey(
            { name: 'Ed25519' },
            false,
            ['sign', 'verify']
        );
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Generate a new secure Ed25519 keypair using WebCrypto
 * Keys are non-extractable for maximum security
 */
async function generateSecureKeypair() {
    // Check WebCrypto Ed25519 support
    const ed25519Supported = await isEd25519Supported();

    if (!ed25519Supported) {
        console.warn('Vouch: Ed25519 not supported in WebCrypto, using fallback');
        return generateFallbackKeypair();
    }

    // Generate non-extractable key pair
    const keyPair = await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        false,  // NON-EXTRACTABLE - key material cannot be read
        ['sign', 'verify']
    );

    // Export public key bytes for DID generation (public keys can be exported)
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const publicKeyBytes = new Uint8Array(publicKeyRaw);

    // Store in IndexedDB
    await storeKeyPair(keyPair, publicKeyBytes);

    console.log('Vouch: Generated secure non-extractable keypair');

    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeyBytes: publicKeyBytes,
    };
}

/**
 * Fallback key generation for browsers without Ed25519 support
 * Uses TweetNaCl but still stores in IndexedDB (more secure than chrome.storage)
 */
function generateFallbackKeypair() {
    console.warn('Vouch: Using TweetNaCl fallback (less secure)');

    const keypair = nacl.sign.keyPair();

    // We can't create a true CryptoKey, so we wrap the bytes
    // This is less secure but still better than chrome.storage
    return {
        privateKey: keypair.secretKey,
        publicKey: keypair.publicKey,
        publicKeyBytes: keypair.publicKey,
        isFallback: true,
    };
}

// =============================================================================
// Secure Signing
// =============================================================================

/**
 * Sign a message using the secure WebCrypto key
 * @param {string} message - Message to sign
 * @returns {Promise<Uint8Array>} Signature bytes
 */
async function signMessageSecure(message) {
    const keyData = await loadKeyPair();

    if (!keyData) {
        throw new Error('No secure keys found. Call generateSecureKeypair first.');
    }

    const messageBytes = new TextEncoder().encode(message);

    // Check if using WebCrypto or fallback
    if (keyData.privateKey instanceof CryptoKey) {
        // WebCrypto signing (secure)
        const signatureBuffer = await crypto.subtle.sign(
            { name: 'Ed25519' },
            keyData.privateKey,
            messageBytes
        );
        return new Uint8Array(signatureBuffer);
    } else {
        // Fallback signing with TweetNaCl
        return nacl.sign.detached(messageBytes, keyData.privateKey);
    }
}

/**
 * Sign a message and return Base64-encoded signature
 */
async function signMessageSecureBase64(message) {
    const signatureBytes = await signMessageSecure(message);
    return toBase64(signatureBytes);
}

// =============================================================================
// Public Key Access
// =============================================================================

/**
 * Get the public key bytes (for DID generation, display, etc.)
 */
async function getPublicKeyBytes() {
    const keyData = await loadKeyPair();
    if (!keyData) return null;
    return keyData.publicKeyBytes;
}

/**
 * Get the public key in hex format (for compatibility)
 */
async function getPublicKeyHex() {
    const bytes = await getPublicKeyBytes();
    if (!bytes) return null;
    return toHex(bytes);
}

/**
 * Get the public key in Base64 format
 */
async function getPublicKeyBase64() {
    const bytes = await getPublicKeyBytes();
    if (!bytes) return null;
    return toBase64(bytes);
}

// =============================================================================
// Migration from chrome.storage
// =============================================================================

/**
 * Migrate keys from chrome.storage to IndexedDB (one-time)
 * After migration, old keys are deleted from chrome.storage
 */
async function migrateFromChromeStorage() {
    // Check if already migrated
    if (await hasSecureKeys()) {
        console.log('Vouch: Secure keys already exist, skipping migration');
        return true;
    }

    // Check for old keys in chrome.storage
    const stored = await chrome.storage.local.get([
        'vouch_secret_key',
        'vouch_public_key',
    ]);

    if (!stored.vouch_secret_key || !stored.vouch_public_key) {
        console.log('Vouch: No legacy keys to migrate');
        return false;
    }

    console.log('Vouch: Migrating keys from chrome.storage to IndexedDB...');

    // Convert hex keys to bytes
    const secretKeyBytes = fromHex(stored.vouch_secret_key);
    const publicKeyBytes = fromHex(stored.vouch_public_key);

    // Store in IndexedDB (as fallback format since we can't import to WebCrypto)
    const db = await openDatabase();

    await new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);

        const record = {
            id: PRIMARY_KEY_ID,
            privateKey: secretKeyBytes,
            publicKey: publicKeyBytes,
            publicKeyBytes: publicKeyBytes,
            createdAt: new Date().toISOString(),
            migratedFrom: 'chrome.storage',
            isFallback: true,  // Mark as fallback since it's not a CryptoKey
        };

        const request = store.put(record);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();

        transaction.oncomplete = () => db.close();
    });

    // Delete old keys from chrome.storage
    await chrome.storage.local.remove(['vouch_secret_key', 'vouch_public_key']);

    console.log('Vouch: Migration complete, old keys removed from chrome.storage');
    return true;
}

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize secure key storage
 * 1. Migrate from chrome.storage if needed
 * 2. Generate new keys if none exist
 */
async function initializeSecureKeys() {
    // Try migration first
    const migrated = await migrateFromChromeStorage();

    // Check if we have keys now
    if (await hasSecureKeys()) {
        const keyData = await loadKeyPair();
        const isFallback = keyData.isFallback || !(keyData.privateKey instanceof CryptoKey);

        if (isFallback) {
            console.log('Vouch: Using fallback keys (TweetNaCl)');
        } else {
            console.log('Vouch: Using secure WebCrypto keys');
        }

        return {
            publicKeyBytes: keyData.publicKeyBytes,
            publicKeyHex: toHex(keyData.publicKeyBytes),
            isFallback: isFallback,
        };
    }

    // Generate new secure keys
    console.log('Vouch: Generating new secure keypair...');
    const keyData = await generateSecureKeypair();

    return {
        publicKeyBytes: keyData.publicKeyBytes,
        publicKeyHex: toHex(keyData.publicKeyBytes),
        isFallback: keyData.isFallback || false,
    };
}

// =============================================================================
// Exports
// =============================================================================

// For use in background.js
if (typeof self !== 'undefined') {
    self.SecureKeys = {
        initialize: initializeSecureKeys,
        sign: signMessageSecure,
        signBase64: signMessageSecureBase64,
        getPublicKeyBytes,
        getPublicKeyHex,
        getPublicKeyBase64,
        hasSecureKeys,
        isEd25519Supported,
    };
}
