/**
 * Example: Using SecureKeyManager in Browser Extension
 *
 * The SecureKeyManager provides secure key storage using IndexedDB and WebCrypto.
 * Private keys are never extractable, ensuring they never leave the browser's 
 * secure storage in plain text.
 */

// Import the manager (from browser-extension/src/secure-key-manager.ts)
// import { SecureKeyManager, KeyType } from './secure-key-manager';

// ============================================================================
// Example 1: Basic Key Generation
// ============================================================================

async function generateNewIdentity() {
    const manager = new SecureKeyManager();

    // Check if we already have keys
    const existingDID = await manager.getDID();
    if (existingDID) {
        console.log('Identity already exists:', existingDID);
        return;
    }

    // Generate new keypair
    // Uses Ed25519 by default, falls back to ECDSA P-256 if not supported
    const keyType = await manager.generateKeys();

    console.log('✅ New identity created!');
    console.log('   Key Type:', keyType);

    // Get the DID
    const did = await manager.getDID();
    console.log('   DID:', did);

    // Get fingerprint
    const fingerprint = await manager.getFingerprint();
    console.log('   Fingerprint:', fingerprint);
}

// ============================================================================
// Example 2: Signing Content
// ============================================================================

async function signWithLocalKeys() {
    const manager = new SecureKeyManager();

    const content = 'Content to sign with local keys';
    const contentBytes = new TextEncoder().encode(content);

    try {
        // Sign the content
        const signature = await manager.sign(contentBytes);

        // signature is an ArrayBuffer
        console.log('✅ Content signed locally!');
        console.log('   Signature length:', signature.byteLength, 'bytes');

        // Convert to base64 for transmission
        const signatureBase64 = btoa(
            String.fromCharCode(...new Uint8Array(signature))
        );
        console.log('   Base64:', signatureBase64.slice(0, 32) + '...');

        return signatureBase64;

    } catch (error) {
        if (error.message.includes('No keys')) {
            console.log('❌ No keys found. Generate first.');
        } else {
            throw error;
        }
    }
}

// ============================================================================
// Example 3: Getting Public Key for Verification
// ============================================================================

async function exportPublicKeyInfo() {
    const manager = new SecureKeyManager();

    // Get raw public key bytes
    const publicKeyRaw = await manager.getPublicKeyRaw();
    console.log('Public Key (raw):', publicKeyRaw.byteLength, 'bytes');

    // Get as hex string
    const publicKeyHex = await manager.getPublicKeyHex();
    console.log('Public Key (hex):', publicKeyHex);

    // Get DID (did:key format)
    const did = await manager.getDID();
    console.log('DID:', did);

    // Get fingerprint (SHA-256 of public key)
    const fingerprint = await manager.getFingerprint();
    console.log('Fingerprint:', fingerprint);

    return {
        publicKey: publicKeyHex,
        did,
        fingerprint,
    };
}

// ============================================================================
// Example 4: Check Available Key Types
// ============================================================================

async function checkKeyTypeSupport() {
    // Ed25519 is preferred but not universally supported
    // ECDSA P-256 is the fallback

    const crypto = window.crypto.subtle;

    // Check Ed25519 support (Chrome 113+)
    let ed25519Supported = false;
    try {
        await crypto.generateKey(
            { name: 'Ed25519' },
            false,
            ['sign', 'verify']
        );
        ed25519Supported = true;
    } catch {
        ed25519Supported = false;
    }

    // ECDSA P-256 is always supported
    const ecdsaSupported = true;

    console.log('Key Type Support:');
    console.log('   Ed25519:', ed25519Supported ? '✅' : '❌');
    console.log('   ECDSA P-256:', ecdsaSupported ? '✅' : '✅');
    console.log('   Recommended:', ed25519Supported ? 'Ed25519' : 'ECDSA P-256');

    return { ed25519Supported, ecdsaSupported };
}

// ============================================================================
// Example 5: Migration Helpers
// ============================================================================

async function checkMigrationNeeded(): Promise<boolean> {
    // Check if there are legacy keys in chrome.storage
    const result = await chrome.storage.local.get([
        'vouch_secret_key',
        'vouch_public_key',
        'vouch_migration_v2_done',
    ]);

    if (result.vouch_migration_v2_done) {
        return false; // Already migrated
    }

    if (result.vouch_secret_key || result.vouch_public_key) {
        console.log('⚠️ Legacy keys found in chrome.storage');
        console.log('   Migration is needed');
        return true;
    }

    return false;
}

async function performMigration() {
    const manager = new SecureKeyManager();

    // 1. Check for legacy keys
    const result = await chrome.storage.local.get(['vouch_secret_key']);

    if (result.vouch_secret_key) {
        console.log('Found legacy secret key');

        // Note: WebCrypto doesn't support importing raw Ed25519 keys
        // with extractable: false. So we generate NEW secure keys instead.

        console.log('Generating new secure keys (legacy keys cannot be imported securely)');
        await manager.generateKeys();

        // 2. Wipe legacy keys from chrome.storage (IMPORTANT!)
        await chrome.storage.local.remove([
            'vouch_secret_key',
            'vouch_public_key',
        ]);
        console.log('✅ Legacy keys wiped from chrome.storage');

        // 3. Mark migration complete
        await chrome.storage.local.set({ vouch_migration_v2_done: true });
        console.log('✅ Migration complete');

        // Get new identity
        const newDID = await manager.getDID();
        console.log('   New DID:', newDID);
    }
}

// ============================================================================
// Example 6: Delete Keys (Factory Reset)
// ============================================================================

async function factoryReset() {
    const manager = new SecureKeyManager();

    // Confirm with user first!
    const confirmed = confirm(
        'This will permanently delete your Vouch identity. Continue?'
    );

    if (!confirmed) {
        console.log('Cancelled');
        return;
    }

    await manager.deleteKeys();
    console.log('✅ Keys deleted');

    // Also clear any other extension data
    await chrome.storage.local.clear();
    console.log('✅ Storage cleared');
}

// ============================================================================
// Usage in Extension Background Script
// ============================================================================

/*
// In background.ts:

import { SecureKeyManager } from './secure-key-manager';

const keyManager = new SecureKeyManager();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'sign') {
    (async () => {
      try {
        const content = new TextEncoder().encode(message.content);
        const signature = await keyManager.sign(content);
        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
        
        sendResponse({
          success: true,
          signature: signatureBase64,
          did: await keyManager.getDID(),
        });
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message,
        });
      }
    })();
    return true; // Keep channel open for async response
  }
});
*/

export {
    generateNewIdentity,
    signWithLocalKeys,
    exportPublicKeyInfo,
    checkKeyTypeSupport,
    checkMigrationNeeded,
    performMigration,
    factoryReset,
};
