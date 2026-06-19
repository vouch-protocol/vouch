/**
 * Vouch Extension - Bridge Migration & Proxy Mode
 * 
 * Handles:
 * 1. Detection of running Bridge Daemon
 * 2. Key migration from chrome.storage to Bridge
 * 3. Proxy mode for forwarding sign requests to Bridge
 * 
 * After migration:
 * - Local keys are wiped from chrome.storage
 * - Extension operates in "proxy" mode
 * - All signing is delegated to the Bridge daemon
 */

// =============================================================================
// Configuration
// =============================================================================

const BRIDGE_URL = 'http://127.0.0.1:7823';
const BRIDGE_CHECK_INTERVAL = 30000; // Check every 30 seconds

// Note: Using BRIDGE_STORAGE_KEYS to avoid conflict with background.js STORAGE_KEYS
const BRIDGE_STORAGE_KEYS = {
    MODE: 'vouch_mode',           // 'local' | 'proxy'
    SECRET_KEY: 'vouch_secret_key',
    PUBLIC_KEY: 'vouch_public_key',
    BRIDGE_DID: 'vouch_bridge_did',
    MIGRATED_AT: 'vouch_migrated_at',
};

// =============================================================================
// Bridge Connection
// =============================================================================

/**
 * Check if the Bridge Daemon is running
 */
async function isBridgeAvailable() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);

        const response = await fetch(`${BRIDGE_URL}/status`, {
            signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (!response.ok) return false;

        const data = await response.json();
        return data.status === 'ok';
    } catch (e) {
        return false;
    }
}

/**
 * Check if Bridge has keys
 */
async function bridgeHasKeys() {
    try {
        const response = await fetch(`${BRIDGE_URL}/status`);
        const data = await response.json();
        return data.has_keys === true;
    } catch (e) {
        return false;
    }
}

/**
 * Get public key from Bridge
 */
async function getBridgePublicKey() {
    const response = await fetch(`${BRIDGE_URL}/keys/public`);
    if (!response.ok) {
        throw new Error('Failed to get public key from Bridge');
    }
    return response.json();
}

/**
 * Sign content via Bridge (triggers consent popup)
 */
async function signViaBridge(content, origin) {
    const response = await fetch(`${BRIDGE_URL}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, origin }),
    });

    if (response.status === 403) {
        throw new Error('Signature request denied by user');
    }

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Signing failed');
    }

    return response.json();
}

// =============================================================================
// Migration Logic
// =============================================================================

/**
 * Check current mode
 */
async function getCurrentMode() {
    const result = await chrome.storage.local.get([BRIDGE_STORAGE_KEYS.MODE]);
    return result[BRIDGE_STORAGE_KEYS.MODE] || 'local';
}

/**
 * Set mode to proxy
 */
async function setProxyMode(bridgeDid) {
    await chrome.storage.local.set({
        [BRIDGE_STORAGE_KEYS.MODE]: 'proxy',
        [BRIDGE_STORAGE_KEYS.BRIDGE_DID]: bridgeDid,
        [BRIDGE_STORAGE_KEYS.MIGRATED_AT]: new Date().toISOString(),
    });
}

/**
 * Check if extension has local keys
 */
async function hasLocalKeys() {
    const result = await chrome.storage.local.get([
        BRIDGE_STORAGE_KEYS.SECRET_KEY,
        BRIDGE_STORAGE_KEYS.PUBLIC_KEY,
    ]);
    return !!(result[BRIDGE_STORAGE_KEYS.SECRET_KEY] && result[BRIDGE_STORAGE_KEYS.PUBLIC_KEY]);
}

/**
 * Export keys to Bridge Daemon
 * 
 * This sends the private key to the Bridge's /import-key endpoint.
 * The Bridge will show a consent popup and store in system keyring.
 */
async function exportKeysToBridge() {
    // Get local keys
    const stored = await chrome.storage.local.get([
        BRIDGE_STORAGE_KEYS.SECRET_KEY,
        BRIDGE_STORAGE_KEYS.PUBLIC_KEY,
    ]);

    if (!stored[BRIDGE_STORAGE_KEYS.SECRET_KEY] || !stored[BRIDGE_STORAGE_KEYS.PUBLIC_KEY]) {
        throw new Error('No local keys to export');
    }

    // Send to Bridge
    const response = await fetch(`${BRIDGE_URL}/import-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            private_key_hex: stored[BRIDGE_STORAGE_KEYS.SECRET_KEY],
            public_key_hex: stored[BRIDGE_STORAGE_KEYS.PUBLIC_KEY],
            source: 'browser-extension',
        }),
    });

    if (response.status === 403) {
        throw new Error('Key import denied by user');
    }

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Key import failed');
    }

    return response.json();
}

/**
 * Wipe local keys after successful migration
 */
async function wipeLocalKeys() {
    await chrome.storage.local.remove([
        BRIDGE_STORAGE_KEYS.SECRET_KEY,
        BRIDGE_STORAGE_KEYS.PUBLIC_KEY,
    ]);
    console.log('Vouch: Local keys wiped after migration');
}

/**
 * Full migration flow:
 * 1. Check Bridge is available
 * 2. Export keys to Bridge
 * 3. Wipe local keys
 * 4. Switch to proxy mode
 */
async function migrateKeysToBridge() {
    console.log('Vouch: Starting key migration to Bridge...');

    // Verify Bridge is running
    if (!await isBridgeAvailable()) {
        throw new Error('Bridge Daemon is not running');
    }

    // Check if we have keys to migrate
    if (!await hasLocalKeys()) {
        console.log('Vouch: No local keys to migrate');
        return { success: false, message: 'No local keys to migrate' };
    }

    // Export to Bridge (will show consent popup)
    const importResult = await exportKeysToBridge();

    if (!importResult.success) {
        throw new Error('Key import failed');
    }

    // Wipe local keys
    await wipeLocalKeys();

    // Switch to proxy mode
    await setProxyMode(importResult.did);

    console.log('Vouch: Migration complete!', importResult);

    return {
        success: true,
        did: importResult.did,
        fingerprint: importResult.fingerprint,
        message: 'Keys migrated to Bridge Daemon',
    };
}

// =============================================================================
// Proxy Mode Handlers
// =============================================================================

/**
 * Get identity - uses Bridge if in proxy mode
 */
async function getIdentity() {
    const mode = await getCurrentMode();

    if (mode === 'proxy' && await isBridgeAvailable()) {
        const bridgeKey = await getBridgePublicKey();
        return {
            publicKey: bridgeKey.public_key,
            did: bridgeKey.did,
            fingerprint: bridgeKey.fingerprint,
            mode: 'proxy',
        };
    }

    // Fall back to local
    const stored = await chrome.storage.local.get([BRIDGE_STORAGE_KEYS.PUBLIC_KEY]);
    if (!stored[BRIDGE_STORAGE_KEYS.PUBLIC_KEY]) {
        throw new Error('No keys available');
    }

    return {
        publicKey: stored[BRIDGE_STORAGE_KEYS.PUBLIC_KEY],
        mode: 'local',
    };
}

/**
 * Sign content - uses Bridge if in proxy mode
 */
async function signContent(content, origin) {
    const mode = await getCurrentMode();

    if (mode === 'proxy' && await isBridgeAvailable()) {
        console.log('Vouch: Signing via Bridge (proxy mode)');
        return signViaBridge(content, origin);
    }

    // Fall back to local signing
    console.log('Vouch: Signing locally');
    return signLocally(content, origin);
}

/**
 * Local signing (existing logic)
 */
async function signLocally(content, origin) {
    // This uses the existing local signing logic from background.js
    // Implementation depends on existing code
    throw new Error('Local signing not implemented in this module');
}

// =============================================================================
// UI Notification for Migration
// =============================================================================

/**
 * Show migration prompt to user
 */
async function showMigrationPrompt() {
    // Check if Bridge is available and we have local keys
    const bridgeAvailable = await isBridgeAvailable();
    const localKeys = await hasLocalKeys();
    const mode = await getCurrentMode();

    if (!bridgeAvailable || !localKeys || mode === 'proxy') {
        return null;  // No migration needed
    }

    // Return migration status for popup UI
    return {
        showMigrationPrompt: true,
        message: 'Vouch Bridge detected! Would you like to migrate your keys for better security?',
        benefits: [
            'Keys stored in system keyring (more secure)',
            'Works across all apps (not just browser)',
            'Signature consent popups',
        ],
    };
}

// =============================================================================
// Periodic Bridge Check
// =============================================================================

let bridgeCheckInterval = null;

/**
 * Start checking for Bridge availability
 */
function startBridgeCheck() {
    if (bridgeCheckInterval) return;

    bridgeCheckInterval = setInterval(async () => {
        const bridgeAvailable = await isBridgeAvailable();
        const mode = await getCurrentMode();
        const localKeys = await hasLocalKeys();

        if (bridgeAvailable && localKeys && mode === 'local') {
            // Bridge is available and we have local keys - notify popup
            console.log('Vouch: Bridge detected, migration available');
            // Could set a badge or send notification
            chrome.action.setBadgeText({ text: '!' });
            chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
        } else if (mode === 'proxy') {
            chrome.action.setBadgeText({ text: '' });
        }
    }, BRIDGE_CHECK_INTERVAL);

    // Run immediately
    setTimeout(() => bridgeCheckInterval, 0);
}

function stopBridgeCheck() {
    if (bridgeCheckInterval) {
        clearInterval(bridgeCheckInterval);
        bridgeCheckInterval = null;
    }
}

// =============================================================================
// Message Handlers (Extension API)
// =============================================================================

// Handle messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkBridgeStatus') {
        (async () => {
            const available = await isBridgeAvailable();
            const mode = await getCurrentMode();
            const hasKeys = await hasLocalKeys();
            const bridgeHas = await bridgeHasKeys();

            sendResponse({
                bridgeAvailable: available,
                mode: mode,
                hasLocalKeys: hasKeys,
                bridgeHasKeys: bridgeHas,
            });
        })();
        return true;
    }

    if (message.action === 'migrateKeys') {
        (async () => {
            try {
                const result = await migrateKeysToBridge();
                sendResponse({ success: true, ...result });
            } catch (error) {
                sendResponse({ success: false, error: error.message });
            }
        })();
        return true;
    }

    if (message.action === 'getMigrationPrompt') {
        (async () => {
            const prompt = await showMigrationPrompt();
            sendResponse(prompt);
        })();
        return true;
    }

    if (message.action === 'getIdentity') {
        (async () => {
            try {
                const identity = await getIdentity();
                sendResponse({ success: true, ...identity });
            } catch (error) {
                sendResponse({ success: false, error: error.message });
            }
        })();
        return true;
    }

    if (message.action === 'signContent') {
        (async () => {
            try {
                const result = await signContent(message.content, message.origin);
                sendResponse({ success: true, ...result });
            } catch (error) {
                sendResponse({ success: false, error: error.message });
            }
        })();
        return true;
    }
});

// Start Bridge check on extension load
startBridgeCheck();

console.log('Vouch: Bridge migration module loaded');

// =============================================================================
// Exports (for use in background.js)
// =============================================================================

if (typeof module !== 'undefined') {
    module.exports = {
        isBridgeAvailable,
        migrateKeysToBridge,
        getCurrentMode,
        getIdentity,
        signContent,
        showMigrationPrompt,
    };
}
