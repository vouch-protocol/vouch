/**
 * Vouch Chrome Extension - Background Service Worker
 * 
 * Implements the Hybrid Bridge Architecture:
 * 
 * 1. BRIDGE MODE (Primary): When the Vouch Daemon is running, the extension
 *    acts as a dumb proxy, forwarding all signing requests to the daemon.
 *    The daemon holds the keys securely in the OS keyring.
 * 
 * 2. SECURE FALLBACK (Secondary): When the daemon is offline, we use
 *    IndexedDB + WebCrypto with non-extractable keys for local signing.
 * 
 * 3. MIGRATION: On first run, legacy keys from chrome.storage are migrated
 *    to either the Bridge daemon (preferred) or IndexedDB, then wiped.
 * 
 * @author Ramprasad Anandam Gaddam
 */

import { SecureKeyManager, keyManager } from './secure-key-manager';

// =============================================================================
// Types
// =============================================================================

type OperatingMode = 'bridge' | 'local' | 'none';

interface SignRequest {
    content: string;
    origin: string;
    metadata?: Record<string, unknown>;
}

interface SignResult {
    signature: string;
    publicKey: string;
    did: string;
    timestamp: string;
    contentHash: string;
}

interface DaemonStatus {
    status: string;
    version: string;
    has_keys: boolean;
}

// =============================================================================
// Configuration
// =============================================================================

const DAEMON_URL = 'http://127.0.0.1:21000';
const DAEMON_CHECK_INTERVAL = 30000; // 30 seconds
const CONNECTION_TIMEOUT = 2000;

// Legacy storage keys (for migration)
const LEGACY_KEYS = {
    SECRET_KEY: 'vouch_secret_key',
    PUBLIC_KEY: 'vouch_public_key',
    MIGRATION_DONE: 'vouch_migration_v2_done',
};

// =============================================================================
// State
// =============================================================================

let operatingMode: OperatingMode = 'none';
let daemonConnected = false;
let daemonCheckInterval: ReturnType<typeof setInterval> | null = null;

// =============================================================================
// Daemon Communication (Bridge Mode)
// =============================================================================

/**
 * Check if the Vouch Daemon is running.
 */
async function checkDaemonStatus(): Promise<boolean> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONNECTION_TIMEOUT);

        const response = await fetch(`${DAEMON_URL}/status`, {
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) return false;

        const data = await response.json() as DaemonStatus;
        return data.status === 'ok';
    } catch {
        return false;
    }
}

/**
 * Sign content via the Bridge daemon.
 */
async function signViaBridge(request: SignRequest): Promise<SignResult> {
    const response = await fetch(`${DAEMON_URL}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            content: request.content,
            origin: request.origin,
            ...request.metadata,
        }),
    });

    if (response.status === 403) {
        throw new Error('USER_DENIED_SIGNATURE');
    }

    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.detail || 'Signing failed');
    }

    const data = await response.json();
    return {
        signature: data.signature,
        publicKey: data.public_key,
        did: data.did,
        timestamp: data.timestamp,
        contentHash: data.content_hash,
    };
}

/**
 * Get public key from Bridge daemon.
 */
async function getPublicKeyFromBridge(): Promise<{ publicKey: string; did: string }> {
    const response = await fetch(`${DAEMON_URL}/keys/public`);

    if (!response.ok) {
        throw new Error('Failed to get public key from daemon');
    }

    const data = await response.json();
    return {
        publicKey: data.public_key,
        did: data.did,
    };
}

/**
 * Import a legacy key to the Bridge daemon.
 */
async function importKeyToBridge(
    privateKeyHex: string,
    publicKeyHex: string
): Promise<boolean> {
    try {
        const response = await fetch(`${DAEMON_URL}/import-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                private_key_hex: privateKeyHex,
                public_key_hex: publicKeyHex,
                source: 'chrome-extension-migration',
            }),
        });

        if (response.status === 403) {
            console.log('[Migration] User denied key import');
            return false;
        }

        return response.ok;
    } catch (error) {
        console.error('[Migration] Failed to import key to Bridge:', error);
        return false;
    }
}

// =============================================================================
// Local Signing (Secure Fallback)
// =============================================================================

/**
 * Sign content locally using WebCrypto.
 */
async function signLocally(request: SignRequest): Promise<SignResult> {
    if (!keyManager.hasKeys()) {
        throw new Error('No local keys available');
    }

    const contentBytes = new TextEncoder().encode(request.content);

    // Compute content hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', contentBytes);
    const contentHash = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    // Sign
    const signature = await keyManager.sign(contentBytes);

    // Base64 encode signature
    const signatureBase64 = btoa(String.fromCharCode(...signature));

    return {
        signature: signatureBase64,
        publicKey: keyManager.getPublicKeyHex(),
        did: keyManager.getDID(),
        timestamp: new Date().toISOString(),
        contentHash,
    };
}

// =============================================================================
// Migration Logic
// =============================================================================

/**
 * Check for legacy keys and migrate them.
 * 
 * Flow:
 * 1. Check if migration already done
 * 2. Check for legacy keys in chrome.storage
 * 3. If Bridge is available -> Push keys to Bridge
 * 4. If Bridge is offline -> Migrate to IndexedDB
 * 5. WIPE legacy keys from chrome.storage
 */
async function performMigration(): Promise<void> {
    // Check if migration already done
    const { [LEGACY_KEYS.MIGRATION_DONE]: migrationDone } =
        await chrome.storage.local.get(LEGACY_KEYS.MIGRATION_DONE);

    if (migrationDone) {
        console.log('[Migration] Already completed');
        return;
    }

    // Check for legacy keys
    const legacyData = await chrome.storage.local.get([
        LEGACY_KEYS.SECRET_KEY,
        LEGACY_KEYS.PUBLIC_KEY,
    ]);

    const hasLegacyKeys = !!(
        legacyData[LEGACY_KEYS.SECRET_KEY] &&
        legacyData[LEGACY_KEYS.PUBLIC_KEY]
    );

    if (!hasLegacyKeys) {
        console.log('[Migration] No legacy keys found');
        await markMigrationDone();
        return;
    }

    console.log('[Migration] Found legacy keys in chrome.storage');

    const privateKeyHex = legacyData[LEGACY_KEYS.SECRET_KEY];
    const publicKeyHex = legacyData[LEGACY_KEYS.PUBLIC_KEY];

    // Try to push to Bridge first
    if (daemonConnected) {
        console.log('[Migration] Bridge is online, pushing keys to daemon...');

        const success = await importKeyToBridge(privateKeyHex, publicKeyHex);

        if (success) {
            console.log('[Migration] Keys successfully pushed to Bridge daemon');
            await wipeLegacyKeys();
            await markMigrationDone();
            return;
        }

        console.warn('[Migration] Bridge import failed or was denied');
    }

    // Fallback: Migrate to IndexedDB
    console.log('[Migration] Migrating to IndexedDB...');

    // Note: WebCrypto can't import raw Ed25519 keys in most browsers
    // We generate new secure keys instead
    // The user will need to re-establish their identity
    console.warn('[Migration] Cannot import legacy keys to WebCrypto (Ed25519 import not supported)');
    console.warn('[Migration] Generating new secure keys instead');

    await keyManager.init();
    if (!keyManager.hasKeys()) {
        await keyManager.generateKeys();
    }

    // Wipe legacy keys regardless
    await wipeLegacyKeys();
    await markMigrationDone();

    console.log('[Migration] Complete - new secure keys generated');
}

/**
 * Wipe legacy keys from chrome.storage.
 */
async function wipeLegacyKeys(): Promise<void> {
    await chrome.storage.local.remove([
        LEGACY_KEYS.SECRET_KEY,
        LEGACY_KEYS.PUBLIC_KEY,
    ]);
    console.log('[Migration] Legacy keys WIPED from chrome.storage');
}

/**
 * Mark migration as complete.
 */
async function markMigrationDone(): Promise<void> {
    await chrome.storage.local.set({
        [LEGACY_KEYS.MIGRATION_DONE]: true,
    });
}

// =============================================================================
// Mode Management
// =============================================================================

/**
 * Determine the operating mode based on available services.
 */
async function determineMode(): Promise<OperatingMode> {
    // Check Bridge first (preferred)
    daemonConnected = await checkDaemonStatus();

    if (daemonConnected) {
        console.log('[Vouch] Bridge daemon connected - using Bridge Mode');
        return 'bridge';
    }

    // Fallback to local
    if (keyManager.hasKeys()) {
        console.log('[Vouch] Using Local Mode (secure fallback)');
        return 'local';
    }

    console.log('[Vouch] No signing capability available');
    return 'none';
}

/**
 * Start periodic daemon check.
 */
function startDaemonCheck(): void {
    if (daemonCheckInterval) return;

    daemonCheckInterval = setInterval(async () => {
        const wasConnected = daemonConnected;
        daemonConnected = await checkDaemonStatus();

        if (daemonConnected && !wasConnected) {
            console.log('[Vouch] Bridge daemon is now available');
            operatingMode = 'bridge';
            // Update badge
            chrome.action.setBadgeText({ text: '🔐' });
            chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
        } else if (!daemonConnected && wasConnected) {
            console.log('[Vouch] Bridge daemon disconnected, falling back to local');
            operatingMode = keyManager.hasKeys() ? 'local' : 'none';
            chrome.action.setBadgeText({ text: '!' });
            chrome.action.setBadgeBackgroundColor({ color: '#FF9800' });
        }
    }, DAEMON_CHECK_INTERVAL);
}

// =============================================================================
// Message Handler
// =============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender)
        .then(sendResponse)
        .catch(error => {
            console.error('[Vouch] Message handler error:', error);
            sendResponse({ success: false, error: error.message });
        });

    return true; // Keep channel open for async response
});

async function handleMessage(
    message: { action: string;[key: string]: unknown },
    sender: chrome.runtime.MessageSender
): Promise<unknown> {
    const { action } = message;

    switch (action) {
        case 'getStatus':
            return {
                success: true,
                mode: operatingMode,
                daemonConnected,
                hasLocalKeys: keyManager.hasKeys(),
            };

        case 'sign': {
            const { content, origin } = message as {
                action: string;
                content: string;
                origin?: string;
            };

            const signOrigin = origin || sender.origin || 'unknown';

            if (operatingMode === 'bridge') {
                try {
                    const result = await signViaBridge({ content, origin: signOrigin });
                    return { success: true, ...result };
                } catch (error) {
                    if ((error as Error).message === 'USER_DENIED_SIGNATURE') {
                        return { success: false, error: 'User denied signature' };
                    }
                    throw error;
                }
            } else if (operatingMode === 'local') {
                const result = await signLocally({ content, origin: signOrigin });
                return { success: true, ...result };
            } else {
                return { success: false, error: 'No signing capability available' };
            }
        }

        case 'getPublicKey': {
            if (operatingMode === 'bridge') {
                const { publicKey, did } = await getPublicKeyFromBridge();
                return { success: true, publicKey, did };
            } else if (operatingMode === 'local') {
                return {
                    success: true,
                    publicKey: keyManager.getPublicKeyHex(),
                    did: keyManager.getDID(),
                };
            } else {
                return { success: false, error: 'No keys available' };
            }
        }

        case 'generateKeys': {
            if (operatingMode === 'bridge') {
                return { success: false, error: 'Use Bridge daemon to manage keys' };
            }

            await keyManager.generateKeys();
            operatingMode = 'local';

            return {
                success: true,
                did: keyManager.getDID(),
            };
        }

        case 'forceMigration': {
            await performMigration();
            return { success: true };
        }

        default:
            return { success: false, error: `Unknown action: ${action}` };
    }
}

// =============================================================================
// Initialization
// =============================================================================

async function initialize(): Promise<void> {
    console.log('[Vouch] Initializing Extension...');

    // Initialize secure key manager
    await keyManager.init();

    // Check daemon connectivity
    daemonConnected = await checkDaemonStatus();

    // Perform migration if needed
    await performMigration();

    // Determine operating mode
    operatingMode = await determineMode();

    // Start daemon monitoring
    startDaemonCheck();

    // Update UI
    if (operatingMode === 'bridge') {
        chrome.action.setBadgeText({ text: '' });
    } else if (operatingMode === 'local') {
        chrome.action.setBadgeText({ text: 'L' });
        chrome.action.setBadgeBackgroundColor({ color: '#2196F3' });
    } else {
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: '#f44336' });
    }

    console.log(`[Vouch] Initialized in ${operatingMode} mode`);
}

// Run initialization
initialize().catch(console.error);

// =============================================================================
// Exports (for testing)
// =============================================================================

export {
    operatingMode,
    daemonConnected,
    checkDaemonStatus,
    signViaBridge,
    signLocally,
    performMigration,
};
