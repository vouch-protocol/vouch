/**
 * Example: Background Script Usage
 *
 * Shows how the refactored background.ts handles different operating modes
 * and routes signing requests appropriately.
 */

// ============================================================================
// Operating Mode Types
// ============================================================================

type OperatingMode = 'bridge' | 'local' | 'none';

interface ExtensionState {
    mode: OperatingMode;
    daemonConnected: boolean;
    lastCheck: number;
}

// ============================================================================
// Example: Complete Message Handler
// ============================================================================

const state: ExtensionState = {
    mode: 'none',
    daemonConnected: false,
    lastCheck: 0,
};

// Handler for messages from popup or content scripts
async function handleMessage(
    message: any,
    sender: chrome.runtime.MessageSender
): Promise<any> {
    switch (message.action) {
        case 'getStatus':
            return getStatus();

        case 'sign':
            return signContent(message.content, message.origin);

        case 'getPublicKey':
            return getPublicKey();

        case 'generateKeys':
            return generateKeys();

        case 'forceRefresh':
            return checkDaemonStatus();

        default:
            throw new Error(`Unknown action: ${message.action}`);
    }
}

// ============================================================================
// Example: Status Check
// ============================================================================

async function getStatus() {
    return {
        mode: state.mode,
        daemonConnected: state.daemonConnected,
        lastCheck: state.lastCheck,
        bridgeUrl: 'http://127.0.0.1:21000',
    };
}

// ============================================================================
// Example: Hybrid Signing Logic
// ============================================================================

async function signContent(content: string, origin: string) {
    // Check which mode we're in
    await checkDaemonStatus();

    if (state.mode === 'bridge') {
        // Route to daemon
        return signViaBridge(content, origin);
    } else if (state.mode === 'local') {
        // Use local WebCrypto keys
        return signLocally(content, origin);
    } else {
        throw new Error('No signing capability available');
    }
}

async function signViaBridge(content: string, origin: string) {
    const response = await fetch('http://127.0.0.1:21000/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, origin }),
    });

    if (response.status === 403) {
        throw new Error('User denied signature');
    }
    if (response.status === 404) {
        throw new Error('No keys configured in daemon');
    }
    if (!response.ok) {
        throw new Error('Bridge signing failed');
    }

    return response.json();
}

async function signLocally(content: string, origin: string) {
    // Use SecureKeyManager
    // const keyManager = new SecureKeyManager();

    const contentBytes = new TextEncoder().encode(content);
    // const signature = await keyManager.sign(contentBytes);
    // const did = await keyManager.getDID();

    // Mock for example
    const signature = new ArrayBuffer(64);
    const did = 'did:key:zExample';

    return {
        signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
        timestamp: new Date().toISOString(),
        did,
        mode: 'local',
    };
}

// ============================================================================
// Example: Daemon Status Check
// ============================================================================

async function checkDaemonStatus(): Promise<boolean> {
    try {
        const response = await fetch('http://127.0.0.1:21000/status', {
            signal: AbortSignal.timeout(2000),
        });

        if (response.ok) {
            state.daemonConnected = true;
            state.mode = 'bridge';
            state.lastCheck = Date.now();
            updateBadge('bridge');
            return true;
        }
    } catch {
        // Connection failed
    }

    state.daemonConnected = false;

    // Check if we have local keys
    // const hasLocalKeys = await keyManager.getDID() !== null;
    const hasLocalKeys = true; // Mock for example

    if (hasLocalKeys) {
        state.mode = 'local';
        updateBadge('local');
    } else {
        state.mode = 'none';
        updateBadge('none');
    }

    state.lastCheck = Date.now();
    return false;
}

// ============================================================================
// Example: Badge Update
// ============================================================================

function updateBadge(mode: OperatingMode) {
    switch (mode) {
        case 'bridge':
            chrome.action.setBadgeText({ text: '🔐' });
            chrome.action.setBadgeBackgroundColor({ color: '#22c55e' }); // Green
            chrome.action.setTitle({ title: 'Vouch - Connected to Daemon' });
            break;

        case 'local':
            chrome.action.setBadgeText({ text: 'L' });
            chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' }); // Amber
            chrome.action.setTitle({ title: 'Vouch - Local Mode (Daemon Offline)' });
            break;

        case 'none':
            chrome.action.setBadgeText({ text: '!' });
            chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); // Red
            chrome.action.setTitle({ title: 'Vouch - No Identity' });
            break;
    }
}

// ============================================================================
// Example: Public Key Retrieval
// ============================================================================

async function getPublicKey() {
    await checkDaemonStatus();

    if (state.mode === 'bridge') {
        const response = await fetch('http://127.0.0.1:21000/keys/public');
        if (!response.ok) throw new Error('Failed to get public key');
        return response.json();
    } else if (state.mode === 'local') {
        // const keyManager = new SecureKeyManager();
        // return {
        //   publicKey: await keyManager.getPublicKeyHex(),
        //   did: await keyManager.getDID(),
        //   fingerprint: await keyManager.getFingerprint(),
        // };
        return { did: 'did:key:zLocal', fingerprint: 'SHA256:local' };
    } else {
        throw new Error('No keys available');
    }
}

// ============================================================================
// Example: Key Generation
// ============================================================================

async function generateKeys() {
    // Only generate local keys if daemon is offline
    await checkDaemonStatus();

    if (state.mode === 'bridge') {
        throw new Error('Use the daemon to generate keys when connected');
    }

    // const keyManager = new SecureKeyManager();
    // await keyManager.generateKeys();

    state.mode = 'local';
    updateBadge('local');

    return {
        success: true,
        mode: 'local',
        // did: await keyManager.getDID(),
        did: 'did:key:zNewLocal',
    };
}

// ============================================================================
// Example: Extension Initialization
// ============================================================================

async function initializeExtension() {
    console.log('Vouch Extension starting...');

    // 1. Check daemon status
    await checkDaemonStatus();
    console.log('Mode:', state.mode);

    // 2. Set up periodic daemon check (every 30 seconds)
    setInterval(checkDaemonStatus, 30000);

    // 3. Perform migration if needed
    // await performMigrationIfNeeded();

    // 4. Set up message listener
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        handleMessage(message, sender)
            .then(sendResponse)
            .catch(error => sendResponse({ error: error.message }));
        return true; // Keep channel open for async
    });

    console.log('Vouch Extension initialized');
}

// Run on install
chrome.runtime.onInstalled.addListener(() => {
    initializeExtension();
});

// Run on startup
chrome.runtime.onStartup.addListener(() => {
    initializeExtension();
});

export {
    handleMessage,
    checkDaemonStatus,
    signContent,
    getStatus,
};
