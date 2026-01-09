/**
 * Vouch Protocol - Background Service Worker
 * 
 * Handles:
 * - Key generation on install
 * - Context menu for signing text
 * - Cloudflare API integration for short URLs
 * - Message passing with content scripts
 */

// Import TweetNaCl for crypto operations
importScripts('lib/tweetnacl.min.js', 'lib/signer.js');

// =============================================================================
// Constants
// =============================================================================

const STORAGE_KEYS = {
    SECRET_KEY: 'vouch_secret_key',
    PUBLIC_KEY: 'vouch_public_key',
    ADDRESS_BOOK: 'vouch_address_book',
};

const CONTEXT_MENU_ID = 'vouch-sign-selection';
const CONTEXT_MENU_SCAN_ID = 'vouch-smart-scan';

// API endpoint for signature storage
// Update this to your Cloudflare Worker URL once deployed
const API_BASE_URL = 'https://api.vouch-protocol.com';

// =============================================================================
// Key Management
// =============================================================================

/**
 * Initialize or load existing keypair
 */
async function initializeKeys() {
    const stored = await chrome.storage.local.get([
        STORAGE_KEYS.SECRET_KEY,
        STORAGE_KEYS.PUBLIC_KEY,
    ]);

    if (stored[STORAGE_KEYS.SECRET_KEY] && stored[STORAGE_KEYS.PUBLIC_KEY]) {
        console.log('Vouch: Loaded existing keypair');
        return {
            publicKey: stored[STORAGE_KEYS.PUBLIC_KEY],
            secretKey: stored[STORAGE_KEYS.SECRET_KEY],
        };
    }

    // Generate new keypair
    console.log('Vouch: Generating new keypair...');
    const keypair = generateKeypair();

    await chrome.storage.local.set({
        [STORAGE_KEYS.SECRET_KEY]: keypair.secretKey,
        [STORAGE_KEYS.PUBLIC_KEY]: keypair.publicKey,
    });

    console.log('Vouch: New keypair generated and saved');
    return keypair;
}

/**
 * Get the user's identity (email and optional display name)
 * Pro users can set a custom display name
 */
async function getUserIdentity() {
    return new Promise(async (resolve, reject) => {
        chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' }, async (userInfo) => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
            }

            if (!userInfo || !userInfo.email) {
                reject(new Error('Could not get user email. Please sign in to Chrome.'));
                return;
            }

            // Check for Pro settings with custom display name
            const settings = await chrome.storage.local.get(['vouch_display_name', 'vouch_is_pro']);

            resolve({
                email: userInfo.email,
                displayName: settings.vouch_display_name || userInfo.email,
                isPro: settings.vouch_is_pro || false,
            });
        });
    });
}

/**
 * Get the user's email (legacy - for backwards compatibility)
 */
async function getUserEmail() {
    const identity = await getUserIdentity();
    return identity.email;
}

// =============================================================================
// Cloudflare API Integration
// =============================================================================

/**
 * Store signature in Cloudflare KV and get short URL
 * @param {Object} signatureData - The signature data to store
 * @returns {Object|null} Response with short ID and URL, or null if unavailable
 */
async function storeSignature(signatureData) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

        const response = await fetch(`${API_BASE_URL}/sign`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(signatureData),
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            console.log('Vouch: API returned error, using fallback format');
            return null;
        }

        return await response.json();
    } catch (error) {
        // Network error, API not deployed yet, or timeout - fall back gracefully
        console.log('Vouch: API unavailable, using fallback format');
        return null;
    }
}

// =============================================================================
// Context Menu
// =============================================================================

/**
 * Create the context menu items
 */
function createContextMenu() {
    // Sign selected text
    chrome.contextMenus.create({
        id: CONTEXT_MENU_ID,
        title: '✍️ Sign with Vouch',
        contexts: ['selection'],
    });

    // Smart Scan - verify signature on page
    chrome.contextMenus.create({
        id: CONTEXT_MENU_SCAN_ID,
        title: '🔍 Vouch: Smart Scan',
        contexts: ['page', 'selection'],
    });
}

/**
 * Handle context menu click
 */
async function handleContextMenuClick(info, tab) {
    if (info.menuItemId !== CONTEXT_MENU_ID) return;

    const selectedText = info.selectionText;
    if (!selectedText) {
        console.error('Vouch: No text selected');
        return;
    }

    try {
        // Get keypair
        const keypair = await initializeKeys();

        // Get user email
        const email = await getUserEmail();

        // Create the message to sign (standardized format for verification)
        const messageToSign = `${selectedText}\n---\nBy: ${email}`;

        // Sign the message (returns Base64)
        const signature = signMessage(messageToSign, keypair.secretKey);

        // TODO: Uncomment when Cloudflare Worker is deployed
        // Convert public key to Base64 for API
        // const publicKeyBase64 = toBase64(fromHex(keypair.publicKey));

        // Try to store in Cloudflare and get short URL
        // const apiResponse = await storeSignature({
        //     text: selectedText,
        //     email: email,
        //     key: publicKeyBase64,
        //     sig: signature,
        // });

        let vouchBlock;

        // TODO: Uncomment when Cloudflare Worker is deployed
        // if (apiResponse && apiResponse.success) {
        //     // Use short URL format
        //     vouchBlock = formatVouchBlockShort(
        //         selectedText,
        //         email,
        //         apiResponse.url
        //     );
        // } else {
        //     // Fall back to full format (API unavailable)
        //     vouchBlock = formatVouchBlock(
        //         selectedText,
        //         email,
        //         keypair.publicKey,
        //         signature
        //     );
        // }

        // For now, use full format directly
        vouchBlock = formatVouchBlock(
            selectedText,
            email,
            keypair.publicKey,
            signature
        );

        // Copy to clipboard via content script
        await chrome.tabs.sendMessage(tab.id, {
            action: 'copyToClipboard',
            text: vouchBlock,
        });

        // Show notification
        await chrome.tabs.sendMessage(tab.id, {
            action: 'showNotification',
            message: '✅ Signed and copied to clipboard!',
            type: 'success',
        });

    } catch (error) {
        console.error('Vouch: Signing error:', error);

        // Send error notification
        try {
            await chrome.tabs.sendMessage(tab.id, {
                action: 'showNotification',
                message: `❌ Error: ${error.message}`,
                type: 'error',
            });
        } catch (e) {
            console.error('Could not show notification:', e);
        }
    }
}

/**
 * Handle Smart Scan context menu click
 * Sends request to content script to scan the page for signed content
 */
async function handleSmartScanClick(info, tab) {
    try {
        await chrome.tabs.sendMessage(tab.id, {
            action: 'smartScan',
            selectedText: info.selectionText || null,
        });
    } catch (error) {
        console.error('Vouch: Smart Scan error:', error);
    }
}

// =============================================================================
// Context Menu Click Router
// =============================================================================

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === CONTEXT_MENU_ID) {
        handleContextMenuClick(info, tab);
    } else if (info.menuItemId === CONTEXT_MENU_SCAN_ID) {
        handleSmartScanClick(info, tab);
    }
});

// =============================================================================
// Message Handling
// =============================================================================

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getMyIdentity') {
        (async () => {
            try {
                const keypair = await initializeKeys();
                const email = await getUserEmail();
                const fingerprint = await getFingerprint(keypair.publicKey);

                sendResponse({
                    success: true,
                    data: {
                        email,
                        publicKey: keypair.publicKey,
                        fingerprint,
                    },
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

    if (message.action === 'getAddressBook') {
        chrome.storage.local.get([STORAGE_KEYS.ADDRESS_BOOK], (result) => {
            sendResponse({
                success: true,
                data: result[STORAGE_KEYS.ADDRESS_BOOK] || {},
            });
        });
        return true;
    }

    if (message.action === 'addContact') {
        (async () => {
            const { email, publicKey } = message;
            const result = await chrome.storage.local.get([STORAGE_KEYS.ADDRESS_BOOK]);
            const addressBook = result[STORAGE_KEYS.ADDRESS_BOOK] || {};

            addressBook[email] = {
                publicKey,
                addedAt: new Date().toISOString(),
            };

            await chrome.storage.local.set({ [STORAGE_KEYS.ADDRESS_BOOK]: addressBook });
            sendResponse({ success: true });
        })();
        return true;
    }

    if (message.action === 'removeContact') {
        (async () => {
            const { email } = message;
            const result = await chrome.storage.local.get([STORAGE_KEYS.ADDRESS_BOOK]);
            const addressBook = result[STORAGE_KEYS.ADDRESS_BOOK] || {};

            delete addressBook[email];

            await chrome.storage.local.set({ [STORAGE_KEYS.ADDRESS_BOOK]: addressBook });
            sendResponse({ success: true });
        })();
        return true;
    }

    if (message.action === 'lookupContact') {
        (async () => {
            const { email } = message;
            const result = await chrome.storage.local.get([STORAGE_KEYS.ADDRESS_BOOK]);
            const addressBook = result[STORAGE_KEYS.ADDRESS_BOOK] || {};

            sendResponse({
                success: true,
                found: email in addressBook,
                contact: addressBook[email] || null,
            });
        })();
        return true;
    }

    // Handle fetching signature from API for verification
    if (message.action === 'fetchSignature') {
        (async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/verify/${message.id}`);
                const data = await response.json();
                sendResponse(data);
            } catch (error) {
                sendResponse({ success: false, error: error.message });
            }
        })();
        return true;
    }
});

// =============================================================================
// Event Listeners
// =============================================================================

// Initialize on install
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('Vouch: Extension installed/updated', details.reason);

    // Generate keys
    await initializeKeys();

    // Create context menu
    createContextMenu();
});

// Re-create context menu on startup (they don't persist)
chrome.runtime.onStartup.addListener(() => {
    createContextMenu();
});

console.log('Vouch: Background service worker loaded');
