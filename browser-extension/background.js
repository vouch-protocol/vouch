/**
 * Vouch Protocol - Background Service Worker
 * 
 * Handles:
 * - Key generation on install
 * - Context menu for signing text
 * - Cloudflare API integration for short URLs
 * - Message passing with content scripts
 */

// Import TweetNaCl for crypto operations (fallback)
// and secure-keys.js for WebCrypto-based secure storage
// and bridge-migration.js for Bridge daemon integration
importScripts(
    'lib/tweetnacl.min.js',
    'lib/signer.js',
    'lib/secure-keys.js',
    'lib/bridge-migration.js'
);

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

// API endpoint for signature storage (Cloudflare Worker)
const API_BASE_URL = 'https://api.vouch-protocol.com';

// Shortlink domain for displaying to users
const SHORTLINK_DOMAIN = 'https://vch.sh';

// =============================================================================
// Key Management
// =============================================================================

/**
 * Initialize or load existing keypair using secure storage
 * Uses WebCrypto with non-extractable keys when available
 */
async function initializeKeys() {
    try {
        // Use the new secure key manager
        const keyInfo = await SecureKeys.initialize();

        console.log('Vouch: Keys initialized', {
            isFallback: keyInfo.isFallback,
            publicKeyPrefix: keyInfo.publicKeyHex.substring(0, 16),
        });

        return {
            publicKey: keyInfo.publicKeyHex,
            // secretKey is NOT returned - it stays in IndexedDB
            isSecure: !keyInfo.isFallback,
        };
    } catch (error) {
        console.error('Vouch: Secure key initialization failed, using fallback', error);

        // Fallback to legacy method if SecureKeys fails
        const stored = await chrome.storage.local.get([
            STORAGE_KEYS.SECRET_KEY,
            STORAGE_KEYS.PUBLIC_KEY,
        ]);

        if (stored[STORAGE_KEYS.SECRET_KEY] && stored[STORAGE_KEYS.PUBLIC_KEY]) {
            console.warn('Vouch: Using legacy keys from chrome.storage (less secure)');
            return {
                publicKey: stored[STORAGE_KEYS.PUBLIC_KEY],
                secretKey: stored[STORAGE_KEYS.SECRET_KEY],
                isSecure: false,
            };
        }

        // Generate new keypair (fallback)
        console.log('Vouch: Generating fallback keypair...');
        const keypair = generateKeypair();

        await chrome.storage.local.set({
            [STORAGE_KEYS.SECRET_KEY]: keypair.secretKey,
            [STORAGE_KEYS.PUBLIC_KEY]: keypair.publicKey,
        });

        return {
            publicKey: keypair.publicKey,
            secretKey: keypair.secretKey,
            isSecure: false,
        };
    }
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

        const response = await fetch(`${API_BASE_URL}/api/sign`, {
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
    // Remove any existing menus first (prevents duplicate ID error on reload)
    chrome.contextMenus.removeAll(() => {
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
        console.log('Vouch: Starting signing process...');
        // Get keypair info (public key only - private stays secure)
        const keypair = await initializeKeys();
        console.log('Vouch: Keys initialized successfully');

        // Get user identity (email and display name)
        const identity = await getUserIdentity();
        console.log('Vouch: Got identity:', identity.displayName);
        const email = identity.email;
        const displayName = identity.displayName;

        // Create the message to sign (standardized format for verification)
        // Use email in signed message for cryptographic binding
        const messageToSign = `${selectedText}\n---\nBy: ${email}`;

        // Sign the message using secure keys if available
        let signature;
        if (keypair.isSecure) {
            // Use WebCrypto secure signing (key never leaves IndexedDB)
            signature = await SecureKeys.signBase64(messageToSign);
        } else if (keypair.secretKey) {
            // Fallback to legacy signing
            signature = signMessage(messageToSign, keypair.secretKey);
        } else {
            throw new Error('No signing key available');
        }

        // Convert public key to Base64 for API
        const publicKeyBase64 = toBase64(fromHex(keypair.publicKey));


        // Try to store in Cloudflare and get short URL
        const apiResponse = await storeSignature({
            text: selectedText,
            email: email,
            key: publicKeyBase64,
            sig: signature,
        });

        let vouchBlock;

        if (apiResponse && apiResponse.success) {
            // Use shortlink for sharing (vch.sh/{id})
            // Show display name for better UX, but email is in the signed message
            const shortlink = apiResponse.shortlink || `${SHORTLINK_DOMAIN}/${apiResponse.id}`;
            vouchBlock = `✅ Signed by ${displayName}\n🔗 ${shortlink}`;
        } else {
            // Fall back to full format (API unavailable)
            vouchBlock = formatVouchBlock(
                selectedText,
                email,
                keypair.publicKey,
                signature
            );
        }

        // Try to copy to clipboard via content script
        // If content script not loaded, inject it first
        try {
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
        } catch (contentScriptError) {
            // Content script not loaded - try to inject it
            console.log('Vouch: Content script not loaded, injecting...');
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ['content.js']
                });
                // Now try again
                await chrome.tabs.sendMessage(tab.id, {
                    action: 'copyToClipboard',
                    text: vouchBlock,
                });
                await chrome.tabs.sendMessage(tab.id, {
                    action: 'showNotification',
                    message: '✅ Signed and copied to clipboard!',
                    type: 'success',
                });
            } catch (injectError) {
                // Cannot inject (chrome:// pages, etc.) - copy via navigator.clipboard in offscreen maybe
                // For now, just log the signed text
                console.log('Vouch: Could not inject content script. Signed text:', vouchBlock);
                // Try using offscreen clipboard API as fallback
                // This requires additional setup, so for now we alert via browser action
                console.error('Vouch: Please refresh the page and try again.');
            }
        }

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
