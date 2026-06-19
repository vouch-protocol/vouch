/**
 * Vouch Protocol - Content Script
 * 
 * Scans the page DOM for Vouch signature blocks and verifies them.
 * Displays trust badges with Vouch logo based on Address Book lookup.
 * Supports multiple signature formats (short URL, Base64, hex).
 */

// =============================================================================
// Constants
// =============================================================================

// Vouch logo as Base64 data URI (embedded for cross-origin compatibility)
const VOUCH_LOGO_DATA_URI = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAdgAAAHYBTnsmCAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAGtSURBVDiNpZM9a8JQFIZ9b8wUIoKDg4uD4FR0kC4iCIVOgm5OHV0cXJ0EwcXRpYuji4uLs6OToIuIoCCIIIJKBxERRQwomhgTEzXH6RIJET8qvc7nPOe+l3tHAID/2Py+iOd5KpUKBEGo1+scx6nT6XQ8Hv/1B4vFws3NjdPpdLvdhqqqsVgsk8nALyWTSY7jFolEUqlUJpNpt9ttNpuVSiUcDsM/vl5fX19dXTUajdXV1XA4HI1Go9FoPB4vl8tOp3N7e+t2u7+lEolEq9VqtVobGxuhUEgURUmSJEkKBoNLS0tQXl9f7+zsZLNZq9Xa7XZlWeZ5XhCEUCi0vr4eCAS8Xi8cP3BxcUEQhCzLhUKhXC7H4/FUKhWPx0OhED4hEAi43e5isQjF1dVVu90WRVGSpGw2m81mg8FgMBgMBALr6+tut9vlcsHlcslxnM/n83g8VqvVbrdbrVaXy7Wzs/MDVlZWVlZWEolEJpMpFAocx71+P4FA4PuE/c8FNzc3ZFkulyuVSo7jKpVKuVz2eDxLS0sLvxd8UjweVyqVOEEsFgvhcBh+6C90K3TLWyqqJAAAAABJRU5ErkJggg==';

// Detection patterns for different signature formats
const PATTERNS = {
    // New short URL format: [Signed] ... By: email 🔗 url
    short: /\[Signed\]\s*([\s\S]*?)\s*---\s*By:\s*(\S+)\s*🔗\s*(https?:\/\/[^\s]+)/g,

    // Base64 format: [Signed] ... By: email Key: base64 Sig: base64
    base64: /\[Signed\]\s*([\s\S]*?)\s*---\s*By:\s*(\S+)\s*Key:\s*([A-Za-z0-9_-]+)\s*Sig:\s*([A-Za-z0-9_-]+)/g,

    // Legacy hex format: [Signed] ... Signed-by: email Key: hex Sig: hex
    hex: /\[Signed\]\s*([\s\S]*?)\s*---\s*Signed-by:\s*(\S+)\s*Key:\s*([a-fA-F0-9]+)\s*Sig:\s*([a-fA-F0-9]+)/g,
};

const VERIFICATION_STATES = {
    NEW: 'new',           // First time seeing this email
    VERIFIED: 'verified', // Email + key match Address Book
    CONFLICT: 'conflict', // Email known but key different
    INVALID: 'invalid',   // Signature doesn't verify
    LOADING: 'loading',   // Fetching from API
};

const STATE_STYLES = {
    [VERIFICATION_STATES.NEW]: {
        badge: '🔵',
        color: '#6b7280',
        bgColor: 'rgba(107, 114, 128, 0.1)',
        label: 'New Identity',
        description: 'First time seeing this signer',
    },
    [VERIFICATION_STATES.VERIFIED]: {
        badge: '✅',
        color: '#10b981',
        bgColor: 'rgba(16, 185, 129, 0.1)',
        label: 'Verified by Vouch',
        description: 'This matches a known contact',
    },
    [VERIFICATION_STATES.CONFLICT]: {
        badge: '⚠️',
        color: '#ef4444',
        bgColor: 'rgba(239, 68, 68, 0.1)',
        label: 'Identity Changed!',
        description: 'WARNING: Key different from saved contact',
    },
    [VERIFICATION_STATES.INVALID]: {
        badge: '❌',
        color: '#ef4444',
        bgColor: 'rgba(239, 68, 68, 0.1)',
        label: 'Invalid Signature',
        description: 'Signature verification failed',
    },
    [VERIFICATION_STATES.LOADING]: {
        badge: '⏳',
        color: '#6b7280',
        bgColor: 'rgba(107, 114, 128, 0.1)',
        label: 'Verifying...',
        description: 'Fetching signature data',
    },
};

// =============================================================================
// Helper Functions
// =============================================================================

function fromHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function fromBase64(base64) {
    let padded = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) {
        padded += '=';
    }
    const binString = atob(padded);
    return new Uint8Array([...binString].map((c) => c.charCodeAt(0)));
}

function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

function verifySignature(message, signature, publicKey) {
    try {
        const messageBytes = stringToBytes(message);

        // Detect signature format
        let signatureBytes;
        if (signature.length === 128 && /^[a-fA-F0-9]+$/.test(signature)) {
            signatureBytes = fromHex(signature);
        } else {
            signatureBytes = fromBase64(signature);
        }

        // Detect public key format
        let publicKeyBytes;
        if (publicKey.length === 64 && /^[a-fA-F0-9]+$/.test(publicKey)) {
            publicKeyBytes = fromHex(publicKey);
        } else {
            publicKeyBytes = fromBase64(publicKey);
        }

        return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    } catch (e) {
        console.error('Vouch: Verification error:', e);
        return false;
    }
}

// =============================================================================
// DOM Scanner
// =============================================================================

function findVouchBlocks() {
    const blocks = [];
    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        null,
        false
    );

    let node;
    while (node = walker.nextNode()) {
        const text = node.textContent;
        if (text.includes('[Signed]')) {
            if (node.parentElement && node.parentElement.classList.contains('vouch-processed')) {
                continue;
            }
            blocks.push(node);
        }
    }

    return blocks;
}

function parseVouchBlock(text) {
    // Try short URL format first
    const shortPattern = /\[Signed\]\s*([\s\S]*?)\s*---\s*By:\s*(\S+)\s*🔗\s*(https?:\/\/[^\s]+)/;
    const shortMatch = text.match(shortPattern);

    if (shortMatch) {
        // Extract short ID from URL
        const urlMatch = shortMatch[3].match(/\/v\/([a-zA-Z0-9]+)/);
        return {
            fullMatch: shortMatch[0],
            format: 'short',
            text: shortMatch[1].trim(),
            email: shortMatch[2].trim(),
            verifyUrl: shortMatch[3].trim(),
            shortId: urlMatch ? urlMatch[1] : null,
        };
    }

    // Try Base64 format
    const base64Pattern = /\[Signed\]\s*([\s\S]*?)\s*---\s*By:\s*(\S+)\s*Key:\s*([A-Za-z0-9_-]+)\s*Sig:\s*([A-Za-z0-9_-]+)/;
    const base64Match = text.match(base64Pattern);

    if (base64Match) {
        return {
            fullMatch: base64Match[0],
            format: 'base64',
            text: base64Match[1].trim(),
            email: base64Match[2].trim(),
            publicKey: base64Match[3].trim(),
            signature: base64Match[4].trim(),
        };
    }

    // Try legacy hex format
    const hexPattern = /\[Signed\]\s*([\s\S]*?)\s*---\s*Signed-by:\s*(\S+)\s*Key:\s*([a-fA-F0-9]+)\s*Sig:\s*([a-fA-F0-9]+)/;
    const hexMatch = text.match(hexPattern);

    if (hexMatch) {
        return {
            fullMatch: hexMatch[0],
            format: 'hex',
            text: hexMatch[1].trim(),
            email: hexMatch[2].trim(),
            publicKey: hexMatch[3].trim().toLowerCase(),
            signature: hexMatch[4].trim().toLowerCase(),
        };
    }

    return null;
}

// =============================================================================
// Verification
// =============================================================================

async function verifyVouchBlock(parsed) {
    // For short URL format, fetch from API first
    if (parsed.format === 'short' && parsed.shortId) {
        try {
            const response = await new Promise((resolve) => {
                chrome.runtime.sendMessage(
                    { action: 'fetchSignature', id: parsed.shortId },
                    resolve
                );
            });

            if (response && response.success) {
                parsed.text = response.text;
                parsed.publicKey = response.key;
                parsed.signature = response.sig;
                parsed.format = 'base64'; // Now treat as base64
            } else {
                return { state: VERIFICATION_STATES.INVALID, parsed };
            }
        } catch (error) {
            console.error('Vouch: Failed to fetch signature:', error);
            return { state: VERIFICATION_STATES.INVALID, parsed };
        }
    }

    // Verify the cryptographic signature
    const messageToSign = `${parsed.text}\n---\nBy: ${parsed.email}`;
    const signatureValid = verifySignature(
        messageToSign,
        parsed.signature,
        parsed.publicKey
    );

    if (!signatureValid) {
        // Try legacy message format
        const legacyMessage = `${parsed.text}\n---\nSigned-by: ${parsed.email}`;
        const legacyValid = verifySignature(
            legacyMessage,
            parsed.signature,
            parsed.publicKey
        );

        if (!legacyValid) {
            return { state: VERIFICATION_STATES.INVALID, parsed };
        }
    }

    // Look up in Address Book
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(
            { action: 'lookupContact', email: parsed.email },
            (response) => {
                if (response && response.found) {
                    // Normalize keys for comparison
                    const storedKey = response.contact.publicKey.toLowerCase();
                    const parsedKey = parsed.publicKey.toLowerCase();

                    if (storedKey === parsedKey) {
                        resolve({ state: VERIFICATION_STATES.VERIFIED, parsed });
                    } else {
                        resolve({
                            state: VERIFICATION_STATES.CONFLICT,
                            parsed,
                            savedKey: response.contact.publicKey,
                        });
                    }
                } else {
                    // New contact - save it
                    chrome.runtime.sendMessage({
                        action: 'addContact',
                        email: parsed.email,
                        publicKey: parsed.publicKey,
                    }, () => {
                        resolve({ state: VERIFICATION_STATES.NEW, parsed });
                    });
                }
            }
        );
    });
}

// =============================================================================
// UI Rendering
// =============================================================================

function wrapVouchBlock(textNode, result) {
    const parsed = result.parsed;
    const stateInfo = STATE_STYLES[result.state];

    // Create wrapper
    const wrapper = document.createElement('div');
    wrapper.className = `vouch-block vouch-block-${result.state} vouch-processed`;
    wrapper.style.cssText = `
    border: 2px solid ${stateInfo.color};
    border-radius: 12px;
    padding: 16px;
    margin: 12px 0;
    background: ${stateInfo.bgColor};
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  `;

    // Header with Vouch logo and badge
    const header = document.createElement('div');
    header.style.cssText = `
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
    font-weight: 600;
    color: ${stateInfo.color};
  `;
    header.innerHTML = `
    <img src="${VOUCH_LOGO_DATA_URI}" alt="Vouch" style="width: 20px; height: 20px; border-radius: 4px;">
    <span style="font-size: 1.1em;">${stateInfo.badge}</span>
    <span>${stateInfo.label}</span>
  `;

    // Signed content
    const content = document.createElement('div');
    content.style.cssText = `
    background: white;
    color: #1e293b;
    padding: 14px;
    border-radius: 8px;
    margin: 12px 0;
    white-space: pre-wrap;
    line-height: 1.5;
    font-size: 0.95em;
    border: 1px solid rgba(0,0,0,0.05);
  `;
    content.textContent = parsed.text;

    // Footer with signer info
    const footer = document.createElement('div');
    footer.style.cssText = `
    font-size: 0.85em;
    color: #64748b;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid rgba(0,0,0,0.1);
  `;

    const keyDisplay = parsed.publicKey
        ? parsed.publicKey.substring(0, 16) + '...'
        : 'via short link';

    footer.innerHTML = `
    <div style="margin-bottom: 4px;"><strong>Signed by:</strong> ${parsed.email}</div>
    <div><strong>Key:</strong> <code style="font-size: 0.85em; background: rgba(0,0,0,0.05); padding: 2px 6px; border-radius: 4px;">${keyDisplay}</code></div>
  `;

    // Conflict warning
    if (result.state === VERIFICATION_STATES.CONFLICT) {
        const warning = document.createElement('div');
        warning.style.cssText = `
      background: #fef2f2;
      border: 1px solid #ef4444;
      color: #b91c1c;
      padding: 10px 12px;
      border-radius: 6px;
      margin-top: 12px;
      font-weight: 500;
      font-size: 0.9em;
    `;
        warning.textContent = '⚠️ WARNING: This key is different from the one saved for this email. This could indicate impersonation.';
        footer.appendChild(warning);
    }

    wrapper.appendChild(header);
    wrapper.appendChild(content);
    wrapper.appendChild(footer);

    // Replace the text node with our wrapper
    const parent = textNode.parentElement;
    if (parent) {
        const before = textNode.textContent.split(parsed.fullMatch)[0];
        const after = textNode.textContent.split(parsed.fullMatch)[1];

        if (before) {
            parent.insertBefore(document.createTextNode(before), textNode);
        }
        parent.insertBefore(wrapper, textNode);
        if (after) {
            parent.insertBefore(document.createTextNode(after), textNode);
        }
        textNode.remove();
    }
}

// =============================================================================
// Message Handling
// =============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'copyToClipboard') {
        navigator.clipboard.writeText(message.text).then(() => {
            sendResponse({ success: true });
        }).catch((err) => {
            sendResponse({ success: false, error: err.message });
        });
        return true;
    }

    if (message.action === 'showNotification') {
        showNotification(message.message, message.type);
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'smartScan') {
        performSmartScan(message.selectedText);
        sendResponse({ success: true });
        return true;
    }
});

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `vouch-notification vouch-notification-${type}`;
    notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 14px 24px;
    border-radius: 10px;
    background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
    color: white;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 4px 16px rgba(0,0,0,0.2);
    z-index: 999999;
    display: flex;
    align-items: center;
    gap: 10px;
    animation: vouch-slide-in 0.3s ease;
  `;

    // Add Vouch logo to notification
    notification.innerHTML = `
    <img src="${VOUCH_LOGO_DATA_URI}" alt="Vouch" style="width: 18px; height: 18px; border-radius: 3px;">
    <span>${message}</span>
  `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'vouch-slide-out 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// =============================================================================
// Main Scanner
// =============================================================================

async function scanPage() {
    const textNodes = findVouchBlocks();

    for (const node of textNodes) {
        const parsed = parseVouchBlock(node.textContent);
        if (!parsed) continue;

        const result = await verifyVouchBlock(parsed);
        wrapVouchBlock(node, result);
    }
}

// Run on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanPage);
} else {
    scanPage();
}

// Watch for dynamic content
const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
                    if (node.textContent && node.textContent.includes('[Signed]')) {
                        shouldScan = true;
                        break;
                    }
                }
            }
        }
        if (shouldScan) break;
    }

    if (shouldScan) {
        scanPage();
    }
});

observer.observe(document.body, { childList: true, subtree: true });

// Inject CSS for animations and Smart Scan highlighting
const style = document.createElement('style');
style.textContent = `
  @keyframes vouch-slide-in {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes vouch-slide-out {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
  
  /* Smart Scan Highlighting */
  .vouch-smart-scan-verified {
    background: linear-gradient(90deg, 
      rgba(34, 197, 94, 0.2) 0%, 
      rgba(34, 197, 94, 0.05) 100%) !important;
    border-left: 4px solid #22c55e !important;
    padding-left: 12px !important;
    position: relative;
    transition: all 0.3s ease;
  }
  
  .vouch-smart-scan-verified::before {
    content: "✅ Verified by Vouch";
    position: absolute;
    top: -24px;
    left: 0;
    font-size: 12px;
    color: #22c55e;
    font-weight: bold;
    background: white;
    padding: 2px 8px;
    border-radius: 4px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  }
  
  .vouch-smart-scan-unverified {
    background: rgba(239, 68, 68, 0.1) !important;
    border-left: 4px solid #ef4444 !important;
    padding-left: 12px !important;
  }
  
  @keyframes vouch-pulse {
    0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); }
    70% { box-shadow: 0 0 0 10px rgba(34, 197, 94, 0); }
    100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
  }
  
  .vouch-smart-scan-verified {
    animation: vouch-pulse 2s ease-out;
  }
`;
document.head.appendChild(style);

// =============================================================================
// Smart Scan Implementation
// =============================================================================

/**
 * SHA-256 hash for text
 */
async function sha256Hash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Normalize text for consistent hashing
 */
function normalizeText(text) {
    return text
        .trim()
        .replace(/\s+/g, ' ')           // Collapse whitespace
        .replace(/[\u200B-\u200D\uFEFF]/g, ''); // Remove zero-width chars
}

/**
 * Get all text blocks from the page for scanning
 */
function getPageTextBlocks() {
    const blocks = [];
    const selectors = [
        'h1', 'h2', 'h3', 'h4',           // Headers
        'p',                               // Paragraphs
        'article', 'section',              // Semantic blocks
        '.post-content', '.article-body',  // Common content classes
        '[data-vouch-content]',            // Explicit Vouch marking
    ];

    for (const sel of selectors) {
        document.querySelectorAll(sel).forEach(el => {
            // Skip already processed or very short text
            if (el.classList.contains('vouch-processed') ||
                el.classList.contains('vouch-smart-scan-verified')) {
                return;
            }

            const text = el.innerText.trim();
            if (text.length > 5) {  // Skip very short text
                blocks.push({
                    element: el,
                    text: normalizeText(text),
                    originalText: text
                });
            }
        });
    }

    return blocks;
}

/**
 * Find verified signature blocks on the page
 */
function findVerifiedSignatures() {
    const signatures = [];
    const vouchBlocks = document.querySelectorAll('.vouch-block-verified, .vouch-block-new');

    vouchBlocks.forEach(block => {
        // Try to extract the signed content from the block
        const contentEl = block.querySelector('div[style*="white-space: pre-wrap"]');
        if (contentEl) {
            const signedText = contentEl.textContent.trim();
            signatures.push({
                text: normalizeText(signedText),
                element: block,
                originalText: signedText
            });
        }
    });

    return signatures;
}

/**
 * Perform Smart Scan - finds and highlights verified content on the page
 */
async function performSmartScan(selectedText) {
    console.log('Vouch: Starting Smart Scan...');

    // 1. Find all verified signature blocks
    const signatures = findVerifiedSignatures();

    if (signatures.length === 0) {
        showNotification('No Vouch signatures found on this page. Look for [Signed] blocks.', 'info');
        return;
    }

    // 2. Get all text blocks on the page
    const textBlocks = getPageTextBlocks();

    // 3. Hash all signed content
    const signedHashes = new Map();
    for (const sig of signatures) {
        const hash = await sha256Hash(sig.text);
        signedHashes.set(hash, sig);
    }

    // 4. Scan page and find matches
    let matchCount = 0;

    for (const block of textBlocks) {
        const blockHash = await sha256Hash(block.text);

        if (signedHashes.has(blockHash)) {
            // EXACT MATCH FOUND!
            const sig = signedHashes.get(blockHash);
            block.element.classList.add('vouch-smart-scan-verified');
            matchCount++;

            console.log('Vouch: Smart Scan match found:', block.originalText.substring(0, 50) + '...');
        }
    }

    // 5. Show result
    if (matchCount > 0) {
        showNotification(`✅ Smart Scan: Found ${matchCount} verified content block(s)!`, 'success');
    } else {
        // Try to show hint from first signature
        if (signatures.length > 0) {
            const hint = signatures[0].originalText.substring(0, 40);
            showNotification(`⚠️ Signed content not found. Looking for: "${hint}..."`, 'info');
        } else {
            showNotification('No matching content found on page.', 'info');
        }
    }
}

console.log('Vouch: Content script loaded, scanning for blocks...');
