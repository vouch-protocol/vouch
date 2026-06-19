/**
 * Vouch Protocol Signer Library
 * 
 * Provides Ed25519 key generation and signing for the browser extension.
 * Uses TweetNaCl.js for cryptographic operations.
 * 
 * Updated to use Base64 encoding for shorter signatures.
 */

// =============================================================================
// Encoding Helpers
// =============================================================================

// Convert Uint8Array to hex string
function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Convert hex string to Uint8Array
function fromHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// Convert Uint8Array to URL-safe Base64
function toBase64(bytes) {
    const binString = Array.from(bytes, (x) => String.fromCharCode(x)).join('');
    return btoa(binString)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, ''); // Remove padding
}

// Convert URL-safe Base64 to Uint8Array
function fromBase64(base64) {
    // Add padding back if needed
    let padded = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) {
        padded += '=';
    }
    const binString = atob(padded);
    return new Uint8Array([...binString].map((c) => c.charCodeAt(0)));
}

// Convert string to Uint8Array (UTF-8)
function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

// =============================================================================
// Key Generation & Signing
// =============================================================================

/**
 * Generate a new Ed25519 keypair
 * Keys are stored in hex format (for compatibility)
 * @returns {Object} { publicKey: hex, secretKey: hex }
 */
function generateKeypair() {
    const keypair = nacl.sign.keyPair();
    return {
        publicKey: toHex(keypair.publicKey),
        secretKey: toHex(keypair.secretKey),
    };
}

/**
 * Get the public key fingerprint (first 16 chars of SHA-256 hash)
 * @param {string} publicKeyHex - Public key in hex format
 * @returns {string} Short fingerprint for display
 */
async function getFingerprint(publicKeyHex) {
    const publicKeyBytes = fromHex(publicKeyHex);
    const hashBuffer = await crypto.subtle.digest('SHA-256', publicKeyBytes);
    const hashArray = new Uint8Array(hashBuffer);
    return toHex(hashArray).substring(0, 16);
}

/**
 * Sign a message with the secret key
 * @param {string} message - Message to sign
 * @param {string} secretKeyHex - Secret key in hex format
 * @returns {string} Signature in Base64 format
 */
function signMessage(message, secretKeyHex) {
    const messageBytes = stringToBytes(message);
    const secretKeyBytes = fromHex(secretKeyHex);
    const signatureBytes = nacl.sign.detached(messageBytes, secretKeyBytes);
    return toBase64(signatureBytes);
}

/**
 * Sign a message and return hex (for backwards compatibility)
 * @param {string} message - Message to sign  
 * @param {string} secretKeyHex - Secret key in hex format
 * @returns {string} Signature in hex format
 */
function signMessageHex(message, secretKeyHex) {
    const messageBytes = stringToBytes(message);
    const secretKeyBytes = fromHex(secretKeyHex);
    const signatureBytes = nacl.sign.detached(messageBytes, secretKeyBytes);
    return toHex(signatureBytes);
}

/**
 * Verify a signature (supports both Base64 and hex)
 * @param {string} message - Original message
 * @param {string} signature - Signature in Base64 or hex format
 * @param {string} publicKey - Public key in hex or Base64 format
 * @returns {boolean} True if signature is valid
 */
function verifySignature(message, signature, publicKey) {
    try {
        const messageBytes = stringToBytes(message);

        // Detect format and convert signature
        let signatureBytes;
        if (signature.length === 128 && /^[a-fA-F0-9]+$/.test(signature)) {
            // Hex format (128 chars = 64 bytes)
            signatureBytes = fromHex(signature);
        } else {
            // Base64 format
            signatureBytes = fromBase64(signature);
        }

        // Detect format and convert public key
        let publicKeyBytes;
        if (publicKey.length === 64 && /^[a-fA-F0-9]+$/.test(publicKey)) {
            // Hex format (64 chars = 32 bytes)
            publicKeyBytes = fromHex(publicKey);
        } else {
            // Base64 format
            publicKeyBytes = fromBase64(publicKey);
        }

        return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    } catch (e) {
        console.error('Verification error:', e);
        return false;
    }
}

// =============================================================================
// Block Formatting
// =============================================================================

/**
 * Format a compact signed badge (new default format)
 * @param {string} signer - Signer's display name or email
 * @param {string} shortUrl - The verification short URL
 * @returns {string} Compact signed badge
 */
function formatVouchBadge(signer, shortUrl) {
    return `✅ Signed by ${signer}
   Verify: ${shortUrl}`;
}

/**
 * Format a signed Vouch block with short URL
 * @param {string} text - The signed text
 * @param {string} signer - Signer's display name or email
 * @param {string} shortUrl - The verification short URL
 * @returns {string} Formatted Vouch block (new format)
 */
function formatVouchBlockShort(text, signer, shortUrl) {
    return `[Signed]
${text}
---
By: ${signer}
🔗 ${shortUrl}`;
}

/**
 * Format a signed Vouch block with full data (legacy format)
 * @param {string} text - The signed text
 * @param {string} email - Signer's email
 * @param {string} publicKeyHex - Public key in hex
 * @param {string} signatureBase64 - Signature in Base64
 * @returns {string} Formatted Vouch block
 */
function formatVouchBlock(text, email, publicKeyHex, signatureBase64) {
    // Convert public key to Base64 for shorter output
    const publicKeyBase64 = toBase64(fromHex(publicKeyHex));
    return `[Signed]
${text}
---
By: ${email}
Key: ${publicKeyBase64}
Sig: ${signatureBase64}`;
}

/**
 * Parse a Vouch block (supports both old and new formats)
 * @param {string} block - The full Vouch block text
 * @returns {Object|null} Parsed components or null if invalid
 */
function parseVouchBlock(block) {
    // Try new short URL format first
    const shortPattern = /\[Signed\]\s*([\s\S]*?)\s*---\s*By:\s*(\S+)\s*🔗\s*(https?:\/\/[^\s]+)/;
    const shortMatch = block.match(shortPattern);

    if (shortMatch) {
        return {
            format: 'short',
            text: shortMatch[1].trim(),
            email: shortMatch[2].trim(),
            verifyUrl: shortMatch[3].trim(),
        };
    }

    // Try new Base64 format
    const base64Pattern = /\[Signed\]\s*([\s\S]*?)\s*---\s*By:\s*(\S+)\s*Key:\s*([A-Za-z0-9_-]+)\s*Sig:\s*([A-Za-z0-9_-]+)/;
    const base64Match = block.match(base64Pattern);

    if (base64Match) {
        return {
            format: 'base64',
            text: base64Match[1].trim(),
            email: base64Match[2].trim(),
            publicKey: base64Match[3].trim(),
            signature: base64Match[4].trim(),
        };
    }

    // Try legacy hex format
    const hexPattern = /\[Signed\]\s*([\s\S]*?)\s*---\s*Signed-by:\s*(\S+)\s*Key:\s*([a-fA-F0-9]+)\s*Sig:\s*([a-fA-F0-9]+)/;
    const hexMatch = block.match(hexPattern);

    if (hexMatch) {
        return {
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
// Exports
// =============================================================================

// Export for use in other scripts (when imported as module)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        toHex,
        fromHex,
        toBase64,
        fromBase64,
        generateKeypair,
        getFingerprint,
        signMessage,
        signMessageHex,
        verifySignature,
        formatVouchBlock,
        formatVouchBlockShort,
        parseVouchBlock,
    };
}
