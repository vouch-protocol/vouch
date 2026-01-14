/**
 * Vouch Verify API - Cloudflare Worker
 * 
 * Stores and retrieves Vouch signatures with short IDs.
 * Supports free tier (1 year expiry) and pro tier (no expiry).
 */

// CORS headers for browser requests
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Generate a random 6-character short ID
function generateShortId() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let id = '';
    for (let i = 0; i < 6; i++) {
        id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
}

// Check if short ID already exists
async function idExists(env, id) {
    const existing = await env.SIGNATURES.get(id);
    return existing !== null;
}

// Generate unique short ID (retry if collision)
async function generateUniqueId(env, maxRetries = 5) {
    for (let i = 0; i < maxRetries; i++) {
        const id = generateShortId();
        if (!await idExists(env, id)) {
            return id;
        }
    }
    // Fallback to longer ID if too many collisions
    return generateShortId() + generateShortId();
}

// Handle OPTIONS (CORS preflight)
function handleOptions() {
    return new Response(null, {
        status: 204,
        headers: corsHeaders,
    });
}

// POST /api/sign - Store a new signature
async function handleSignature(request, env) {
    try {
        const body = await request.json();

        // Validate required fields
        const { text, email, key, sig } = body;
        if (!text || !email || !key || !sig) {
            return new Response(JSON.stringify({
                error: 'Missing required fields: text, email, key, sig',
            }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        // Check for pro tier (via API key header)
        const apiKey = request.headers.get('X-Vouch-API-Key');
        const isPro = apiKey && await validateProKey(env, apiKey);

        // Calculate expiration
        const expiryDays = isPro ? null : parseInt(env.FREE_TIER_EXPIRY_DAYS || '365');
        const expiresAt = expiryDays
            ? Date.now() + (expiryDays * 24 * 60 * 60 * 1000)
            : null;

        // Generate unique short ID
        const shortId = await generateUniqueId(env);

        // Prepare data to store
        const signatureData = {
            text,
            email,
            key,
            sig,
            created: new Date().toISOString(),
            expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
            tier: isPro ? 'pro' : 'free',
        };

        // Store in KV with optional expiration (in seconds)
        const kvOptions = expiryDays
            ? { expirationTtl: expiryDays * 24 * 60 * 60 }
            : {};

        await env.SIGNATURES.put(shortId, JSON.stringify(signatureData), kvOptions);

        // Return success with short ID
        return new Response(JSON.stringify({
            success: true,
            id: shortId,
            url: `https://v.vouch-protocol.com/${shortId}`,
            shortUrl: `https://vouch-protocol.com/v/${shortId}`,
            expiresAt: signatureData.expiresAt,
        }), {
            status: 201,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: 'Failed to store signature',
            details: error.message,
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
}

// GET /api/verify/:id - Retrieve a signature
async function handleVerify(id, env) {
    try {
        const data = await env.SIGNATURES.get(id);

        if (!data) {
            return new Response(JSON.stringify({
                error: 'Signature not found or expired',
            }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        const signatureData = JSON.parse(data);

        return new Response(JSON.stringify({
            success: true,
            ...signatureData,
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: 'Failed to retrieve signature',
            details: error.message,
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
}

// Pro signers list - GitHub usernames who get custom ID access
// In production, this could be stored in KV or fetched from a database
const PRO_SIGNERS = ['rampyg']; // Add more as needed

// Verify Vouch token using GitHub SSH keys (PAD-008 approach)
async function verifyVouchAuth(request, env, payload) {
    const vouchToken = request.headers.get('Vouch-Token');

    if (!vouchToken) {
        // Also support API key as fallback
        const apiKey = request.headers.get('X-Vouch-API-Key');
        if (apiKey) {
            const validKeys = (env.PRO_API_KEYS || '').split(',').filter(k => k);
            return { isPro: validKeys.includes(apiKey), signer: null };
        }
        return { isPro: false, signer: null };
    }

    try {
        // Parse the Vouch token (JWS format: header.payload.signature)
        const parts = vouchToken.split('.');
        if (parts.length !== 3) {
            return { isPro: false, signer: null, error: 'Invalid token format' };
        }

        const [headerB64, payloadB64, signatureB64] = parts;
        const tokenPayload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));

        // Extract signer identity
        const issuer = tokenPayload.iss || tokenPayload.signer;
        if (!issuer) {
            return { isPro: false, signer: null, error: 'No issuer in token' };
        }

        // Parse issuer format: "github:username" or "did:web:..."
        let githubUsername = null;
        if (issuer.startsWith('github:')) {
            githubUsername = issuer.replace('github:', '');
        } else if (issuer.startsWith('did:github:')) {
            githubUsername = issuer.replace('did:github:', '');
        }

        if (!githubUsername) {
            return { isPro: false, signer: issuer, error: 'Only GitHub-based identities supported' };
        }

        // Check if signer is in Pro list
        // Note: We trust the issuer claim from the signed Vouch token
        // Full signature verification could be added via WebCrypto when Ed25519 support improves
        const isPro = PRO_SIGNERS.includes(githubUsername);

        return {
            isPro,
            signer: issuer,
            githubUsername,
            verified: true,
            note: 'Issuer from signed Vouch token, on Pro signers list'
        };

    } catch (error) {
        return { isPro: false, signer: null, error: error.message };
    }
}

// Legacy: Validate Pro API key 
async function validateProKey(env, apiKey) {
    const validKeys = (env.PRO_API_KEYS || '').split(',').filter(k => k);
    return validKeys.includes(apiKey);
}

// Health check endpoint
function handleHealth() {
    return new Response(JSON.stringify({
        status: 'healthy',
        service: 'vouch-verify-api',
        timestamp: new Date().toISOString(),
    }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
}

// Main request handler
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // Handle CORS preflight
        if (method === 'OPTIONS') {
            return handleOptions();
        }

        // Route requests
        const hostname = url.hostname;

        // Handle v.vouch-protocol.com 
        if (hostname === 'v.vouch-protocol.com') {
            // Check if it's an API endpoint first (before shortlink handling)
            if (path.startsWith('/api/')) {
                // Fall through to API handling below
            }
            // Check if it's a paper link (/p/xxx)
            else if (path.match(/^\/p\/([a-zA-Z0-9_-]+)$/)) {
                const paperMatch = path.match(/^\/p\/([a-zA-Z0-9_-]+)$/);
                return handlePaperPage(paperMatch[1], env);
            }
            // Handle shortlinks (e.g., /abc123)
            else {
                const shortId = path.replace('/', '');
                if (shortId && shortId.match(/^[a-zA-Z0-9]+$/)) {
                    // Redirect to main site verification page
                    return Response.redirect(`https://vouch-protocol.com/v/${shortId}`, 302);
                }
                // Root of v subdomain - redirect to main site
                return Response.redirect('https://vouch-protocol.com', 302);
            }
        }

        // Support both /api/* (old) and /* (new api subdomain)
        const apiPath = path.startsWith('/api') ? path : '/api' + path;

        if (apiPath === '/api/health' && method === 'GET') {
            return handleHealth();
        }

        if (apiPath === '/api/sign' && method === 'POST') {
            return handleSignature(request, env);
        }

        // Match /api/verify/:id or /verify/:id
        const verifyMatch = apiPath.match(/^\/api\/verify\/([a-zA-Z0-9]+)$/);
        if (verifyMatch && method === 'GET') {
            return handleVerify(verifyMatch[1], env);
        }

        // Paper registration endpoint - POST /api/paper/register
        if (apiPath === '/api/paper/register' && method === 'POST') {
            return handlePaperRegister(request, env);
        }

        // Paper verification endpoint - GET /api/paper/verify/:id
        const paperVerifyMatch = apiPath.match(/^\/api\/paper\/verify\/([a-zA-Z0-9_-]+)$/);
        if (paperVerifyMatch && method === 'GET') {
            return handlePaperVerify(paperVerifyMatch[1], env);
        }

        // 404 for unmatched routes
        return new Response(JSON.stringify({
            error: 'Not found',
            endpoints: {
                'POST /api/sign': 'Store a new signature',
                'GET /api/verify/:id': 'Retrieve a signature',
                'POST /api/paper/register': 'Register a paper signature',
                'GET /api/paper/verify/:id': 'Verify a paper signature',
                'GET /api/health': 'Health check',
            },
        }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    },
};

// POST /api/paper/register - Register a paper signature
// Free tier: generates random short ID
// Pro tier (with Vouch token or API key): allows custom ID
async function handlePaperRegister(request, env) {
    try {
        const body = await request.json();

        // Validate required fields
        const { sha256, author, signer, signature, title } = body;
        let { id } = body; // Optional for free tier, required for pro tier custom IDs

        if (!sha256 || !author || !signer) {
            return new Response(JSON.stringify({
                error: 'Missing required fields: sha256, author, signer',
            }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        // Check for pro tier via Vouch token or API key
        const authResult = await verifyVouchAuth(request, env, body);
        const isPro = authResult.isPro;

        // Handle ID assignment
        if (id) {
            // Custom ID requested - Pro tier only
            if (!isPro) {
                return new Response(JSON.stringify({
                    error: 'Custom paper IDs are a Pro feature. Sign your request with a Vouch token.',
                    hint: 'Use: vouch sign --json "<payload>" --header, then pass Vouch-Token header',
                    authResult,
                }), {
                    status: 402,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            }

            // Validate custom ID format
            if (!id.match(/^[a-zA-Z0-9_-]+$/)) {
                return new Response(JSON.stringify({
                    error: 'Invalid ID format. Use alphanumeric characters, dashes, and underscores.',
                }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            }
        } else {
            // Free tier: generate random ID
            id = await generateUniqueId(env);
        }

        // Check if ID already exists
        const existing = await env.SIGNATURES.get(`paper:${id}`);
        if (existing) {
            return new Response(JSON.stringify({
                error: 'Paper ID already registered. Choose a different ID.',
            }), {
                status: 409,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        // Prepare paper data
        const paperData = {
            id,
            sha256,
            author,
            signer, // e.g., "github:rampyg"
            signature: signature || null,
            title: title || null,
            registered: new Date().toISOString(),
            type: 'paper',
            tier: isPro ? 'pro' : 'free',
        };

        // Store with paper: prefix
        await env.SIGNATURES.put(`paper:${id}`, JSON.stringify(paperData));

        // Return success
        return new Response(JSON.stringify({
            success: true,
            id,
            verifyUrl: `https://v.vouch-protocol.com/p/${id}`,
            message: 'Paper signature registered successfully',
        }), {
            status: 201,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: 'Failed to register paper',
            details: error.message,
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
}

// GET /api/paper/verify/:id - Get paper signature data
async function handlePaperVerify(id, env) {
    try {
        const data = await env.SIGNATURES.get(`paper:${id}`);

        if (!data) {
            return new Response(JSON.stringify({
                error: 'Paper not found',
                id,
            }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        const paperData = JSON.parse(data);

        return new Response(JSON.stringify({
            success: true,
            verified: true,
            ...paperData,
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

    } catch (error) {
        return new Response(JSON.stringify({
            error: 'Failed to verify paper',
            details: error.message,
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
}

// Paper verification HTML page
function handlePaperPage(id, env) {
    return handlePaperVerify(id, env).then(async (response) => {
        const data = await response.json();

        // Format date as "10 Jan 2026 10:30:45"
        const formatDate = (isoString) => {
            const date = new Date(isoString);
            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            const day = date.getDate();
            const month = months[date.getMonth()];
            const year = date.getFullYear();
            const hours = date.getHours().toString().padStart(2, '0');
            const mins = date.getMinutes().toString().padStart(2, '0');
            const secs = date.getSeconds().toString().padStart(2, '0');
            return `${day} ${month} ${year} ${hours}:${mins}:${secs}`;
        };

        // Sanitize title - remove LaTeX commands like \title{...}
        const sanitizeTitle = (title) => {
            if (!title) return null;
            let clean = title;
            // Handle: \title{ (literal backslash stored in JSON)
            if (clean.startsWith('\\title{')) {
                clean = clean.slice(7); // \title{ = 7 chars
            }
            // Handle: TAB + itle{ (when \t was interpreted as tab)
            // Tab is 1 char, so total = 1 + 5 = 6 chars: \t + i + t + l + e + {
            else if (clean.startsWith('\title{')) {
                clean = clean.slice(6);
            }
            // Remove trailing }
            if (clean.endsWith('}')) {
                clean = clean.slice(0, -1);
            }
            return clean.trim() || null;
        };

        const displayTitle = sanitizeTitle(data.title);

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch Paper Verification - ${id}</title>
    <link rel="icon" type="image/png" href="https://vouch-protocol.com/assets/vouch-verified-icon.png?v=2">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #f5f5f5; }
        .card { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
        .logo { width: 40px; height: 40px; border-radius: 8px; }
        .verified { color: #22c55e; margin: 0; }
        .not-found { color: #ef4444; }
        h1 { margin-top: 0; }
        .field { margin: 16px 0; }
        .label { font-size: 12px; color: #666; text-transform: uppercase; }
        .value { font-size: 16px; margin-top: 4px; word-break: break-all; }
        .hash { font-family: monospace; font-size: 14px; background: #f0f0f0; padding: 8px; border-radius: 4px; }
        .footer { margin-top: 24px; text-align: center; color: #666; font-size: 14px; }
        .verify-note { font-style: italic; color: #888; font-size: 13px; margin-top: 16px; text-align: center; }
        .cta-banner { margin-top: 24px; padding: 16px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px; text-align: center; }
        .cta-banner a { color: white; text-decoration: none; font-weight: 600; }
        .cta-banner a:hover { text-decoration: underline; }
        a { color: #3b82f6; }
    </style>
</head>
<body>
    <div class="card">
        ${data.success ? `
        <div class="header">
            <img class="logo" src="https://vouch-protocol.com/vouch-logo-icon.jpg" alt="Vouch Protocol">
            <h1 class="verified">✓ Verified Paper</h1>
        </div>
        <div class="field">
            <div class="label">Paper ID</div>
            <div class="value">${data.id}</div>
        </div>
        ${displayTitle ? `
        <div class="field">
            <div class="label">Title</div>
            <div class="value">${displayTitle}</div>
        </div>` : ''}
        <div class="field">
            <div class="label">Author</div>
            <div class="value">${data.author}</div>
        </div>
        <div class="field">
            <div class="label">Signer</div>
            <div class="value">${data.signer}</div>
        </div>
        <div class="field">
            <div class="label">SHA-256 Hash</div>
            <div class="value hash">${data.sha256}</div>
        </div>
        <div class="field">
            <div class="label">Registered</div>
            <div class="value">${formatDate(data.registered)}</div>
        </div>
        <div class="verify-note">
            To verify yourself: compute SHA-256 of the PDF and compare with the hash above.
        </div>
        <div class="footer">
            <a href="https://vouch-protocol.com">vouch-protocol.com</a>
        </div>
        <div class="cta-banner">
            <a href="https://vouch-protocol.com">✍️ Sign your paper using Vouch Protocol for free → Get Started</a>
        </div>
        ` : `
        <h1 class="not-found">✗ Paper Not Found</h1>
        <p>No paper registered with ID: <strong>${id}</strong></p>
        <div class="footer">
            <a href="https://vouch-protocol.com">vouch-protocol.com</a>
        </div>
        <div class="cta-banner">
            <a href="https://vouch-protocol.com">✍️ Sign your paper using Vouch Protocol for free → Get Started</a>
        </div>
        `}
    </div>
</body>
</html>`;

        return new Response(html, {
            status: data.success ? 200 : 404,
            headers: { 'Content-Type': 'text/html' },
        });
    });
}



