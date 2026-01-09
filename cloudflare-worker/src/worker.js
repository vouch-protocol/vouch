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

// Validate Pro API key (placeholder - implement with your auth system)
async function validateProKey(env, apiKey) {
    // TODO: Implement actual API key validation
    // For now, check against a simple env var
    // In production, you'd check against a database or auth service
    const validKeys = (env.PRO_API_KEYS || '').split(',');
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

        // Handle v.vouch-protocol.com shortlinks - redirect to verification page
        if (hostname === 'v.vouch-protocol.com') {
            const shortId = path.replace('/', '');
            if (shortId && shortId.match(/^[a-zA-Z0-9]+$/)) {
                // Redirect to main site verification page
                return Response.redirect(`https://vouch-protocol.com/v/${shortId}`, 302);
            }
            // Root of v subdomain - redirect to main site
            return Response.redirect('https://vouch-protocol.com', 302);
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

        // 404 for unmatched routes
        return new Response(JSON.stringify({
            error: 'Not found',
            endpoints: {
                'POST /api/sign': 'Store a new signature',
                'GET /api/verify/:id': 'Retrieve a signature',
                'GET /api/health': 'Health check',
            },
        }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    },
};
