/**
 * Answers for the vouch-protocol.com apex now that the website lives at
 * vouch-protocol.org.
 *
 * Two kinds of request arrive here:
 *
 *   1. Identifier URLs. JSON-LD context and vocabulary URLs, did:web documents
 *      and credential status lists are named with the .com host inside signed
 *      credentials and resolver configuration, so they keep answering on .com
 *      with an ordinary response. They are fetched from the site and returned
 *      as they are.
 *   2. Pages. Everything else gets a permanent redirect to the same path on
 *      the site.
 *
 * The verify, API and C2PA routes on this host belong to other Workers. Their
 * own, more specific routes match first, and this Worker hands such a request
 * straight to the origin if one ever reaches it.
 */

const DEFAULT_SITE = 'https://vouch-protocol.org';

// Path prefixes that name protocol identifiers.
const IDENTIFIER_PREFIXES = [
    '/.well-known/',
    '/contexts/',
    '/schemas/',
    '/ns/',
    '/credentials/',
    '/attribution/',
    '/covenants/',
    '/xmp/',
    '/pacing/',
    '/budget/',
    '/audit/',
    '/ext/',
];

// Single files that tools fetch by their .com address.
const IDENTIFIER_FILES = ['/funding.json', '/install.sh'];

// Paths served by other Workers on this host.
const OTHER_WORKER_PREFIXES = ['/v/', '/api/', '/.well-known/c2pa-'];

// Response headers carried over from the site for an identifier URL.
const PASSED_HEADERS = ['content-type', 'cache-control', 'etag', 'last-modified', 'access-control-allow-origin'];

const MAX_SITE_HOPS = 3;

function siteOrigin(env) {
    const configured = env && env.SITE_ORIGIN ? String(env.SITE_ORIGIN) : DEFAULT_SITE;
    const url = new URL(configured);
    if (url.protocol !== 'https:' || url.origin !== configured.replace(/\/+$/, '')) {
        throw new Error('SITE_ORIGIN must be a plain https origin');
    }
    return url.origin;
}

/** Sort a request path into "other" (another Worker's), "identifier" or "page". */
export function classify(pathname) {
    if (OTHER_WORKER_PREFIXES.some((prefix) => pathname.startsWith(prefix))) return 'other';
    if (pathname.endsWith('/did.json')) return 'identifier';
    if (IDENTIFIER_FILES.includes(pathname)) return 'identifier';
    if (IDENTIFIER_PREFIXES.some((prefix) => pathname.startsWith(prefix))) return 'identifier';
    return 'page';
}

function text(status, body, extra = {}) {
    return new Response(body, {
        status,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff', ...extra },
    });
}

/**
 * Fetch one identifier file from the site. Only the site origin is ever
 * contacted: a redirect is followed when it stays on that origin and refused
 * otherwise. The query string and the caller's headers are not sent on.
 */
async function fetchFromSite(origin, pathname, method, fetchImpl) {
    let target = origin + pathname;
    for (let hop = 0; hop < MAX_SITE_HOPS; hop += 1) {
        const url = new URL(target);
        if (url.origin !== origin) return null;
        const response = await fetchImpl(url.toString(), { method, redirect: 'manual', headers: { accept: '*/*' } });
        if (response.status < 300 || response.status >= 400) return response;
        const location = response.headers.get('location');
        if (!location) return null;
        target = new URL(location, url).toString();
    }
    return null;
}

async function serveIdentifier(origin, pathname, method, fetchImpl) {
    if (method !== 'GET' && method !== 'HEAD') {
        return text(405, 'Method not allowed\n', { allow: 'GET, HEAD' });
    }
    let response;
    try {
        response = await fetchFromSite(origin, pathname, method, fetchImpl);
    } catch (error) {
        return text(502, 'The site could not be reached\n');
    }
    if (response === null) return text(502, 'The site returned an unexpected redirect\n');
    if (response.status === 404 || response.status === 410) return text(404, 'Not found\n');
    if (response.status !== 200) return text(502, 'The site returned an unexpected response\n');

    const headers = new Headers({ 'x-content-type-options': 'nosniff' });
    for (const name of PASSED_HEADERS) {
        const value = response.headers.get(name);
        if (value) headers.set(name, value);
    }
    return new Response(method === 'HEAD' ? null : response.body, { status: 200, headers });
}

export async function handle(request, env, fetchImpl = fetch) {
    const origin = siteOrigin(env);
    const url = new URL(request.url);
    const kind = classify(url.pathname);

    if (kind === 'other') return fetchImpl(request);
    if (kind === 'identifier') return serveIdentifier(origin, url.pathname, request.method, fetchImpl);

    // The path always starts with a slash, so the redirect cannot leave the site.
    return new Response(null, {
        status: 301,
        headers: { location: origin + url.pathname + url.search, 'cache-control': 'public, max-age=3600' },
    });
}

export default {
    fetch(request, env) {
        return handle(request, env);
    },
};
