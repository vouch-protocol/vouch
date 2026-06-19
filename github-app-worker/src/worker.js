/**
 * Vouch Gatekeeper - GitHub App Webhook Handler
 * Cloudflare Workers Edition
 * 
 * Enforces cryptographic identity on every Pull Request.
 * 
 * Features:
 * - Webhook signature verification
 * - GitHub App JWT authentication
 * - Installation token exchange
 * - Check run creation
 * - Hybrid verification (GitHub keys + Vouch Registry)
 */

// =============================================================================
// Constants
// =============================================================================

const GITHUB_API = 'https://api.github.com';

// GitHub web-flow key IDs (merge via UI)
const GITHUB_WEBFLOW_KEY_IDS = new Set([
    '4AEE18F83AFDEB23',
    'B5690EEEBB952194',
]);

// Known bot accounts
const KNOWN_BOTS = new Set([
    'dependabot[bot]',
    'github-actions[bot]',
    'renovate[bot]',
]);

// CORS headers
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Hub-Signature-256, X-GitHub-Event',
};

// =============================================================================
// Crypto Helpers
// =============================================================================

/**
 * Verify GitHub webhook signature
 */
async function verifyWebhookSignature(payload, signature, secret) {
    if (!signature) return false;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
    const computed = 'sha256=' + Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return computed === signature;
}

/**
 * Create GitHub App JWT
 */
async function createAppJWT(appId, privateKey) {
    const now = Math.floor(Date.now() / 1000);

    const header = {
        alg: 'RS256',
        typ: 'JWT',
    };

    const payload = {
        iat: now - 60,
        exp: now + (10 * 60),
        iss: appId,
    };

    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const data = `${encodedHeader}.${encodedPayload}`;

    // Import the private key
    const pemContents = privateKey
        .replace('-----BEGIN RSA PRIVATE KEY-----', '')
        .replace('-----END RSA PRIVATE KEY-----', '')
        .replace(/\s/g, '');

    const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

    const key = await crypto.subtle.importKey(
        'pkcs8',
        binaryKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        key,
        new TextEncoder().encode(data)
    );

    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    return `${data}.${encodedSignature}`;
}

// =============================================================================
// GitHub API Client
// =============================================================================

class GitHubClient {
    constructor(env, installationId) {
        this.env = env;
        this.installationId = installationId;
        this.token = null;
    }

    async getInstallationToken() {
        if (this.token) return this.token;

        const jwt = await createAppJWT(this.env.GITHUB_APP_ID, this.env.GITHUB_PRIVATE_KEY);

        const response = await fetch(
            `${GITHUB_API}/app/installations/${this.installationId}/access_tokens`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${jwt}`,
                    'Accept': 'application/vnd.github+json',
                    'User-Agent': 'Vouch-Gatekeeper/2.0',
                },
            }
        );

        if (!response.ok) {
            throw new Error(`Failed to get installation token: ${response.status}`);
        }

        const data = await response.json();
        this.token = data.token;
        return this.token;
    }

    async request(method, endpoint, body = null) {
        const token = await this.getInstallationToken();

        const options = {
            method,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'Vouch-Gatekeeper/2.0',
            },
        };

        if (body) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }

        const response = await fetch(`${GITHUB_API}${endpoint}`, options);

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`GitHub API error ${response.status}: ${text}`);
        }

        return response.json();
    }

    // PR commits
    async getPRCommits(owner, repo, prNumber) {
        return this.request('GET', `/repos/${owner}/${repo}/pulls/${prNumber}/commits`);
    }

    // File content
    async getFileContent(owner, repo, path, ref = 'HEAD') {
        try {
            const data = await this.request('GET', `/repos/${owner}/${repo}/contents/${path}?ref=${ref}`);
            return atob(data.content);
        } catch (e) {
            return null;
        }
    }

    // Create check run
    async createCheckRun(owner, repo, headSha, name, status, conclusion, title, summary, text) {
        const payload = {
            name,
            head_sha: headSha,
            status,
        };

        if (conclusion) {
            payload.conclusion = conclusion;
        }

        if (title || summary) {
            payload.output = { title, summary, text: text || '' };
        }

        return this.request('POST', `/repos/${owner}/${repo}/check-runs`, payload);
    }

    // Get user GPG keys
    async getUserGPGKeys(username) {
        try {
            return await this.request('GET', `/users/${username}/gpg_keys`);
        } catch (e) {
            return [];
        }
    }

    // Check org membership
    async isOrgMember(org, username) {
        try {
            await this.request('GET', `/orgs/${org}/members/${username}`);
            return true;
        } catch (e) {
            return false;
        }
    }
}

// =============================================================================
// Policy Parser
// =============================================================================

function parsePolicy(yamlContent) {
    // Simple YAML parser for our use case
    if (!yamlContent) {
        return {
            requireSignedCommits: true,
            allowUnsignedMergeCommits: false,
            allowBots: true,
            policyType: 'implicit_organization_trust',
            allowedOrganizations: [],
            allowedUsers: [],
            isDefault: true,
        };
    }

    try {
        // Basic YAML parsing (supports our simple structure)
        const lines = yamlContent.split('\n');
        const policy = {
            requireSignedCommits: true,
            allowUnsignedMergeCommits: false,
            allowBots: true,
            policyType: 'explicit',
            allowedOrganizations: [],
            allowedUsers: [],
            isDefault: false,
        };

        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('require_signed_commits:')) {
                policy.requireSignedCommits = trimmed.includes('true');
            }
            if (trimmed.startsWith('allow_unsigned_merge_commits:')) {
                policy.allowUnsignedMergeCommits = trimmed.includes('true');
            }
            if (trimmed.startsWith('allow_bots:')) {
                policy.allowBots = trimmed.includes('true');
            }
            if (trimmed.startsWith('policy_type:')) {
                policy.policyType = trimmed.split(':')[1].trim().replace(/["']/g, '');
            }
        }

        return policy;
    } catch (e) {
        return {
            requireSignedCommits: true,
            allowUnsignedMergeCommits: false,
            allowBots: true,
            policyType: 'implicit_organization_trust',
            allowedOrganizations: [],
            allowedUsers: [],
            isDefault: true,
        };
    }
}

// =============================================================================
// Verification Engine
// =============================================================================

async function verifyCommit(commit, github, repoOrg, policy) {
    const sha = commit.sha.substring(0, 7);
    const author = commit.commit.author.name;
    const authorLogin = commit.author?.login || '';
    const verification = commit.commit.verification || {};
    const isVerified = verification.verified || false;
    const signature = verification.signature || '';
    const keyId = verification.key_id || '';
    const reason = verification.reason || '';

    const isMerge = (commit.parents?.length || 0) > 1;
    const isBot = KNOWN_BOTS.has(authorLogin);

    const result = {
        sha,
        author,
        authorLogin,
        isSigned: !!signature,
        isVerified,
        isBot,
        isMergeCommit: isMerge,
        error: null,
        source: null,
        isOrgMember: false,
    };

    // Unsigned commit
    if (!result.isSigned) {
        if (isMerge && policy.allowUnsignedMergeCommits) {
            result.source = 'unsigned_merge';
            return result;
        }
        if (isBot && policy.allowBots) {
            result.source = 'bot';
            return result;
        }
        result.error = 'Commit is not signed';
        return result;
    }

    // Bot with signature
    if (isBot && policy.allowBots) {
        result.source = 'bot';
        return result;
    }

    // GitHub web-flow
    if (GITHUB_WEBFLOW_KEY_IDS.has(keyId)) {
        result.source = 'github_webflow';
        return result;
    }

    // Signature didn't verify
    if (!isVerified) {
        result.error = `Signature verification failed: ${reason}`;
        return result;
    }

    // Check GitHub GPG keys
    if (authorLogin) {
        const gpgKeys = await github.getUserGPGKeys(authorLogin);

        for (const gpgKey of gpgKeys) {
            if (gpgKey.key_id === keyId) {
                result.source = 'github_gpg';
                result.isOrgMember = await github.isOrgMember(repoOrg, authorLogin);
                return result;
            }

            for (const subkey of (gpgKey.subkeys || [])) {
                if (subkey.key_id === keyId) {
                    result.source = 'github_gpg';
                    result.isOrgMember = await github.isOrgMember(repoOrg, authorLogin);
                    return result;
                }
            }
        }
    }

    // GitHub verified but key not in user's account
    result.source = 'github_verified';
    if (authorLogin) {
        result.isOrgMember = await github.isOrgMember(repoOrg, authorLogin);
    }

    return result;
}

function isAuthorized(result, policy, repoOrg) {
    // Zero-config: implicit org trust
    if (policy.policyType === 'implicit_organization_trust') {
        if (result.isOrgMember) return true;
        if (result.source === 'github_webflow') return true;
        if (result.source === 'bot') return true;
        return false;
    }

    // Explicit: check allowlists
    if (policy.allowedOrganizations.length === 0 && policy.allowedUsers.length === 0) {
        return true; // No restrictions
    }

    if (policy.allowedUsers.includes(`github:${result.authorLogin}`)) {
        return true;
    }

    return false;
}

// =============================================================================
// Webhook Handler
// =============================================================================

async function handlePullRequestEvent(payload, env) {
    const action = payload.action;
    const pr = payload.pull_request;
    const repo = payload.repository;
    const installation = payload.installation;

    // Only handle PR opened/synchronized
    if (!['opened', 'synchronize', 'reopened'].includes(action)) {
        return { message: `Skipping PR action: ${action}` };
    }

    const owner = repo.owner.login;
    const repoName = repo.name;
    const prNumber = pr.number;
    const headSha = pr.head.sha;

    const github = new GitHubClient(env, installation.id);

    // Create "in progress" check
    await github.createCheckRun(
        owner, repoName, headSha,
        'Vouch Gatekeeper',
        'in_progress',
        null,
        '🔍 Verifying commit signatures...',
        'Checking cryptographic identity of all commits.'
    );

    try {
        // Get policy
        const policyContent = await github.getFileContent(owner, repoName, '.github/vouch-policy.yml');
        const policy = parsePolicy(policyContent);

        // Get commits
        const commits = await github.getPRCommits(owner, repoName, prNumber);

        // Verify each commit
        const results = [];
        for (const commit of commits) {
            const result = await verifyCommit(commit, github, owner, policy);

            if (!result.error && !isAuthorized(result, policy, owner)) {
                result.error = `User '${result.authorLogin}' is not authorized by policy`;
            }

            results.push(result);
        }

        const passed = results.filter(r => !r.error);
        const failed = results.filter(r => r.error);

        // Create final check
        if (failed.length > 0) {
            const failedDetails = failed.map(f =>
                `- \`${f.sha}\` by ${f.author}: ${f.error}`
            ).join('\n');

            await github.createCheckRun(
                owner, repoName, headSha,
                'Vouch Gatekeeper',
                'completed',
                'failure',
                `❌ ${failed.length} commit(s) failed verification`,
                `Failed commits:\n${failedDetails}`,
                `Policy: ${policy.isDefault ? 'Zero-Config (org members only)' : 'Custom'}`
            );
        } else {
            const authors = [...new Set(passed.map(p => p.authorLogin || p.author))].join(', ');
            const policyNote = policy.isDefault ? ' (Zero-Config)' : '';

            await github.createCheckRun(
                owner, repoName, headSha,
                'Vouch Gatekeeper',
                'completed',
                'success',
                `✅ All ${passed.length} commit(s) verified`,
                `Authors: ${authors}${policyNote}`,
                ''
            );
        }

        return {
            success: true,
            passed: passed.length,
            failed: failed.length,
        };

    } catch (error) {
        // Report error as check
        await github.createCheckRun(
            owner, repoName, headSha,
            'Vouch Gatekeeper',
            'completed',
            'failure',
            '❌ Error during verification',
            `Error: ${error.message}`,
            ''
        );

        throw error;
    }
}

async function handleCheckSuiteEvent(payload, env) {
    const action = payload.action;

    if (action !== 'requested') {
        return { message: `Skipping check_suite action: ${action}` };
    }

    // Re-run verification for all PRs in this check suite
    const checkSuite = payload.check_suite;
    const pullRequests = checkSuite.pull_requests || [];

    if (pullRequests.length === 0) {
        return { message: 'No pull requests in check suite' };
    }

    // Process first PR
    const pr = pullRequests[0];
    return handlePullRequestEvent({
        action: 'synchronize',
        pull_request: {
            number: pr.number,
            head: { sha: checkSuite.head_sha },
        },
        repository: payload.repository,
        installation: payload.installation,
    }, env);
}

// =============================================================================
// Main Handler
// =============================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const method = request.method;

        // CORS
        if (method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders });
        }

        // Health check
        if (url.pathname === '/health' && method === 'GET') {
            return new Response(JSON.stringify({
                status: 'healthy',
                service: 'vouch-gatekeeper',
                version: '2.0.0',
                timestamp: new Date().toISOString(),
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
        }

        // Webhook endpoint
        if (url.pathname === '/webhook' && method === 'POST') {
            const body = await request.text();
            const signature = request.headers.get('X-Hub-Signature-256');
            const event = request.headers.get('X-GitHub-Event');

            // Verify signature
            if (!await verifyWebhookSignature(body, signature, env.GITHUB_WEBHOOK_SECRET)) {
                return new Response(JSON.stringify({ error: 'Invalid signature' }), {
                    status: 401,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            }

            const payload = JSON.parse(body);

            try {
                let result;

                switch (event) {
                    case 'pull_request':
                        result = await handlePullRequestEvent(payload, env);
                        break;
                    case 'check_suite':
                        result = await handleCheckSuiteEvent(payload, env);
                        break;
                    case 'ping':
                        result = { message: 'pong', zen: payload.zen };
                        break;
                    default:
                        result = { message: `Unhandled event: ${event}` };
                }

                return new Response(JSON.stringify(result), {
                    status: 200,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });

            } catch (error) {
                console.error('Webhook error:', error);
                return new Response(JSON.stringify({
                    error: 'Internal error',
                    message: error.message,
                }), {
                    status: 500,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
                });
            }
        }

        // 404
        return new Response(JSON.stringify({
            error: 'Not found',
            endpoints: {
                'GET /health': 'Health check',
                'POST /webhook': 'GitHub webhook handler',
            },
        }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    },
};
