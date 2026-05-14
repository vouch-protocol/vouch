/**
 * Vouch Assistant error codes (client-side, frontend-only for now).
 *
 * Each code is stable and append-only. Once a code ships, its meaning does
 * not change. New conditions get new numbers. This is what makes the system
 * useful for tracking error recurrence across versions.
 *
 * The full system (backend-issued codes + Python SDK `vouch.errors` module
 * + protocol verifier-reason mapping) is in the roadmap as a follow-up.
 *
 * Public surface: when something fails, the user sees the code first
 * (monospace, selectable so they can paste it into a GitHub issue) and the
 * remediation hint second. The code identifies the failure class; the hint
 * tells the user what to try.
 */

export type VouchErrorCategory =
    | 'NET'    // Network / transport
    | 'CFG'    // Configuration
    | 'VAL'    // Validation / allow-list
    | 'LLM'    // Upstream LLM provider
    | 'SIG'    // Signing errors (sidecar-side)
    | 'VRF'    // Verification errors (verifier-side)
    | 'RAG'    // Knowledge retrieval
    | 'SES'    // Heartbeat / session
    | 'UNK';   // Anything we did not anticipate

export interface VouchError {
    /** Stable identifier, e.g. "VCH-NET-001". Never changes once published. */
    code: string;
    /** Short title for inline display. */
    title: string;
    /** Longer explanation, one or two sentences. */
    description: string;
    /** Recommended user action. */
    hint: string;
}

/**
 * Registry of error codes the chat widget knows about today.
 * Append new entries; do not renumber existing ones.
 */
export const ERROR_CODES: Record<string, VouchError> = {
    'VCH-NET-001': {
        code: 'VCH-NET-001',
        title: 'Hosted backend unreachable',
        description: 'The chat backend could not be reached from your browser.',
        hint: 'The hosted assistant may not be live yet. You can self-host the backend (see Guides), or try again later.',
    },
    'VCH-NET-002': {
        code: 'VCH-NET-002',
        title: 'Blocked by browser security policy',
        description: 'Your browser blocked the request to the chat backend (Private Network Access, CORS, or content-security policy).',
        hint: 'If you saw a permission prompt earlier, clicking Allow may resolve this. If the issue persists, the deployed configuration may need a fix; open a GitHub issue with this code.',
    },
    'VCH-NET-003': {
        code: 'VCH-NET-003',
        title: 'Request timed out',
        description: 'The chat backend did not respond in time.',
        hint: 'Try again. If timeouts keep happening, the upstream LLM provider may be slow or down.',
    },
    'VCH-NET-004': {
        code: 'VCH-NET-004',
        title: 'Backend returned an HTTP error',
        description: 'The chat backend responded with a non-success status. The status code is included in the message.',
        hint: 'A transient issue. Try again; if it recurs, paste this code in a GitHub issue.',
    },
    'VCH-CFG-001': {
        code: 'VCH-CFG-001',
        title: 'No LLM key configured on backend',
        description: 'The chat backend is running but has no API key for the configured LLM provider.',
        hint: 'If you are self-hosting, set VOUCH_LLM_PROVIDER and the matching key in .env, then restart. If this is the hosted assistant, this is a deployment bug; open a GitHub issue.',
    },
    'VCH-CFG-002': {
        code: 'VCH-CFG-002',
        title: 'Sidecar unreachable from backend',
        description: 'The chat backend is running but cannot reach the signing sidecar.',
        hint: 'If self-hosting, confirm the sidecar is up on the URL set in VOUCH_SIDECAR_URL (default http://127.0.0.1:8877).',
    },
    'VCH-VAL-001': {
        code: 'VCH-VAL-001',
        title: 'Required intent field missing',
        description: 'A signing request was sent with a missing action, target, or resource.',
        hint: 'This is a frontend bug; the assistant should never propose an intent missing required fields. Open a GitHub issue with the question you asked.',
    },
    'VCH-VAL-002': {
        code: 'VCH-VAL-002',
        title: 'Action not in this deployment\'s allow-list',
        description: 'The assistant attempted to sign an action that is not permitted by this deployment\'s configuration.',
        hint: 'This is expected for actions outside the assistant\'s scope. Rephrase your question, or open a GitHub issue if you believe the action should be allowed.',
    },
    'VCH-LLM-001': {
        code: 'VCH-LLM-001',
        title: 'Upstream LLM provider error',
        description: 'The chat backend reached the LLM provider but received an error response.',
        hint: 'Try again; this is usually transient. If it keeps happening, the provider may be in an outage.',
    },
    'VCH-UNK-001': {
        code: 'VCH-UNK-001',
        title: 'Unexpected error',
        description: 'Something went wrong that the assistant does not recognize.',
        hint: 'Reload the page and try again. If it recurs, please open a GitHub issue with this code and the message below.',
    },
};

/**
 * Map a raw error (Error object, response status, or backend event payload)
 * to a structured VouchError. Heuristics are intentionally conservative; when
 * in doubt we return VCH-UNK-001 with the raw message attached.
 */
export interface ClassifiedError {
    vouch: VouchError;
    raw: string;
}

export function classifyError(input: unknown, context?: { status?: number; rawText?: string }): ClassifiedError {
    const raw = (() => {
        if (typeof input === 'string') return input;
        if (input instanceof Error) return input.message;
        try {
            return JSON.stringify(input);
        } catch {
            return String(input);
        }
    })();

    const lowerRaw = raw.toLowerCase();

    // Backend error event with explicit message
    if (lowerRaw.includes('gemini_api_key') || lowerRaw.includes('anthropic_api_key') || lowerRaw.includes('openai_api_key')) {
        return { vouch: ERROR_CODES['VCH-CFG-001'], raw };
    }
    if (lowerRaw.includes('sidecar') && (lowerRaw.includes('unreachable') || lowerRaw.includes('refused'))) {
        return { vouch: ERROR_CODES['VCH-CFG-002'], raw };
    }
    if (lowerRaw.includes('not in allow-list') || lowerRaw.includes('not_in_allow_list')) {
        return { vouch: ERROR_CODES['VCH-VAL-002'], raw };
    }
    if (lowerRaw.includes('is required') && lowerRaw.includes('intent.')) {
        return { vouch: ERROR_CODES['VCH-VAL-001'], raw };
    }
    if (lowerRaw.includes('llm') || lowerRaw.includes('upstream')) {
        return { vouch: ERROR_CODES['VCH-LLM-001'], raw };
    }

    // Fetch-level failures (the most common case).
    if (input instanceof TypeError) {
        // `TypeError: Failed to fetch` is what browsers throw on network refused,
        // PNA block, CORS preflight fail. We can't distinguish them at the JS layer.
        return { vouch: ERROR_CODES['VCH-NET-001'], raw };
    }

    if (context?.status) {
        if (context.status === 408 || context.status === 504) {
            return { vouch: ERROR_CODES['VCH-NET-003'], raw };
        }
        return { vouch: ERROR_CODES['VCH-NET-004'], raw };
    }

    if (lowerRaw.includes('timeout') || lowerRaw.includes('timed out')) {
        return { vouch: ERROR_CODES['VCH-NET-003'], raw };
    }
    if (lowerRaw.includes('failed to fetch') || lowerRaw.includes('networkerror') || lowerRaw.includes('load failed')) {
        return { vouch: ERROR_CODES['VCH-NET-001'], raw };
    }

    return { vouch: ERROR_CODES['VCH-UNK-001'], raw };
}
