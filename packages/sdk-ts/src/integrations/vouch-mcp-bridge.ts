/**
 * Vouch MCP signed-response extension.
 *
 * Adds Vouch-native per-response signing to any MCP server. Every tool
 * response carries a full Vouch Credential in `_meta.vouch`, signed
 * with `eddsa-jcs-2022` (or the dual-proof PQ profile). The credential
 * proves which agent produced the response, what intent it claimed,
 * and binds those claims to the response body via a content hash in
 * the credential's intent field.
 *
 * This is the Vouch-native counterpart to MCP-I's transport-level
 * signing pattern, with two differences:
 *   1. Wire format is a full W3C Verifiable Credential, not a detached JWS.
 *      Verifiers get the issuer DID, the intent, the delegation chain,
 *      and the cryptosuite all in one self-describing object.
 *   2. The crypto is `eddsa-jcs-2022` (Data Integrity), the protocol's
 *      canonical cryptosuite, with an opt-in dual-proof PQ variant.
 *      No new cryptosuite identifier is introduced for MCP usage.
 *
 * A response that's been signed this way can be verified by any Vouch
 * verifier, on or off MCP. The signing is transport-independent; MCP is
 * just one carrier.
 *
 * USAGE
 * -----
 *
 *     import { signMcpResponse, mcpSignedHandler } from
 *         '@vouch-protocol-official/sdk/integrations/mcp-signed-response';
 *     import { Signer } from '@vouch-protocol-official/sdk';
 *
 *     const signer = new Signer({ privateKey, did, ... });
 *
 *     // Single-call:
 *     const stamped = await signMcpResponse(
 *         { content: [{ type: 'text', text: 'hello' }] },
 *         signer,
 *         { action: 'respond', target: 'echo_tool',
 *           resource: 'https://my-mcp.example.com/tools/echo' },
 *     );
 *
 *     // Or wrap a handler:
 *     const handler = mcpSignedHandler(
 *         originalHandler,
 *         signer,
 *         (args) => ({ action: 'respond', target: 'echo_tool',
 *                      resource: 'https://my-mcp.example.com/tools/echo' }),
 *     );
 */

import { canonicalize } from '../jcs.js';
import type { Signer } from '../signer.js';
import type { VouchCredential, Intent } from '../types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface VouchMetaBlock {
    /** Vouch protocol version this metadata block conforms to. */
    v: '1.0';
    /** SHA-256 of the JCS-canonicalized response body (excluding `_meta.vouch`),
     *  hex-encoded. Verifiers recompute and compare. Same value also lives
     *  inside the credential's `intent.contentHash` so the binding is
     *  cryptographically signed, not merely transport-attached. */
    contentHash: string;
    /** The full Vouch Credential signing this response. Includes the agent's
     *  DID (issuer), the intent (with contentHash), validity window,
     *  delegation chain (if any), and the Data Integrity proof. */
    credential: VouchCredential;
}

export interface McpResponse {
    [key: string]: unknown;
    _meta?: {
        [key: string]: unknown;
        vouch?: VouchMetaBlock;
    };
}

export interface SignMcpResponseOptions {
    /** Optional clock for deterministic testing. */
    now?: () => number;
    /** Optional override for credential validity (seconds). Defaults to
     *  the Signer's configured `defaultExpiry`. */
    validSeconds?: number;
    /** Use the dual-proof PQ cryptosuite (eddsa + ML-DSA-44) instead of
     *  the classical-only profile. Default: false. */
    hybrid?: boolean;
}

/** The intent the wrapper builds for a response. Caller supplies action,
 *  target, and resource; the wrapper appends `contentHash`. */
export interface ResponseIntent {
    action: string;
    target: string;
    resource: string;
    /** Optional additional fields the deployment cares about. */
    [extra: string]: unknown;
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

const asBufferSource = (bytes: Uint8Array): ArrayBuffer => {
    const out = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(out).set(bytes);
    return out;
};

const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
    const digest = await crypto.subtle.digest('SHA-256', asBufferSource(bytes));
    const arr = new Uint8Array(digest);
    let hex = '';
    for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
    return hex;
};

// ---------------------------------------------------------------------------
// Sign a single response
// ---------------------------------------------------------------------------

/**
 * Stamp an MCP response with a Vouch credential signing the response body.
 *
 * The credential's `intent.contentHash` field carries the SHA-256 of the
 * JCS-canonicalized response with `_meta.vouch` removed. Because the
 * credential is itself signed (Data Integrity), the binding between
 * intent + response body is cryptographically enforced. A verifier:
 *   1. Strips `_meta.vouch` from the response.
 *   2. JCS-canonicalizes the remainder.
 *   3. SHA-256 hashes the canonical bytes.
 *   4. Reads the credential's `intent.contentHash` from the stripped block.
 *   5. Confirms the two hashes match.
 *   6. Verifies the credential's Data Integrity proof against the issuer DID.
 */
export async function signMcpResponse(
    response: McpResponse,
    signer: Signer,
    intent: ResponseIntent,
    options: SignMcpResponseOptions = {},
): Promise<McpResponse> {
    // 1. Strip any existing _meta.vouch and compute the content hash.
    const { _meta = {}, ...rest } = response;
    const { vouch: _drop, ...metaWithoutVouch } = (_meta as Record<string, unknown>) ?? {};
    const sanitised: Record<string, unknown> = { ...rest };
    if (Object.keys(metaWithoutVouch).length > 0) {
        sanitised._meta = metaWithoutVouch;
    }
    const canonicalBytes = canonicalize(sanitised);
    const contentHash = await sha256Hex(canonicalBytes);

    // 2. Build the bound intent: include contentHash so the binding is
    //    inside the signed credential, not just transport-attached.
    const boundIntent: Intent = {
        ...intent,
        contentHash: `sha256:${contentHash}`,
    } as Intent;

    // 3. Sign via the protocol's normal credential path.
    const credential = options.hybrid
        ? await signer.signCredentialHybrid({ intent: boundIntent, validSeconds: options.validSeconds })
        : await signer.signCredential({ intent: boundIntent, validSeconds: options.validSeconds });

    // 4. Attach the credential.
    return {
        ...rest,
        _meta: {
            ...metaWithoutVouch,
            vouch: {
                v: '1.0',
                contentHash,
                credential,
            } satisfies VouchMetaBlock,
        },
    };
}

// ---------------------------------------------------------------------------
// Wrap an MCP tool handler
// ---------------------------------------------------------------------------

export type McpToolHandler<TArgs = unknown> = (args: TArgs) => Promise<McpResponse>;
export type IntentBuilder<TArgs = unknown> = (args: TArgs, response: McpResponse) => ResponseIntent;

/**
 * Wrap an MCP tool handler so every successful response is signed with
 * a Vouch credential.
 *
 * The `intentBuilder` callback computes the intent from the call args
 * and the produced response (so e.g. you can include the tool name and
 * the resource path in `intent.target` / `intent.resource`). Errors
 * propagate unchanged; the wrapper signs only successful responses.
 */
export function mcpSignedHandler<TArgs>(
    handler: McpToolHandler<TArgs>,
    signer: Signer,
    intentBuilder: IntentBuilder<TArgs>,
    options: SignMcpResponseOptions = {},
): McpToolHandler<TArgs> {
    return async (args: TArgs): Promise<McpResponse> => {
        const response = await handler(args);
        const intent = intentBuilder(args, response);
        return signMcpResponse(response, signer, intent, options);
    };
}

// ---------------------------------------------------------------------------
// Verify a signed response
// ---------------------------------------------------------------------------

export interface VerifyMcpResponseResult {
    ok: boolean;
    reason?: string;
    /** The Vouch credential extracted from `_meta.vouch.credential`. */
    credential?: VouchCredential;
}

/**
 * Verify a Vouch-signed MCP response. Confirms (a) `_meta.vouch` is
 * present, (b) the embedded `contentHash` matches the recomputed hash
 * of the response body, (c) the credential's `intent.contentHash`
 * matches both, and (d) the credential's Data Integrity proof verifies.
 *
 * The fourth check requires a verifier; this function performs (a)-(c)
 * inline and delegates (d) to the caller-supplied `verifyCredential`
 * function. The Vouch SDK's verifier module provides one.
 */
export async function verifyMcpResponse(
    response: McpResponse,
    verifyCredential: (credential: VouchCredential) => Promise<boolean>,
): Promise<VerifyMcpResponseResult> {
    const block = response._meta?.vouch;
    if (!block) return { ok: false, reason: 'no _meta.vouch block' };

    // (b) recompute contentHash from the response body.
    const { _meta = {}, ...rest } = response;
    const { vouch: _drop, ...metaWithoutVouch } = (_meta as Record<string, unknown>) ?? {};
    const sanitised: Record<string, unknown> = { ...rest };
    if (Object.keys(metaWithoutVouch).length > 0) {
        sanitised._meta = metaWithoutVouch;
    }
    const canonicalBytes = canonicalize(sanitised);
    const computedHash = await sha256Hex(canonicalBytes);
    if (computedHash !== block.contentHash) {
        return { ok: false, reason: 'contentHash mismatch (response body tampered)' };
    }

    // (c) confirm the credential's intent.contentHash matches.
    const intent = block.credential.credentialSubject?.intent as Record<string, unknown> | undefined;
    const intentHash = intent?.contentHash;
    if (typeof intentHash !== 'string' || !intentHash.endsWith(computedHash)) {
        return {
            ok: false,
            reason: 'credential intent.contentHash does not match response body',
        };
    }

    // (d) delegate Data Integrity verification.
    const proofOk = await verifyCredential(block.credential);
    return proofOk
        ? { ok: true, credential: block.credential }
        : { ok: false, reason: 'credential Data Integrity proof failed to verify' };
}
