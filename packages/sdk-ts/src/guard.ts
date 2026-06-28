/**
 * One-line verification guards for tool servers (MCP and other frameworks).
 *
 * On the sending side, `sign` / the Agent make an agent sign every tool call.
 * On the receiving side, a tool server has to verify those credentials before
 * it runs anything. This module covers in-process tool handlers:
 *
 * ```typescript
 * const writeFile = requireSigned(
 *   async (args) => `wrote ${args.path}`,
 *   { trustedDids: ['did:key:z6Mk...'] }
 * );
 * await writeFile({ path: '/x', vouchCredential: signed });
 *
 * const server = guardMcp(server, { trustedDids: ['did:web:agent.example'] });
 * ```
 *
 * Handlers take a single args object; the credential arrives on it under the
 * `vouchCredential` field (configurable). The guard verifies the Data Integrity
 * proof, enforces the issuer allowlist (`trustedDids`), and optionally matches
 * the intent, before the handler runs.
 *
 * Security boundary: the guard authenticates the caller and, when configured,
 * the declared intent. It does NOT by itself bind the credential to the other
 * argument values, and it does NOT provide replay protection; pair it with
 * intent policy and a nonce check when those matter.
 */

import * as crypto from 'crypto';

import type { CredentialVerificationResult } from './types';
import type { VouchCredential } from './vc';
import { Verifier, verify } from './verifier';

export const DEFAULT_CREDENTIAL_ARG = 'vouchCredential';

export interface RequireSignedOptions {
  /** Allowed issuer DIDs. Omit to allow any issuer whose key verifies. */
  trustedDids?: string[];
  /** Verify offline against this key. */
  publicKey?: crypto.KeyObject | string | Record<string, unknown>;
  /** Offline allowlist of issuer DID to public key. */
  trustedKeys?: Record<string, string>;
  /** Exact intent policy. */
  requireAction?: string;
  requireTarget?: string;
  requireResource?: string;
  /** Field the credential arrives under (default "vouchCredential"). */
  credentialArg?: string;
  /** Keep the credential field when calling the handler (default false). */
  passCredential?: boolean;
  /** "throw" (default) raises on reject; "null" returns null. */
  onReject?: 'throw' | 'null';
}

type ArgsObject = Record<string, unknown>;

/**
 * Wrap a tool handler so a valid Vouch credential is required before it runs.
 * The handler takes a single args object; the credential is read from
 * `options.credentialArg` (default "vouchCredential").
 */
export function requireSigned<A extends ArgsObject, R>(
  handler: (args: A) => R | Promise<R>,
  options: RequireSignedOptions = {}
): (args: A) => Promise<R | null> {
  const allow = options.trustedDids ? new Set(options.trustedDids) : null;
  const credentialArg = options.credentialArg ?? DEFAULT_CREDENTIAL_ARG;

  const wrapped = async (args: A): Promise<R | null> => {
    const credential = (args ?? {})[credentialArg] as
      | VouchCredential
      | Record<string, unknown>
      | string
      | undefined;
    const result = await checkCredential(credential, options);

    let reason: string | null = null;
    if (!result.isValid || !result.passport) {
      reason = result.error ?? 'unsigned or invalid credential';
    } else if (allow && !allow.has(result.passport.issuer)) {
      reason = `issuer ${result.passport.issuer} is not in trustedDids`;
    }

    if (reason) {
      if (options.onReject === 'null') return null;
      throw new Error(`Vouch guard rejected the call: ${reason}`);
    }

    let forwarded: A = args;
    if (!options.passCredential && args && credentialArg in args) {
      const copy = { ...(args as ArgsObject) };
      delete copy[credentialArg];
      forwarded = copy as A;
    }
    return handler(forwarded);
  };
  (wrapped as { __vouchGuarded?: boolean }).__vouchGuarded = true;
  return wrapped;
}

/** Wrap a list of tool handlers with {@link requireSigned}. */
export function guardTools<A extends ArgsObject, R>(
  handlers: Array<(args: A) => R | Promise<R>>,
  options: RequireSignedOptions = {}
): Array<(args: A) => Promise<R | null>> {
  return handlers.map((h) =>
    (h as { __vouchGuarded?: boolean }).__vouchGuarded
      ? (h as unknown as (args: A) => Promise<R | null>)
      : requireSigned(h, options)
  );
}

/**
 * Wrap an MCP-style tool server so every tool registered after this call is
 * verified. Patches the server's tool-registration entry point (`tool`,
 * `addTool`, or `registerTool`, each taking the handler as its last function
 * argument). Returns the same server. The credential must reach each handler
 * under the `vouchCredential` field of its args object.
 */
export function guardMcp<S extends object>(server: S, options: RequireSignedOptions = {}): S {
  for (const attr of ['tool', 'addTool', 'registerTool'] as const) {
    const original = (server as Record<string, unknown>)[attr];
    if (typeof original === 'function') {
      if ((original as { __vouchGuardPatched?: boolean }).__vouchGuardPatched) {
        return server;
      }
      const patched = function (this: unknown, ...args: unknown[]): unknown {
        const idx = lastFunctionIndex(args);
        if (idx >= 0) {
          args[idx] = requireSigned(args[idx] as (a: ArgsObject) => unknown, options);
        }
        return (original as (...a: unknown[]) => unknown).apply(this ?? server, args);
      };
      (patched as { __vouchGuardPatched?: boolean }).__vouchGuardPatched = true;
      (server as Record<string, unknown>)[attr] = patched;
      return server;
    }
  }
  throw new TypeError(
    'guardMcp could not find a tool-registration hook (tool/addTool/registerTool) ' +
    'on the server. Use the requireSigned wrapper on each handler instead.'
  );
}

async function checkCredential(
  credential: VouchCredential | Record<string, unknown> | string | undefined,
  options: RequireSignedOptions
): Promise<CredentialVerificationResult> {
  if (!credential) {
    return { isValid: false, passport: null, error: 'missing credential' };
  }

  let result: CredentialVerificationResult;
  if (options.publicKey !== undefined) {
    result = await verify(credential, options.publicKey);
  } else if (options.trustedKeys) {
    const issuer = issuerOf(credential);
    const key = issuer ? options.trustedKeys[issuer] : undefined;
    if (!key) {
      return { isValid: false, passport: null, error: 'issuer not in trustedKeys' };
    }
    result = await Verifier.verifyCredential(credential, key);
  } else {
    result = await verify(credential);
  }

  if (!result.isValid || !result.passport) return result;

  const intent = result.passport.intent ?? {};
  const checks: Array<[string, string | undefined, unknown]> = [
    ['action', options.requireAction, intent.action],
    ['target', options.requireTarget, intent.target],
    ['resource', options.requireResource, intent.resource],
  ];
  for (const [field, expected, actual] of checks) {
    if (expected !== undefined && actual !== expected) {
      return {
        isValid: false,
        passport: null,
        error: `intent.${field} does not match ${expected}`,
      };
    }
  }
  return result;
}

function issuerOf(
  credential: VouchCredential | Record<string, unknown> | string
): string | null {
  try {
    const cred =
      typeof credential === 'string'
        ? (JSON.parse(credential) as Record<string, unknown>)
        : (credential as Record<string, unknown>);
    const issuer = cred.issuer;
    if (Array.isArray(issuer)) return (issuer[0] as string) ?? null;
    return (issuer as string) ?? null;
  } catch {
    return null;
  }
}

function lastFunctionIndex(args: unknown[]): number {
  for (let i = args.length - 1; i >= 0; i--) {
    if (typeof args[i] === 'function') return i;
  }
  return -1;
}
