/**
 * The protection behind `McpServer` and `protect`.
 *
 * One place decides whether a tool call may run. Everything else in this
 * package is plumbing that routes calls through here.
 *
 * Faithful port of vouch/mcp/_guard.py. The five steps, in order, all before
 * the tool body:
 *
 * 1. Locate the credential.
 * 2. Verify it (proof, issuer binding, purpose, validity window).
 * 3. Confirm the issuer is trusted.
 * 4. Confirm the credential's intent is *this* call, not a similar one.
 * 5. Ask Shield.
 *
 * Any failure refuses. No exception reaches the tool body, and no partial
 * success lets it run.
 */

import { readFileSync } from 'node:fs';

import {
  RuleSet,
  Verifier,
  canonicalizeToString,
  parseRules,
} from '@vouch-protocol-official/sdk';
import { parse as parseYaml } from 'yaml';

/** The tool argument carrying the credential. */
export const CREDENTIAL_ARG = 'credential';

/** Raised when a protected server is not configured to protect anything. */
export class VouchMcpConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VouchMcpConfigError';
  }
}

/** A structured refusal. Carried on the error a refused call throws. */
export interface Refusal {
  reason: string;
  tool: string;
  detail?: string;
}

export function refusalPayload(refusal: Refusal): Record<string, unknown> {
  const out: Record<string, unknown> = {
    error: 'refused',
    reason: refusal.reason,
    tool: refusal.tool,
  };
  if (refusal.detail) out.detail = refusal.detail;
  return out;
}

/** Configuration for a protected server. Read from the environment. */
export interface GuardConfig {
  rulesPath: string;
  trustedIssuers: Set<string>;
  target: string;
}

export interface GuardOptions {
  rulesPath?: string;
  trustedIssuers?: string[] | string;
  target?: string;
  env?: Record<string, string | undefined>;
}

/** Build configuration from the environment. Throws rather than starting unprotected. */
export function guardConfigFrom(serverName: string, options: GuardOptions = {}): GuardConfig {
  const env = options.env ?? process.env;

  const rulesPath = options.rulesPath ?? env.VOUCH_RULES;
  if (!rulesPath) {
    throw new VouchMcpConfigError(
      'VOUCH_RULES is not set. A Vouch-protected MCP server needs a Shield rules ' +
        'file to know what it may do. Point VOUCH_RULES at one, or pass rulesPath. ' +
        'Refusing to start unprotected.',
    );
  }

  const rawIssuers = options.trustedIssuers ?? env.VOUCH_TRUSTED_ISSUERS ?? '';
  const list = Array.isArray(rawIssuers) ? rawIssuers : rawIssuers.split(',');
  const trustedIssuers = new Set(list.map((d) => d.trim()).filter((d) => d.length > 0));
  if (trustedIssuers.size === 0) {
    throw new VouchMcpConfigError(
      'VOUCH_TRUSTED_ISSUERS is not set. Without it no credential can be accepted, ' +
        'so every call would be refused. Set it to a comma-separated list of DIDs. ' +
        'Refusing to start unprotected.',
    );
  }

  return {
    rulesPath,
    trustedIssuers,
    target: options.target ?? env.VOUCH_TARGET ?? serverName,
  };
}

/**
 * The resource string this call binds to.
 *
 * Default is the JCS canonicalisation of the whole argument object, so a
 * credential authorises exactly one call with exactly these arguments. A tool
 * that opts into `resource` is deliberately loosening that.
 */
export function computeResource(
  args: Record<string, unknown>,
  resourceFn?: (args: Record<string, unknown>) => string,
): string {
  const payload: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (key !== CREDENTIAL_ARG) payload[key] = value;
  }
  if (resourceFn) {
    const value = resourceFn(payload);
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('the resource callback must return a non-empty string');
    }
    return value;
  }
  return canonicalizeToString(payload);
}

/** Decides whether one tool call may run. */
export class ToolGuard {
  readonly config: GuardConfig;
  readonly rules: RuleSet;
  private readonly verifier: Verifier;

  constructor(config: GuardConfig, rules?: RuleSet) {
    this.config = config;
    this.rules = rules ?? loadRulesFromFile(config.rulesPath);
    this.verifier = new Verifier();

    if (!this.rules.ok) {
      // Loud, but still deny-all rather than a crash: a running server that
      // refuses everything is easier to diagnose than one that will not start,
      // and it cannot be mistaken for a permissive one.
      // eslint-disable-next-line no-console
      console.error(
        `Vouch: rules did not load (${this.rules.malformedReason}). Every call will be refused.`,
      );
    }
  }

  /**
   * Return undefined if the call may run, or a Refusal if it may not.
   *
   * Emits exactly one structured decision line, whichever way it goes, so an
   * operator can read the server's behaviour from stderr.
   */
  async check(
    toolName: string,
    args: Record<string, unknown>,
    resourceFn?: (args: Record<string, unknown>) => string,
  ): Promise<Refusal | undefined> {
    const { refusal, did, resource } = await this.decide(toolName, args, resourceFn);
    const verdict = refusal ? 'DENY ' : 'ALLOW';
    const detail = refusal ? `${refusal.reason}${refusal.detail ? ` (${refusal.detail})` : ''}` : '';
    // eslint-disable-next-line no-console
    console.error(`${verdict}  ${did}  ${toolName}  ${resource}  ${detail}`.trimEnd());
    return refusal;
  }

  private async decide(
    toolName: string,
    args: Record<string, unknown>,
    resourceFn?: (args: Record<string, unknown>) => string,
  ): Promise<{ refusal?: Refusal; did: string; resource: string }> {
    let did = '-';
    let resource = '-';
    try {
      resource = computeResource(args, resourceFn);
    } catch {
      resource = '-';
    }

    // 1. Locate and parse the credential.
    const raw = args[CREDENTIAL_ARG];
    if (raw === undefined || raw === null || raw === '') {
      return { refusal: { reason: 'no credential', tool: toolName }, did, resource };
    }
    let credential: Record<string, unknown>;
    if (typeof raw === 'string') {
      try {
        credential = JSON.parse(raw) as Record<string, unknown>;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          refusal: { reason: 'no credential', tool: toolName, detail: `not valid JSON: ${message}` },
          did,
          resource,
        };
      }
    } else if (typeof raw === 'object') {
      credential = raw as Record<string, unknown>;
    } else {
      return {
        refusal: {
          reason: 'no credential',
          tool: toolName,
          detail: 'credential must be a JSON object',
        },
        did,
        resource,
      };
    }

    // 2. Verify it: proof, issuer binding, proof purpose, validity window.
    const result = await this.verifier.checkVouchCredential(credential);
    if (!result.isValid || !result.passport) {
      return {
        refusal: {
          reason: 'credential did not verify',
          tool: toolName,
          detail: result.error ?? 'signature, issuer binding, or validity window failed',
        },
        did,
        resource,
      };
    }
    const passport = result.passport as { issuer?: string; intent?: Record<string, unknown> };
    did = passport.issuer ?? '-';

    // 3. Trusted issuer.
    if (!this.config.trustedIssuers.has(did)) {
      return { refusal: { reason: 'untrusted issuer', tool: toolName, detail: did }, did, resource };
    }

    // 4. The credential must be for *this* call. A credential for
    //    read_file reports/q3.txt must not authorise reports/q4.txt.
    let expectedResource: string;
    try {
      expectedResource = computeResource(args, resourceFn);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        refusal: { reason: 'credential does not match request', tool: toolName, detail: message },
        did,
        resource,
      };
    }

    const intent = passport.intent ?? {};
    if (intent.action !== toolName) {
      return {
        refusal: {
          reason: 'credential does not match request',
          tool: toolName,
          detail: `intent.action is ${JSON.stringify(intent.action)}, called ${JSON.stringify(toolName)}`,
        },
        did,
        resource,
      };
    }
    if (intent.target !== this.config.target) {
      return {
        refusal: {
          reason: 'credential does not match request',
          tool: toolName,
          detail: `intent.target is ${JSON.stringify(intent.target)}, this server is ${JSON.stringify(this.config.target)}`,
        },
        did,
        resource,
      };
    }
    if (intent.resource !== expectedResource) {
      return {
        refusal: {
          reason: 'credential does not match request',
          tool: toolName,
          detail: 'intent.resource does not match these arguments',
        },
        did,
        resource,
      };
    }

    // 5. Shield.
    const decision = this.rules.check(did, toolName, this.config.target, expectedResource);
    if (!decision.allow) {
      return { refusal: { reason: decision.reason, tool: toolName }, did, resource };
    }

    return { did, resource };
  }
}

/** Read a rules file from disk. Node only; a bad file denies everything. */
export function loadRulesFromFile(path: string): RuleSet {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return parseRules('', `rules file could not be read: ${path}: ${message}`);
  }
  return parseRules(text, path, parseYaml);
}
