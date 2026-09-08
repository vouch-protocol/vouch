/**
 * Vouch-protected MCP servers: change one import, every tool checks first.
 *
 * `McpServer` is a drop-in replacement for the MCP SDK's `McpServer` in which
 * every registered tool is protected by default:
 *
 * ```ts
 * import { McpServer } from '@vouch-protocol-official/mcp';
 * // was: import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
 *
 * const server = new McpServer({ name: 'files', version: '1.0.0' });
 *
 * server.registerTool(
 *   'read_file',
 *   { inputSchema: { path: z.string() }, resource: (args) => args.path as string },
 *   async ({ path }) => ({ content: [{ type: 'text', text: read(path) }] }),
 * );
 * ```
 *
 * A protected tool gains a required `credential` argument. Before its body
 * runs, the credential is verified, checked against the trusted issuer list,
 * confirmed to authorise *this exact call*, and put to Shield. Any failure
 * refuses and the body never runs.
 *
 * Configuration comes from the environment and is required: `VOUCH_RULES`,
 * `VOUCH_TRUSTED_ISSUERS`, and optionally `VOUCH_TARGET` (default: the server
 * name). A server missing what it needs refuses to start. It never starts
 * unprotected.
 *
 * This is the receiving side. The signing side lives in the Vouch Protocol SDK.
 */

import { McpServer as BaseMcpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import {
  CREDENTIAL_ARG,
  type GuardConfig,
  type GuardOptions,
  type Refusal,
  ToolGuard,
  VouchMcpConfigError,
  computeResource,
  guardConfigFrom,
  loadRulesFromFile,
  refusalPayload,
} from './guard.js';

export {
  CREDENTIAL_ARG,
  ToolGuard,
  VouchMcpConfigError,
  computeResource,
  guardConfigFrom,
  loadRulesFromFile,
};
export type { GuardConfig, GuardOptions, Refusal };

/** Thrown when a call is refused. Carries the structured reason. */
export class VouchRefusedError extends Error {
  readonly refusal: Refusal;

  constructor(refusal: Refusal) {
    super(JSON.stringify(refusalPayload(refusal)));
    this.name = 'VouchRefusedError';
    this.refusal = refusal;
  }
}

/** Extra options a Vouch-protected tool accepts, on top of the SDK's config. */
export interface VouchToolOptions {
  /**
   * Skip protection entirely. Logs a warning at registration and on every call,
   * because an unprotected tool on a protected server is a decision someone
   * should be able to see in the logs.
   */
  unprotected?: boolean;
  /**
   * Map the argument object to the resource string. Without it the resource is
   * the JCS canonicalisation of all arguments, so a credential authorises
   * exactly one call with exactly those arguments. Supplying this is a
   * deliberate loosening, and a policy decision the tool author is making.
   */
  resource?: (args: Record<string, unknown>) => string;
}

/** The config object a Vouch-protected tool takes: the SDK's, plus ours. */
export type VouchToolConfig<InputArgs> = VouchToolOptions & {
  title?: string;
  description?: string;
  inputSchema?: InputArgs;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  outputSchema?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  annotations?: any;
  _meta?: Record<string, unknown>;
};

export interface VouchServerOptions extends GuardOptions {
  /** A preconfigured guard, mainly for tests. */
  guard?: ToolGuard;
}

/**
 * An MCP server whose tools are protected by default.
 *
 * A thin subclass. The constructor takes everything the SDK's `McpServer`
 * takes; `registerTool` and `tool` take everything theirs take plus
 * `unprotected` and `resource`. Registration, schema generation, and dispatch
 * all stay with the SDK.
 */
export class McpServer extends BaseMcpServer {
  readonly vouchGuard: ToolGuard;

  constructor(serverInfo: ConstructorParameters<typeof BaseMcpServer>[0], options: VouchServerOptions = {}, ...rest: unknown[]) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    super(serverInfo as any, ...(rest as []));

    const name = (serverInfo as { name?: string })?.name ?? 'mcp';
    this.vouchGuard = options.guard ?? new ToolGuard(guardConfigFrom(name, options));

    // eslint-disable-next-line no-console
    console.error(
      `Vouch: protecting '${name}' (target=${this.vouchGuard.config.target}, ` +
        `rules=${this.vouchGuard.config.rulesPath}, issuers=${this.vouchGuard.config.trustedIssuers.size})`,
    );
  }

  /**
   * Register a tool. Protected unless `unprotected: true` is set in the config.
   *
   * The generics mirror the SDK's own, so a tool body still gets its arguments
   * typed from `inputSchema`. The Vouch options are added to the config object
   * rather than the positional signature, so the call shape is unchanged.
   */
  // The base method is overloaded and generic, so an override that narrows it
  // would not be assignable. The config is documented by VouchToolConfig and
  // the example annotates its callbacks; see the README.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registerTool(name: string, config: VouchToolConfig<any>, cb: any): any {
    const { unprotected, resource, ...sdkConfig } = (config ?? {}) as VouchToolOptions &
      Record<string, unknown>;

    if (unprotected && resource) {
      throw new Error('the resource callback has no meaning on an unprotected tool');
    }

    if (unprotected) {
      // eslint-disable-next-line no-console
      console.error(
        `Vouch: tool '${name}' is registered UNPROTECTED; calls to it are not checked`,
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const warned = async (...callArgs: any[]) => {
        // eslint-disable-next-line no-console
        console.error(`Vouch: UNPROTECTED call to '${name}'`);
        return cb(...callArgs);
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (super.registerTool as any)(name, sdkConfig, warned);
    }

    // Add `credential` to the tool's declared schema so a client that knows
    // nothing about Vouch Protocol fails loudly on a required argument rather
    // than silently omitting it.
    const inputSchema = {
      ...((sdkConfig.inputSchema as Record<string, unknown>) ?? {}),
      [CREDENTIAL_ARG]: z
        .string()
        .describe('A Vouch Credential authorising exactly this call, as JSON.'),
    };

    const guard = this.vouchGuard;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const guarded = async (args: any, extra: any) => {
      const supplied = (args ?? {}) as Record<string, unknown>;
      const refusal = await guard.check(name, supplied, resource);
      if (refusal) throw new VouchRefusedError(refusal);

      const forwarded: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(supplied)) {
        if (key !== CREDENTIAL_ARG) forwarded[key] = value;
      }
      return cb(forwarded, extra);
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (super.registerTool as any)(name, { ...sdkConfig, inputSchema }, guarded);
  }

  /**
   * The SDK's older `tool()` entry point, kept working and protected.
   *
   * The SDK deprecates it in favour of `registerTool`, and its overloads make
   * the argument positions ambiguous, so this normalises the common shapes and
   * hands them to `registerTool`.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool(name: string, ...rest: any[]): any {
    const cb = rest[rest.length - 1];
    const middle = rest.slice(0, -1);

    let description: string | undefined;
    let schemaOrOptions: Record<string, unknown> = {};
    for (const part of middle) {
      if (typeof part === 'string') description = part;
      else if (part && typeof part === 'object') schemaOrOptions = part as Record<string, unknown>;
    }

    const { unprotected, resource, ...maybeSchema } = schemaOrOptions as VouchToolOptions &
      Record<string, unknown>;

    const config: Record<string, unknown> = {};
    if (description) config.description = description;
    if (unprotected !== undefined) config.unprotected = unprotected;
    if (resource !== undefined) config.resource = resource;
    if (Object.keys(maybeSchema).length > 0) config.inputSchema = maybeSchema;

    return this.registerTool(name, config, cb);
  }
}

/**
 * Protect an already-built server's tool dispatch.
 *
 * The secondary API, for a server this package did not construct. Same checks
 * and the same refusals; the difference is that it cannot add a `credential`
 * parameter to a schema it does not own, so the credential is read from the
 * call's arguments if the tool already accepts one.
 *
 * Prefer `McpServer` where you can: a wrapper someone has to remember to apply
 * is a wrapper someone will forget.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function protect<T extends { callTool?: any; name?: string }>(
  server: T,
  options: VouchServerOptions = {},
): T {
  const guard = options.guard ?? new ToolGuard(guardConfigFrom(server.name ?? 'mcp', options));
  const original = server.callTool;
  if (typeof original !== 'function') {
    throw new TypeError(
      `${server.constructor?.name ?? 'server'} has no callTool to wrap; use McpServer instead`,
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (server as any).callTool = async (name: string, args: Record<string, unknown>, ...more: any[]) => {
    const supplied = args ?? {};
    const refusal = await guard.check(name, supplied);
    if (refusal) throw new VouchRefusedError(refusal);
    const forwarded: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(supplied)) {
      if (key !== CREDENTIAL_ARG) forwarded[key] = value;
    }
    return original.call(server, name, forwarded, ...more);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (server as any).vouchGuard = guard;
  return server;
}
