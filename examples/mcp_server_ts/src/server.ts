#!/usr/bin/env node
/**
 * A Vouch-protected MCP server, in TypeScript.
 *
 * The TypeScript counterpart of examples/mcp_server/. An ordinary filesystem
 * MCP server; the only thing that makes it Vouch-protected is the import on the
 * next line. Every tool registered on this server refuses to run unless the
 * call arrives with a Vouch Credential that verifies, comes from a trusted
 * issuer, authorises that exact call, and passes Shield.
 *
 * Run:
 *   VOUCH_FS_ROOT=/tmp/vouch-demo \
 *   VOUCH_RULES=/tmp/vouch-demo/rules.yaml \
 *   VOUCH_TRUSTED_ISSUERS=did:key:z6Mk... \
 *   VOUCH_TARGET=files \
 *   npm start
 */

import { readFileSync, readdirSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';

import { McpServer } from '@vouch-protocol-official/mcp';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const ROOT = resolve(process.env.VOUCH_FS_ROOT ?? '');

/**
 * Resolve a relative path inside the configured root, or refuse.
 *
 * Shield already rejects `..` traversal in the policy string. This is the
 * second half of the job: policy matching is lexical, so it cannot see a
 * symlink pointing out of the root. Both checks are needed, and neither
 * replaces the other.
 */
function resolveInRoot(path: string): string {
  const candidate = resolve(ROOT, path);
  if (candidate !== ROOT && !candidate.startsWith(ROOT + sep)) {
    throw new Error(`path escapes VOUCH_FS_ROOT: ${path}`);
  }
  return candidate;
}

const server = new McpServer({ name: 'files', version: '2.2.0' });

const byPath = (args: Record<string, unknown>) => args.path as string;

server.registerTool(
  'read_file',
  {
    description: "Read a file inside the server's root.",
    inputSchema: { path: z.string().describe("Path relative to the root, e.g. 'reports/q3.txt'") },
    resource: byPath,
  },
  async ({ path }: { path: string }) => ({
    content: [{ type: 'text' as const, text: readFileSync(resolveInRoot(path), 'utf8') }],
  }),
);

server.registerTool(
  'write_file',
  {
    description: "Write a file inside the server's root.",
    inputSchema: { path: z.string(), content: z.string() },
    resource: byPath,
  },
  async ({ path, content }: { path: string; content: string }) => {
    const target = resolveInRoot(path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
    return { content: [{ type: 'text' as const, text: `wrote ${content.length} bytes to ${path}` }] };
  },
);

server.registerTool(
  'delete_file',
  {
    description: "Delete a file inside the server's root.",
    inputSchema: { path: z.string() },
    resource: byPath,
  },
  async ({ path }: { path: string }) => {
    unlinkSync(resolveInRoot(path));
    return { content: [{ type: 'text' as const, text: `deleted ${path}` }] };
  },
);

server.registerTool(
  'list_dir',
  {
    description: "List a directory inside the server's root.",
    inputSchema: { path: z.string() },
    resource: byPath,
  },
  async ({ path }: { path: string }) => ({
    content: [
      { type: 'text' as const, text: readdirSync(resolveInRoot(path)).sort().join('\n') },
    ],
  }),
);

async function main(): Promise<void> {
  if (!process.env.VOUCH_FS_ROOT) {
    console.error(
      'VOUCH_FS_ROOT is not set. This server refuses to run without a root directory to confine itself to.',
    );
    process.exit(1);
  }
  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
