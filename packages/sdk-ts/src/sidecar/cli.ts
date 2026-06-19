#!/usr/bin/env node
/**
 * CLI entry point for the TypeScript Vouch sidecar.
 *
 * Mirrors the Go sidecar's developer ergonomics: a required `--did`, an
 * optional `--port` (default 8877), and an Ed25519 seed loaded from the
 * `VOUCH_ED25519_SEED` environment variable (base64 or hex, 32 bytes). When
 * no seed is supplied an ephemeral one is generated and a warning is printed
 * to stderr, matching the Go sidecar's development behavior.
 *
 *   vouch-sidecar-ts --did did:web:agent.example.com --port 8877
 */

import { webcrypto } from 'node:crypto';

import { createSidecarServer } from './server';

interface CliArgs {
  did: string;
  port: number;
}

function parseArgs(argv: string[]): CliArgs {
  let did = '';
  let port = 8877;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--did') {
      did = argv[++i] ?? '';
    } else if (arg === '--port') {
      const raw = argv[++i] ?? '';
      const parsed = Number.parseInt(raw, 10);
      if (Number.isNaN(parsed)) {
        process.stderr.write(`error: invalid --port value: ${raw}\n`);
        process.exit(1);
      }
      port = parsed;
    }
  }

  if (did === '') {
    process.stderr.write('error: --did is required\n');
    process.exit(1);
  }

  return { did, port };
}

/** Decode a 32-byte Ed25519 seed from a base64 or hex string. */
function decodeSeed(raw: string): Uint8Array {
  const trimmed = raw.trim();

  // Hex: exactly 64 hex chars.
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return new Uint8Array(Buffer.from(trimmed, 'hex'));
  }

  // Otherwise treat as base64 (standard or url-safe).
  const seed = new Uint8Array(Buffer.from(trimmed, 'base64'));
  if (seed.length !== 32) {
    throw new Error(
      `VOUCH_ED25519_SEED must decode to 32 bytes (base64 or hex), got ${seed.length}`
    );
  }
  return seed;
}

function loadSeed(): Uint8Array {
  const fromEnv = process.env.VOUCH_ED25519_SEED;
  if (fromEnv && fromEnv.trim() !== '') {
    return decodeSeed(fromEnv);
  }
  process.stderr.write(
    'warning: no VOUCH_ED25519_SEED set, generating ephemeral keys\n'
  );
  const seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);
  return seed;
}

function main(): void {
  const { did, port } = parseArgs(process.argv.slice(2));
  const seed = loadSeed();

  const server = createSidecarServer({ did, seed });
  server.listen(port, () => {
    process.stdout.write(`vouch-sidecar-ts listening on :${port}\n`);
  });
}

main();
