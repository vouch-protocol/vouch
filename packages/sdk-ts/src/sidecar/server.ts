/**
 * Standalone TypeScript Vouch sidecar HTTP server.
 *
 * The TypeScript counterpart to the Go sidecar at
 * `go-sidecar/cmd/vouch-sidecar/main.go`. Signs Vouch Credentials with the
 * `eddsa-jcs-2022` Data Integrity cryptosuite using the raw-seed portable
 * signing primitive, so its output is BYTE-IDENTICAL to the Python, Go, and
 * Rust sidecars for the same inputs.
 *
 * Endpoints:
 *   - POST /sign   : sign a supplied credential as-is, or build one from an
 *                    intent and sign it. Returns the signed credential JSON.
 *   - GET  /health : liveness/identity probe.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { buildProofPortable } from '../data-integrity-portable';
import { buildVouchCredential, type Intent } from '../vc';

const CRYPTOSUITE_LABEL = 'standard (eddsa-jcs-2022)';

export interface SidecarConfig {
  /** Agent DID used as the credential issuer and verification method base. */
  did: string;
  /** 32-byte raw Ed25519 seed used to sign credentials. */
  seed: Uint8Array;
}

interface SignRequestBody {
  intent?: Intent;
  credential?: Record<string, unknown>;
  validSeconds?: number;
  validFrom?: string;
  created?: string;
}

/**
 * Create (but do not start) a Node HTTP server exposing the sidecar API.
 * The caller is responsible for `.listen()` and `.close()`.
 */
export function createSidecarServer(config: SidecarConfig): Server {
  const verificationMethod = config.did + '#key-1';

  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? '/';

    if (url === '/health') {
      if (req.method !== 'GET') {
        return sendError(res, 405, 'method not allowed');
      }
      return sendJson(res, 200, {
        status: 'operational',
        did: config.did,
        mode: CRYPTOSUITE_LABEL,
      });
    }

    if (url === '/sign') {
      if (req.method !== 'POST') {
        return sendError(res, 405, 'method not allowed');
      }
      return readBody(req, (err, raw) => {
        if (err) {
          return sendError(res, 400, 'failed to read request body');
        }
        let body: SignRequestBody;
        try {
          body = raw.length === 0 ? {} : (JSON.parse(raw) as SignRequestBody);
        } catch {
          return sendError(res, 400, 'invalid JSON body');
        }
        try {
          const signed = signCredential(config, verificationMethod, body);
          return sendJson(res, 200, signed);
        } catch (e) {
          return sendError(res, 400, (e as Error).message);
        }
      });
    }

    return sendError(res, 404, 'not found');
  });
}

function signCredential(
  config: SidecarConfig,
  verificationMethod: string,
  body: SignRequestBody
): Record<string, unknown> {
  const created = body.created ? new Date(body.created) : undefined;

  let credential: Record<string, unknown>;
  if (body.credential !== undefined) {
    if (typeof body.credential !== 'object' || body.credential === null) {
      throw new Error('credential must be an object');
    }
    // Sign the supplied credential AS-IS. Do not rebuild it: the interop
    // contract depends on the exact bytes the caller provided.
    credential = body.credential;
  } else if (body.intent !== undefined) {
    credential = buildVouchCredential({
      issuerDid: config.did,
      intent: body.intent,
      validSeconds: body.validSeconds,
      validFrom: body.validFrom ? new Date(body.validFrom) : undefined,
    }) as unknown as Record<string, unknown>;
  } else {
    throw new Error('request must provide either `credential` or `intent`');
  }

  const proof = buildProofPortable(credential, {
    rawPrivateKey: config.seed,
    verificationMethod,
    created,
  });

  return { ...credential, proof };
}

function readBody(
  req: IncomingMessage,
  cb: (err: Error | null, raw: string) => void
): void {
  const chunks: Buffer[] = [];
  let done = false;
  const finish = (err: Error | null, raw: string): void => {
    if (done) return;
    done = true;
    cb(err, raw);
  };
  req.on('data', (chunk: Buffer) => chunks.push(chunk));
  req.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
  req.on('error', (err: Error) => finish(err, ''));
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const out = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(out);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { error: message });
}
