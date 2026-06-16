/**
 * Robot-to-robot trust handshake (Phase 5.4), TypeScript.
 *
 * Mirrors `vouch/robotics/handshake.py`. Two robots in different trust domains
 * authenticate and establish a bounded-trust session via three signed messages
 * (HELLO, ACCEPT, CONFIRM). The session scope is the intersection of what each
 * side offers, never the union, and the responder checks the initiator's domain
 * against its trust policy. Each message is an eddsa-jcs-2022 signed object, so
 * authentication reuses the shared verifier and is interoperable with Python.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';

export const HELLO = 'handshake_hello';
export const ACCEPT = 'handshake_accept';
export const CONFIRM = 'handshake_confirm';

export class HandshakeError extends Error {}

/** A peer is trusted when its did:web domain is allowed, or when open. */
export class TrustPolicy {
  trustedDomains: Set<string>;
  acceptUnknown: boolean;

  constructor(opts: { trustedDomains?: Iterable<string>; acceptUnknown?: boolean } = {}) {
    this.trustedDomains = new Set(opts.trustedDomains ?? []);
    this.acceptUnknown = opts.acceptUnknown ?? false;
  }

  isTrusted(did: string | null | undefined): boolean {
    if (this.acceptUnknown) return true;
    const d = didWebDomain(did ?? '');
    return d !== undefined && this.trustedDomains.has(d);
  }
}

export interface BoundedSession {
  sessionId: string;
  initiator: string;
  responder: string;
  scope: string[];
  nonce: string;
  validUntil?: string;
}

function didWebDomain(did: string): string | undefined {
  if (did.startsWith('did:web:')) return did.slice('did:web:'.length).split(':')[0];
  return undefined;
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function verify(obj: Record<string, unknown>, publicKey: crypto.KeyObject): boolean {
  try {
    return verifyProof(obj, publicKey);
  } catch {
    return false;
  }
}

export interface BuildHelloOptions {
  proposedScope: string[];
  nonce?: string;
  peerDid?: string;
}

/** A: open the handshake with a proposed scope and a fresh nonce. */
export async function buildHello(
  signer: Signer,
  opts: BuildHelloOptions
): Promise<Record<string, unknown>> {
  const hello = {
    type: HELLO,
    from: signer.getDid(),
    to: opts.peerDid ?? null,
    nonce: opts.nonce ?? crypto.randomBytes(16).toString('hex'),
    proposedScope: [...opts.proposedScope],
    issuedAt: iso(new Date()),
  };
  return signer.attachProof(hello);
}

export interface BuildAcceptOptions {
  hello: Record<string, any>;
  helloPublicKey: crypto.KeyObject;
  policy: TrustPolicy;
  offeredScope: string[];
  validSeconds?: number;
  sessionId?: string;
}

/**
 * B: verify A's HELLO and identity domain, intersect the scope, and sign an
 * acceptance. Throws HandshakeError if A is untrusted or the HELLO is invalid.
 */
export async function buildAccept(
  signer: Signer,
  opts: BuildAcceptOptions
): Promise<Record<string, unknown>> {
  const { hello, helloPublicKey, policy, offeredScope } = opts;
  if (hello.type !== HELLO) throw new HandshakeError('not a HELLO message');
  if (!verify(hello, helloPublicKey)) throw new HandshakeError('HELLO signature invalid');
  const initiator = hello.from as string;
  if (!policy.isTrusted(initiator)) {
    throw new HandshakeError(`peer ${initiator} is not in this trust domain's policy`);
  }

  const offered = new Set<string>(offeredScope);
  const bounded = [...new Set((hello.proposedScope ?? []) as string[])]
    .filter((s) => offered.has(s))
    .sort();
  const sid = opts.sessionId ?? `urn:uuid:${crypto.randomUUID()}`;
  const validUntil = iso(new Date(Date.now() + (opts.validSeconds ?? 300) * 1000));

  const accept = {
    type: ACCEPT,
    from: signer.getDid(),
    to: initiator,
    sessionId: sid,
    nonce: hello.nonce,
    boundedScope: bounded,
    validUntil,
  };
  return signer.attachProof(accept);
}

/** A: verify B's ACCEPT, that the nonce echoes, and optionally that B is trusted. */
export function verifyAccept(
  accept: Record<string, any>,
  acceptPublicKey: crypto.KeyObject,
  opts: { expectedNonce: string; policy?: TrustPolicy }
): { ok: boolean; session?: BoundedSession } {
  if (accept.type !== ACCEPT) return { ok: false };
  if (!verify(accept, acceptPublicKey)) return { ok: false };
  if (accept.nonce !== opts.expectedNonce) return { ok: false };
  const responder = accept.from as string;
  if (opts.policy && !opts.policy.isTrusted(responder)) return { ok: false };

  return {
    ok: true,
    session: {
      sessionId: accept.sessionId,
      initiator: accept.to,
      responder,
      scope: [...(accept.boundedScope ?? [])],
      nonce: accept.nonce,
      validUntil: accept.validUntil,
    },
  };
}

/** A: confirm the bounded session to B. */
export async function buildConfirm(
  signer: Signer,
  opts: { session: BoundedSession }
): Promise<Record<string, unknown>> {
  const { session } = opts;
  const confirm = {
    type: CONFIRM,
    from: signer.getDid(),
    to: session.responder,
    sessionId: session.sessionId,
    nonce: session.nonce,
    acceptedScope: [...session.scope],
  };
  return signer.attachProof(confirm);
}

/** B: verify A's CONFIRM closes the agreed session. */
export function verifyConfirm(
  confirm: Record<string, any>,
  confirmPublicKey: crypto.KeyObject,
  opts: { sessionId: string; expectedNonce: string }
): boolean {
  if (confirm.type !== CONFIRM) return false;
  if (!verify(confirm, confirmPublicKey)) return false;
  return confirm.sessionId === opts.sessionId && confirm.nonce === opts.expectedNonce;
}
