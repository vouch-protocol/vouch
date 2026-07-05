/**
 * The `Agent` wrapper: one object that holds an identity and signs/verifies.
 *
 * ```typescript
 * const agent = await Agent.create('agent.example');
 * const signed = await agent.sign({
 *   action: 'read', target: 'did:web:files', resource: 'https://files/x',
 * });
 * const { isValid, passport } = await agent.verify(signed);
 * agent.did; agent.publicKeyJwk;
 * ```
 *
 * Construction is via the async `Agent.create` factory (key generation and
 * persistence are async). With a `domain` the identity is `did:web:<domain>`;
 * without one it is a self-certifying `did:key`.
 *
 * Storage is secure by default: a minted identity is persisted to the best
 * available store (or the caller is warned that it is memory-only). The raw
 * private key is not handed back unless `allowKeyExport: true` is set; signing
 * always works through the Agent.
 */

import * as crypto from 'crypto';

import {
  EncryptedFileKeyStore,
  KeyStore,
  resolveDefaultStore,
  StoredIdentity,
} from './keystore';
import { Signer, generateIdentity } from './signer';
import type { CredentialVerificationResult, SignOptions } from './types';
import type { VouchCredential } from './vc';
import { Verifier, verify } from './verifier';

export interface AgentCreateOptions {
  defaultExpirySeconds?: number;
  /** Explicit key store. Omit to auto-resolve; pass null to disable persistence. */
  store?: KeyStore | null;
  /** Persist the minted identity (default true). */
  persist?: boolean;
  /** Password for the default encrypted file store. */
  password?: string;
  /** Allow reading the raw private key back (default false). */
  allowKeyExport?: boolean;
}

export interface AgentVerifyOptions {
  publicKey?: crypto.KeyObject | string | Record<string, unknown>;
  clockSkewSeconds?: number;
}

export class Agent {
  private readonly identity: StoredIdentity;
  private readonly signerInstance: Signer;
  private readonly allowKeyExport: boolean;
  private store?: KeyStore;
  /** Where the identity was persisted, if it was. */
  storedAt?: string;

  private constructor(
    identity: StoredIdentity,
    signer: Signer,
    allowKeyExport: boolean
  ) {
    this.identity = identity;
    this.signerInstance = signer;
    this.allowKeyExport = allowKeyExport;
  }

  /** Mint a fresh identity and (by default) persist it securely. */
  static async create(domain?: string, opts?: AgentCreateOptions): Promise<Agent> {
    const gen = await generateIdentity(domain);
    const did = gen.did ?? `did:key:${gen.publicKeyMultikey}`;
    const identity: StoredIdentity = {
      privateKeyJwk: gen.privateKeyJwk,
      publicKeyJwk: gen.publicKeyJwk,
      did,
    };
    const signer = Signer.fromKeypair(
      { privateKeyJwk: identity.privateKeyJwk, did },
      { defaultExpirySeconds: opts?.defaultExpirySeconds }
    );
    const agent = new Agent(identity, signer, opts?.allowKeyExport ?? false);

    const persist = opts?.persist ?? true;
    const resolved =
      opts?.store !== undefined ? opts.store : persist ? resolveDefaultStore(opts?.password) : null;
    if (persist && resolved) {
      agent.storedAt = await resolved.save(identity);
      agent.store = resolved;
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        `vouch: Agent minted identity ${did} (in memory only, not persisted). ` +
        'It is lost when this process exits; pass a store/password to keep it.'
      );
    }
    return agent;
  }

  /** Rehydrate an Agent from stored keys (no new identity is minted). */
  static load(
    privateKeyJwk: string,
    did: string,
    opts?: {
      publicKeyJwk?: string;
      defaultExpirySeconds?: number;
      allowKeyExport?: boolean;
    }
  ): Agent {
    const publicKeyJwk = opts?.publicKeyJwk ?? publicJwkFromPrivate(privateKeyJwk);
    const identity: StoredIdentity = { privateKeyJwk, publicKeyJwk, did };
    const signer = Signer.fromKeypair(
      { privateKeyJwk, did },
      { defaultExpirySeconds: opts?.defaultExpirySeconds }
    );
    return new Agent(identity, signer, opts?.allowKeyExport ?? true);
  }

  /** Load a previously persisted identity from a store (key stays gated). */
  static async fromStore(
    did: string,
    store: KeyStore,
    opts?: { defaultExpirySeconds?: number; allowKeyExport?: boolean }
  ): Promise<Agent> {
    const identity = await store.load(did);
    const signer = Signer.fromKeypair(
      { privateKeyJwk: identity.privateKeyJwk, did: identity.did },
      { defaultExpirySeconds: opts?.defaultExpirySeconds }
    );
    const agent = new Agent(identity, signer, opts?.allowKeyExport ?? false);
    agent.store = store;
    return agent;
  }

  get did(): string {
    return this.identity.did;
  }

  get publicKeyJwk(): string {
    return this.identity.publicKeyJwk;
  }

  get signer(): Signer {
    return this.signerInstance;
  }

  /** The raw private key. Gated: requires `allowKeyExport: true`. */
  privateKeyJwk(): string {
    this.requireExport('privateKeyJwk');
    return this.identity.privateKeyJwk;
  }

  private requireExport(what: string): void {
    if (!this.allowKeyExport) {
      throw new Error(
        `Access to ${what} is disabled for this Agent. The private key is meant ` +
        'to stay inside the Agent and sign on your behalf. If you really need the ' +
        'raw key, create the Agent with allowKeyExport: true.'
      );
    }
  }

  /** Sign an intent as a Vouch Credential. */
  async sign(opts: SignOptions): Promise<VouchCredential> {
    return this.signerInstance.sign(opts);
  }

  /** Issue a delegation grant from this agent (the principal side). */
  async delegate(opts: {
    action: string;
    target: string;
    resource: string;
    to?: string;
    validSeconds?: number;
    reputationScore?: number;
  }): Promise<VouchCredential> {
    const intent: Record<string, unknown> = {
      action: opts.action,
      target: opts.target,
      resource: opts.resource,
    };
    if (opts.to) intent.delegatee = opts.to;
    return this.signerInstance.sign({
      intent: intent as never,
      validSeconds: opts.validSeconds,
      reputationScore: opts.reputationScore,
    });
  }

  /**
   * Verify a credential. Uses this agent's own key for its own credentials,
   * otherwise resolves by DID (did:key) or uses an explicit key.
   */
  async verify(
    credential: VouchCredential | Record<string, unknown> | string,
    opts?: AgentVerifyOptions
  ): Promise<CredentialVerificationResult> {
    const skew = opts?.clockSkewSeconds ?? 30;
    if (opts?.publicKey === undefined && issuerOf(credential) === this.did) {
      return Verifier.verify(credential, this.identity.publicKeyJwk, skew);
    }
    return verify(credential, opts?.publicKey, { clockSkewSeconds: skew });
  }

  /** Persist this identity and return where it was saved. */
  async save(
    store?: KeyStore,
    opts?: { password?: string; keyDir?: string }
  ): Promise<string> {
    const target =
      store ?? new EncryptedFileKeyStore({ password: opts?.password, keyDir: opts?.keyDir });
    const location = await target.save(this.identity);
    this.store = target;
    this.storedAt = location;
    return location;
  }
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

function publicJwkFromPrivate(privateKeyJwk: string): string {
  const priv = crypto.createPrivateKey({
    key: JSON.parse(privateKeyJwk) as crypto.JsonWebKey,
    format: 'jwk',
  });
  const pub = crypto.createPublicKey(priv);
  const jwk = pub.export({ format: 'jwk' });
  return JSON.stringify(jwk);
}
