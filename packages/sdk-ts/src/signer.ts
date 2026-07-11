/**
 * Vouch Protocol Signer (TypeScript).
 *
 * Issues Verifiable Credentials with W3C Data Integrity proofs
 * (eddsa-jcs-2022, Specification §3.1) via Signer.sign(). The post-quantum
 * hybrid profile (hybrid-eddsa-mldsa44-jcs-2026) is available via
 * Signer.signHybrid().
 */

import * as crypto from 'crypto';
import * as jose from 'jose';

import { buildProof } from './data-integrity';
import {
  buildHybridProof,
  generateMLDSA44KeyPair,
} from './data-integrity-hybrid';
import {
  decode as decodeMultikey,
  encodeEd25519Public,
  encodeMLDSA44Public,
} from './multikey';
import type {
  SignOptions,
  SignerConfig,
  JWKKey,
} from './types';
import {
  buildVouchCredential,
  type DelegationLink,
  type Intent,
  type VouchCredential,
} from './vc';

const MAX_CHAIN_DEPTH = 5;

/**
 * Signer for creating Vouch credentials (modern) or Vouch-Tokens (legacy).
 *
 * @example
 * ```typescript
 * const signer = new Signer({ privateKey: privateKeyJwk, did });
 *
 * // Legacy JWS path (unchanged):
 * const token = await signer.sign({ action: 'read_database' });
 *
 * // Modern VC + Data Integrity:
 * const cred = await signer.sign({
 *  intent: {
 *   action: 'read_database',
 *   target: 'users_table',
 *   resource: 'https://api.example.com/v1/users',
 *  },
 * });
 * ```
 */
export class Signer {
  private did: string;
  private defaultExpiry: number;
  private keyPromise!: Promise<jose.KeyLike | Uint8Array>;
  private rawPrivateKeyPromise!: Promise<crypto.KeyObject>;
  private rawPublicKeyBytesPromise!: Promise<Uint8Array>;

  // Set for a backend Signer (fromBackend): the private key lives outside this
  // process and this callback produces the signature over the digest.
  private signFunc?: (digest: Uint8Array) => Uint8Array;
  private backendPublicKeyJwk?: string;
  private backendPublicMultikey?: string;

  // Lazily-generated ML-DSA-44 keypair for the hybrid post-quantum profile
  // (Specification §13.2). Independent of any other PQ key the caller may
  // have configured for legacy paths.
  private mldsa44SecretKey?: Uint8Array;
  private mldsa44PublicKey?: Uint8Array;

  constructor(config: SignerConfig) {
    if (!config.privateKey) {
      throw new Error('privateKey is required');
    }
    if (!config.did) {
      throw new Error('did is required');
    }

    this.did = config.did;
    this.defaultExpiry = config.defaultExpirySeconds ?? 300;

    const jwk =
      typeof config.privateKey === 'string'
        ? (JSON.parse(config.privateKey) as JWKKey)
        : (config.privateKey as JWKKey);

    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
      throw new Error('Key must be Ed25519 (OKP with crv Ed25519)');
    }

    // Legacy JWS path (jose KeyLike).
    this.keyPromise = jose.importJWK(jwk as jose.JWK, 'EdDSA');

    // Modern Data Integrity path. Use Node's KeyObject for raw Ed25519
    // signing of SHA-256 digests.
    const rawPriv = crypto.createPrivateKey({
      key: jwk as crypto.JsonWebKey,
      format: 'jwk',
    });
    this.rawPrivateKeyPromise = Promise.resolve(rawPriv);

    // Public-key raw bytes for Multikey export.
    this.rawPublicKeyBytesPromise = (async () => {
      if (jwk.x) {
        return base64UrlDecode(jwk.x);
      }
      // Fallback: derive from the already-built private key.
      const pub = crypto.createPublicKey(rawPriv);
      const pubJwk = pub.export({ format: 'jwk' }) as JWKKey;
      if (!pubJwk.x) {
        throw new Error(
          'Cannot derive Ed25519 public key bytes from private key'
        );
      }
      return base64UrlDecode(pubJwk.x);
    })();
  }

  /**
   * Build a Signer from a generated identity (the result of generateIdentity),
   * so you do not have to unpack privateKeyJwk and did by hand.
   */
  static fromKeypair(
    keypair: { privateKeyJwk: string; did: string | null },
    opts?: { defaultExpirySeconds?: number }
  ): Signer {
    if (!keypair.did) {
      throw new Error(
        'Signer.fromKeypair requires a keypair with a DID; generate it with a ' +
        "domain, e.g. generateIdentity('agent.example')"
      );
    }
    return new Signer({
      privateKey: keypair.privateKeyJwk,
      did: keypair.did,
      defaultExpirySeconds: opts?.defaultExpirySeconds,
    });
  }

  /**
   * Build a Signer whose Ed25519 private key lives outside this process.
   *
   * Instead of a private JWK you supply the agent's public key and a callback
   * `sign(digest) -> signature` that produces the Ed25519 signature over the
   * digest. The raw key never enters this process, so it can live in an OS
   * secure element, a sidecar, a cloud KMS/HSM, or an MPC quorum. This Signer
   * issues Data Integrity credentials; the legacy JWS sign() and the hybrid
   * profile, which need the raw key, are not available.
   *
   * @param did The agent's DID.
   * @param publicKey The agent's public key as a JWK JSON string or a Multikey
   *          (z-prefixed) string.
   * @param sign Callback that signs the 32-byte digest, returns the 64-byte
   *        Ed25519 signature.
   */
  static fromBackend(
    did: string,
    publicKey: string,
    sign: (digest: Uint8Array) => Uint8Array,
    opts?: { defaultExpirySeconds?: number }
  ): Signer {
    if (!did) throw new Error('Signer.fromBackend requires a did');
    if (!publicKey) throw new Error('Signer.fromBackend requires the public key');
    if (typeof sign !== 'function') {
      throw new Error('Signer.fromBackend requires a sign callback');
    }
    const s: Signer = Object.create(Signer.prototype);
    s.initBackend(did, publicKey, sign, opts?.defaultExpirySeconds ?? 300);
    return s;
  }

  private initBackend(
    did: string,
    publicKey: string,
    sign: (digest: Uint8Array) => Uint8Array,
    defaultExpiry: number
  ): void {
    this.did = did;
    this.defaultExpiry = defaultExpiry;
    this.signFunc = sign;
    const { jwk, multikey } = normalizePublicKey(publicKey);
    this.backendPublicKeyJwk = jwk;
    this.backendPublicMultikey = multikey;
  }

  /**
   * Get the DID associated with this signer.
   */
  getDid(): string {
    return this.did;
  }

  /**
   * Canonical verification method ID for this signer (Specification §5.5).
   */
  verificationMethodId(): string {
    return `${this.did}#key-1`;
  }

  /**
   * Public key in Multikey format (z-prefixed base58btc, with the
   * Ed25519 multicodec prefix). Used in modern DID Documents per
   * Specification §4.3.
   */
  async getPublicKeyMultikey(): Promise<string> {
    if (this.backendPublicMultikey) return this.backendPublicMultikey;
    const raw = await this.rawPublicKeyBytesPromise;
    return encodeEd25519Public(raw);
  }

  /**
   * Attach an eddsa-jcs-2022 Data Integrity proof to a pre-built credential.
   *
   * For custom credential types (for example robotics credentials) that the
   * caller assembles by hand rather than from an intent. Mirrors the signing
   * step of `sign`. Returns the credential with its `proof` set.
   */
  async attachProof(
    credential: Record<string, unknown>,
    opts?: { created?: Date }
  ): Promise<Record<string, unknown>> {
    const signOpts = await this.proofSignOptions();
    const proof = buildProof(credential, {
      ...signOpts,
      created: opts?.created,
    });
    return { ...credential, proof };
  }

  /**
   * Attach a hybrid-eddsa-mldsa44-jcs-2026 Data Integrity proof to a pre-built
   * credential. The hybrid counterpart to `attachProof`, for custom credential
   * types the caller assembles by hand. Lazily generates the ML-DSA-44 keypair.
   */
  async attachProofHybrid(
    credential: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    this.ensureMldsa44KeyPair();
    const ed25519PrivateKey = await this.rawPrivateKeyPromise;
    const proof = buildHybridProof(credential, {
      ed25519PrivateKey,
      mldsa44SecretKey: this.mldsa44SecretKey!,
      verificationMethod: this.verificationMethodId(),
    });
    return { ...credential, proof };
  }

  /**
   * Get the public key in JWK format (for DID Documents).
   */
  async getPublicKeyJwk(): Promise<string> {
    if (this.backendPublicKeyJwk) return this.backendPublicKeyJwk;
    const key = await this.keyPromise;
    const publicJwk = await jose.exportJWK(key);
    delete (publicJwk as { d?: string }).d;
    return JSON.stringify(publicJwk);
  }

  // ------------------------------------------------------------------
  // Modern path: VC + Data Integrity (eddsa-jcs-2022).
  // ------------------------------------------------------------------

  /**
   * Issue a Verifiable Credential with a Data Integrity proof.
   *
   * Implements the v1.0 issuance path per Specification §5 and §7.1.
   * Returns a credential dict that can be JSON-serialized and transmitted
   * in an HTTP body or header.
   */
  async sign(opts: SignOptions): Promise<VouchCredential> {
    const intent = mergeIntent(opts);
    let chain: DelegationLink[] | undefined = opts.delegationChain;
    if (opts.parentCredential) {
      chain = this.extendDelegationChainFromParent(opts.parentCredential, intent);
    }

    const credential = buildVouchCredential({
      issuerDid: this.did,
      intent,
      validSeconds: opts.validSeconds ?? this.defaultExpiry,
      reputationScore: opts.reputationScore,
      delegationChain: chain,
      credentialId: opts.credentialId,
      validFrom: opts.validFrom,
    });

    const proof = buildProof(
      credential as unknown as Record<string, unknown>,
      await this.proofSignOptions()
    );
    credential.proof = proof;
    return credential;
  }

  /**
   * Build the signing options for buildProof: the raw key if this Signer holds
   * it, otherwise the backend sign callback.
   */
  private async proofSignOptions(): Promise<{
    privateKey?: crypto.KeyObject;
    sign?: (digest: Uint8Array) => Uint8Array;
    verificationMethod: string;
  }> {
    if (this.signFunc) {
      return { sign: this.signFunc, verificationMethod: this.verificationMethodId() };
    }
    const privateKey = await this.rawPrivateKeyPromise;
    return { privateKey, verificationMethod: this.verificationMethodId() };
  }

  /**
   * JSON-serialized form of `sign` for HTTP transport.
   */
  async signJson(opts: SignOptions): Promise<string> {
    const cred = await this.sign(opts);
    return JSON.stringify(cred);
  }

  /**
   * Issue a Vouch Credential under the hybrid post-quantum profile
   * (Specification §13.2). The credential carries a
   * hybrid-eddsa-mldsa44-jcs-2026 Data Integrity proof containing both
   * an Ed25519 signature and an ML-DSA-44 signature over the same
   * canonical form. Verification REQUIRES both signatures to validate.
   *
   * Note: this profile produces credentials roughly 2.5 KB larger than
   * the eddsa-jcs-2022 default. Callers using this profile SHOULD
   * transmit credentials in the HTTP request body.
   */
  async signHybrid(opts: SignOptions): Promise<VouchCredential> {
    if (this.signFunc) {
      throw new Error(
        'signHybrid is not supported for a backend Signer (fromBackend); ' +
        'use the eddsa-jcs-2022 path or hold the key locally'
      );
    }
    const intent = mergeIntent(opts);
    let chain: DelegationLink[] | undefined = opts.delegationChain;
    if (opts.parentCredential) {
      chain = this.extendDelegationChainFromParent(opts.parentCredential, intent);
    }

    const credential = buildVouchCredential({
      issuerDid: this.did,
      intent,
      validSeconds: opts.validSeconds ?? this.defaultExpiry,
      reputationScore: opts.reputationScore,
      delegationChain: chain,
      credentialId: opts.credentialId,
      validFrom: opts.validFrom,
    });

    this.ensureMldsa44KeyPair();
    const ed25519PrivateKey = await this.rawPrivateKeyPromise;
    const proof = buildHybridProof(
      credential as unknown as Record<string, unknown>,
      {
        ed25519PrivateKey,
        mldsa44SecretKey: this.mldsa44SecretKey!,
        verificationMethod: this.verificationMethodId(),
      }
    );
    credential.proof = proof;
    return credential;
  }

  /**
   * Return the ML-DSA-44 public key bytes (1312 bytes). Used by callers
   * that want to publish a second Multikey verification method in the
   * DID Document for hybrid verification.
   */
  publicKeyMLDSA44(): Uint8Array {
    this.ensureMldsa44KeyPair();
    return this.mldsa44PublicKey!;
  }

  /**
   * ML-DSA-44 public key encoded as a Multikey string
   * (z-prefixed base58btc, with the ML-DSA-44 multicodec prefix).
   */
  publicKeyMLDSA44Multikey(): string {
    return encodeMLDSA44Public(this.publicKeyMLDSA44());
  }

  private ensureMldsa44KeyPair(): void {
    if (this.mldsa44SecretKey && this.mldsa44PublicKey) return;
    const kp = generateMLDSA44KeyPair();
    this.mldsa44SecretKey = kp.secretKey;
    this.mldsa44PublicKey = kp.publicKey;
  }

  /**
   * Build a delegation link from `parentCredential` to this signer.
   *
   * Implements Specification §9.2 link structure. Validates depth limit
   * (§9.4) and resource-narrowing (§9.3 step 5).
   */
  private extendDelegationChainFromParent(
    parentCredential: VouchCredential,
    currentIntent: Intent
  ): DelegationLink[] {
    const parentSubject = parentCredential.credentialSubject;
    const parentIntent = parentSubject.intent;
    const parentChain: DelegationLink[] = parentSubject.delegationChain ?? [];

    if (parentChain.length >= MAX_CHAIN_DEPTH) {
      throw new Error(
        `Delegation chain exceeds max depth of ${MAX_CHAIN_DEPTH}`
      );
    }

    const parentResource = parentIntent.resource ?? '';
    const childResource = currentIntent.resource ?? '';
    if (
      parentResource &&
      childResource &&
      !isSubResource(childResource, parentResource)
    ) {
      throw new Error(
        'Delegation violates resource-narrowing rule: child resource ' +
        `${JSON.stringify(childResource)} is not a sub-resource of parent ` +
        `${JSON.stringify(parentResource)}`
      );
    }

    const parentProof = (parentCredential as { proof?: { proofValue?: string } }).proof;
    const newLink: DelegationLink = {
      issuer: parentCredential.issuer,
      subject: this.did,
      intent: currentIntent,
      validFrom: parentCredential.validFrom,
      validUntil: parentCredential.validUntil,
      parentProofValue: parentProof?.proofValue?.slice(0, 64),
    };

    return [...parentChain, newLink];
  }
}

/**
 * Generate a new Ed25519 keypair for Vouch signing.
 *
 * @param domain - Optional domain for did:web generation
 * @returns Object containing privateKey, publicKey, and optional did
 */
export async function generateIdentity(domain?: string): Promise<{
  privateKeyJwk: string;
  publicKeyJwk: string;
  publicKeyMultikey: string;
  did: string | null;
}> {
  const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA', {
    crv: 'Ed25519',
  });

  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);

  const xRaw = base64UrlDecode(publicJwk.x as string);

  return {
    privateKeyJwk: JSON.stringify(privateJwk),
    publicKeyJwk: JSON.stringify(publicJwk),
    publicKeyMultikey: encodeEd25519Public(xRaw),
    did: domain ? `did:web:${domain}` : null,
  };
}

/**
 * Sign an intent as a Vouch Credential in one line, no Signer to construct.
 *
 * The sending-side counterpart to {@link verify}:
 * ```typescript
 * const keys = await generateIdentity('agent.example');
 * const signed = await sign(keys, {
 *   action: 'read', target: 'did:web:files', resource: 'https://files/x',
 * });
 * ```
 */
export async function sign(
  keypair: { privateKeyJwk: string; did: string | null },
  opts: SignOptions
): Promise<VouchCredential> {
  return Signer.fromKeypair(keypair).sign(opts);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Combine a dict intent with the named action/target/resource shortcuts. */
function mergeIntent(opts: SignOptions): Intent {
  const merged: Record<string, unknown> = { ...(opts.intent ?? {}) };
  if (opts.action !== undefined) merged.action = opts.action;
  if (opts.target !== undefined) merged.target = opts.target;
  if (opts.resource !== undefined) merged.resource = opts.resource;
  return merged as Intent;
}

/** Accept a JWK JSON string or a Multikey (z...) string, return both forms. */
function normalizePublicKey(publicKey: string): { jwk: string; multikey: string } {
  if (publicKey.startsWith('z')) {
    const { algorithm, rawKey } = decodeMultikey(publicKey);
    if (algorithm !== 'Ed25519') {
      throw new Error(`Expected an Ed25519 public key, got ${algorithm}`);
    }
    const jwk = JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64UrlEncode(rawKey),
    });
    return { jwk, multikey: publicKey };
  }
  const parsed = JSON.parse(publicKey) as JWKKey;
  if (parsed.kty !== 'OKP' || parsed.crv !== 'Ed25519' || !parsed.x) {
    throw new Error('Public key JWK must be an Ed25519 key (OKP, crv Ed25519)');
  }
  const raw = base64UrlDecode(parsed.x);
  return { jwk: publicKey, multikey: encodeEd25519Public(raw) };
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(s.length + ((4 - (s.length % 4)) % 4), '=');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function isSubResource(child: string, parent: string): boolean {
  if (child === parent) return true;
  const trimmed = parent.replace(/\/+$/, '');
  return child.startsWith(trimmed + '/');
}
