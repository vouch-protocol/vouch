/**
 * Where a minted identity is saved, so it is not lost when the process exits.
 *
 * A freshly generated identity (DID, private key, public key) lives only in
 * memory until something persists it. This module gives a small, uniform
 * `KeyStore` interface and two backends:
 *
 *   - `MemoryKeyStore`        in-process only (explicitly ephemeral)
 *   - `EncryptedFileKeyStore` encrypted file on disk (~/.vouch/keys), with the
 *                             private key sealed under a password (scrypt +
 *                             ChaCha20-Poly1305)
 *
 * `resolveDefaultStore()` picks the best available backend. The store keeps the
 * private key sealed; it is only returned to a caller on an explicit `load`.
 *
 * (An OS-keyring backend, like the Python KeyringKeyStore, is a follow-up: it
 * needs an optional native dependency.)
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** A stored agent identity. */
export interface StoredIdentity {
  privateKeyJwk: string;
  publicKeyJwk: string;
  did: string;
}

/** A place identities can be saved to and loaded from. */
export interface KeyStore {
  readonly name: string;
  /** Persist an identity. Resolves to a human-readable location string. */
  save(identity: StoredIdentity): Promise<string>;
  /** Load a previously saved identity by DID. */
  load(did: string): Promise<StoredIdentity>;
  /** List the DIDs this store holds. */
  list(): Promise<string[]>;
  /** Remove a stored identity. */
  delete(did: string): Promise<void>;
}

/** In-process store. Explicitly ephemeral: nothing survives the process. */
export class MemoryKeyStore implements KeyStore {
  readonly name = 'memory';
  private items = new Map<string, StoredIdentity>();

  async save(identity: StoredIdentity): Promise<string> {
    if (!identity.did) throw new Error('Cannot store an identity without a DID');
    this.items.set(identity.did, identity);
    return 'memory (not persisted)';
  }

  async load(did: string): Promise<StoredIdentity> {
    const found = this.items.get(did);
    if (!found) throw new Error(`Identity ${did} not in memory store`);
    return found;
  }

  async list(): Promise<string[]> {
    return [...this.items.keys()];
  }

  async delete(did: string): Promise<void> {
    this.items.delete(did);
  }
}

interface SealedFile {
  v: 1;
  did: string;
  publicKeyJwk: string;
  encrypted: boolean;
  privateKeyJwk?: string;
  kdf?: { salt: string; n: number; r: number; p: number };
  cipher?: { algo: string; nonce: string; ciphertext: string; tag: string };
}

/**
 * Encrypted-at-rest file store under ~/.vouch/keys.
 *
 * With a `password`, the private key is sealed with scrypt + ChaCha20-Poly1305.
 * With no password the private key is written in plaintext and a warning is
 * logged; pass a password.
 */
export class EncryptedFileKeyStore implements KeyStore {
  readonly name = 'encrypted-file';
  private readonly keyDir: string;
  private readonly password?: string;

  constructor(opts?: { keyDir?: string; password?: string }) {
    this.keyDir = opts?.keyDir ?? path.join(os.homedir(), '.vouch', 'keys');
    this.password = opts?.password;
  }

  private filename(did: string): string {
    const safe = did.replace(/[^A-Za-z0-9._-]/g, '-').replace(/^\.+|\.+$/g, '');
    if (!safe) throw new Error(`DID does not yield a safe filename: ${did}`);
    const file = path.join(this.keyDir, `${safe}.json`);
    const resolved = path.resolve(file);
    if (path.dirname(resolved) !== path.resolve(this.keyDir)) {
      throw new Error(`unsafe key path for DID ${did}`);
    }
    return file;
  }

  async save(identity: StoredIdentity): Promise<string> {
    if (!identity.did) throw new Error('Cannot store an identity without a DID');
    fs.mkdirSync(this.keyDir, { recursive: true, mode: 0o700 });
    const file = this.filename(identity.did);

    let data: SealedFile;
    if (this.password) {
      const salt = crypto.randomBytes(16);
      const n = 16384;
      const r = 8;
      const p = 1;
      const key = crypto.scryptSync(this.password, salt, 32, { N: n, r, p });
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
        authTagLength: 16,
      });
      const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(identity.privateKeyJwk, 'utf8')),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();
      data = {
        v: 1,
        did: identity.did,
        publicKeyJwk: identity.publicKeyJwk,
        encrypted: true,
        kdf: { salt: salt.toString('base64'), n, r, p },
        cipher: {
          algo: 'chacha20-poly1305',
          nonce: nonce.toString('base64'),
          ciphertext: ciphertext.toString('base64'),
          tag: tag.toString('base64'),
        },
      };
    } else {
      // eslint-disable-next-line no-console
      console.warn(
        `vouch: saving identity ${identity.did} WITHOUT a password; the private ` +
        'key is stored in plaintext. Pass a password to encrypt it.'
      );
      data = {
        v: 1,
        did: identity.did,
        publicKeyJwk: identity.publicKeyJwk,
        encrypted: false,
        privateKeyJwk: identity.privateKeyJwk,
      };
    }

    fs.writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.chmodSync(file, 0o600);
    return `${this.keyDir} (${this.password ? 'encrypted' : 'plaintext'})`;
  }

  async load(did: string): Promise<StoredIdentity> {
    const file = this.filename(did);
    if (!fs.existsSync(file)) throw new Error(`Identity ${did} not found`);
    const data = JSON.parse(fs.readFileSync(file, 'utf8')) as SealedFile;

    let privateKeyJwk: string;
    if (data.encrypted) {
      if (!this.password) throw new Error('Password required to decrypt identity');
      try {
        const kdf = data.kdf!;
        const c = data.cipher!;
        const key = crypto.scryptSync(this.password, Buffer.from(kdf.salt, 'base64'), 32, {
          N: kdf.n,
          r: kdf.r,
          p: kdf.p,
        });
        const decipher = crypto.createDecipheriv(
          'chacha20-poly1305',
          key,
          Buffer.from(c.nonce, 'base64'),
          { authTagLength: 16 }
        );
        decipher.setAuthTag(Buffer.from(c.tag, 'base64'));
        privateKeyJwk = Buffer.concat([
          decipher.update(Buffer.from(c.ciphertext, 'base64')),
          decipher.final(),
        ]).toString('utf8');
      } catch (e) {
        throw new Error('Decryption failed. Invalid password or corrupted file.');
      }
    } else {
      privateKeyJwk = data.privateKeyJwk as string;
    }

    return { privateKeyJwk, publicKeyJwk: data.publicKeyJwk, did: data.did };
  }

  async list(): Promise<string[]> {
    if (!fs.existsSync(this.keyDir)) return [];
    const dids: string[] = [];
    for (const f of fs.readdirSync(this.keyDir)) {
      if (!f.endsWith('.json')) continue;
      try {
        const data = JSON.parse(
          fs.readFileSync(path.join(this.keyDir, f), 'utf8')
        ) as SealedFile;
        if (data.did) dids.push(data.did);
      } catch {
        // skip unreadable files
      }
    }
    return dids;
  }

  async delete(did: string): Promise<void> {
    const file = this.filename(did);
    if (fs.existsSync(file)) fs.rmSync(file);
  }
}

/**
 * Pick the best available store for secure-by-default persistence.
 *
 * Order:
 *   1. `VOUCH_KEYSTORE` = `memory` | `file` (explicit).
 *   2. The encrypted file store, if a password is available (argument or
 *      `VOUCH_KEY_PASSWORD`).
 *   3. `null` (no secure persistence available; the caller should keep the
 *      identity in memory and tell the user).
 */
export function resolveDefaultStore(password?: string): KeyStore | null {
  const choice = (process.env.VOUCH_KEYSTORE ?? '').trim().toLowerCase();
  const pw = password ?? process.env.VOUCH_KEY_PASSWORD;

  if (choice === 'memory') return new MemoryKeyStore();
  if (choice === 'file') return new EncryptedFileKeyStore({ password: pw });

  if (pw) return new EncryptedFileKeyStore({ password: pw });
  return null;
}
