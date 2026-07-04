/**
 * Root-identity recovery by Shamir secret sharing (the OSS recovery path).
 *
 * Splits a root's Ed25519 seed into n shares so any threshold reconstruct it and
 * fewer reveal nothing. Hand the shares to guardians or separate locations, and
 * gather a threshold only during a deliberate recovery. This is the recovery and
 * escrow primitive (the seed is reconstructed at recovery time); it is distinct
 * from threshold signing, where the key is never reassembled.
 *
 * Mirrors the Python vouch.recovery module. Textbook Shamir over GF(2^8).
 */

import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic (AES field, reducing polynomial 0x11b)
// ---------------------------------------------------------------------------

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(function initTables() {
  // 3 (not 2) is a primitive element of GF(2^8) under 0x11b, so powers of 3
  // cycle through all 255 non-zero elements. Multiply by 3 = (x*2) XOR x.
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    let x2 = x << 1;
    if (x2 & 0x100) x2 ^= 0x11b;
    x = x2 ^ x;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfInv(a: number): number {
  if (a === 0) throw new Error('no inverse for 0 in GF(2^8)');
  return EXP[255 - LOG[a]];
}

function evalPoly(coeffs: number[], x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfMul(result, x) ^ coeffs[i];
  }
  return result;
}

function interpolateAtZero(points: Array<[number, number]>): number {
  let result = 0;
  for (let i = 0; i < points.length; i++) {
    const [xi, yi] = points[i];
    let num = 1;
    let den = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      const xj = points[j][0];
      num = gfMul(num, xj); // (0 - xj) == xj in GF(2^8)
      den = gfMul(den, xi ^ xj); // (xi - xj) == xi ^ xj
    }
    result ^= gfMul(yi, gfMul(num, gfInv(den)));
  }
  return result;
}

// ---------------------------------------------------------------------------
// Byte-level split / combine
// ---------------------------------------------------------------------------

export interface SplitOptions {
  threshold: number;
  shares: number;
}

/** Split `secret` into `shares` pieces; any `threshold` reconstruct it. */
export function splitSecret(secret: Uint8Array, opts: SplitOptions): Uint8Array[] {
  if (!secret || secret.length === 0) throw new Error('secret must be non-empty bytes');
  const { threshold, shares } = opts;
  if (!(2 <= threshold && threshold <= shares && shares <= 255)) {
    throw new Error('require 2 <= threshold <= shares <= 255');
  }
  const out: number[][] = [];
  for (let x = 1; x <= shares; x++) out.push([x]);
  for (const byte of secret) {
    const coeffs = [byte];
    for (let k = 1; k < threshold; k++) coeffs.push(crypto.randomInt(256));
    for (let i = 0; i < shares; i++) {
      out[i].push(evalPoly(coeffs, i + 1));
    }
  }
  return out.map((s) => Uint8Array.from(s));
}

/** Reconstruct a secret from `threshold` (or more) shares. */
export function combineShares(shares: Uint8Array[]): Uint8Array {
  if (!shares || shares.length < 2) throw new Error('need at least 2 shares');
  const xs: number[] = [];
  const bodies: Uint8Array[] = [];
  for (const s of shares) {
    if (s.length < 2) throw new Error('malformed share');
    xs.push(s[0]);
    bodies.push(s.subarray(1));
  }
  if (new Set(xs).size !== xs.length) throw new Error('shares must have distinct indices');
  const length = bodies[0].length;
  if (bodies.some((b) => b.length !== length)) {
    throw new Error('shares have inconsistent length');
  }
  const secret = new Uint8Array(length);
  for (let j = 0; j < length; j++) {
    const points: Array<[number, number]> = xs.map((x, k) => [x, bodies[k][j]]);
    secret[j] = interpolateAtZero(points);
  }
  return secret;
}

// ---------------------------------------------------------------------------
// Vouch identity recovery
// ---------------------------------------------------------------------------

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function seedFromPrivateJwk(privateKeyJwk: string): Uint8Array {
  const data = JSON.parse(privateKeyJwk) as { kty?: string; crv?: string; d?: string };
  if (data.kty !== 'OKP' || data.crv !== 'Ed25519' || !data.d) {
    throw new Error("expected an Ed25519 private JWK with a 'd' seed");
  }
  return base64UrlDecode(data.d);
}

/** Split a root identity's Ed25519 seed into base64 recovery shares. */
export function splitIdentity(
  keypair: { privateKeyJwk: string } | string,
  opts: SplitOptions
): string[] {
  const privateKeyJwk = typeof keypair === 'string' ? keypair : keypair.privateKeyJwk;
  const seed = seedFromPrivateJwk(privateKeyJwk);
  return splitSecret(seed, opts).map((s) => Buffer.from(s).toString('base64'));
}

export interface RecoveredIdentity {
  privateKeyJwk: string;
  publicKeyJwk: string;
  did: string | null;
}

/** Recover a root identity from `threshold` base64 recovery shares. */
export function recoverIdentity(shares: string[], opts?: { did?: string }): RecoveredIdentity {
  const raw = shares.map((s) => new Uint8Array(Buffer.from(s, 'base64')));
  const seed = combineShares(raw);
  if (seed.length !== 32) {
    throw new Error('recovered seed is not 32 bytes; wrong or too few shares');
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const privJwk = priv.export({ format: 'jwk' });
  const pubJwk = pub.export({ format: 'jwk' });
  return {
    privateKeyJwk: JSON.stringify(privJwk),
    publicKeyJwk: JSON.stringify(pubJwk),
    did: opts?.did ?? null,
  };
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + ((4 - (s.length % 4)) % 4), '=');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}
