/**
 * Multikey encoding for verification methods.
 *
 * Mirrors `vouch/multikey.py`. Per the Controlled Identifiers
 * specification, public keys in DID Documents are encoded as a Multikey:
 *
 *   publicKeyMultibase = base58btc( multicodec_prefix || raw_public_key_bytes )
 *
 * The leading 'z' character indicates base58btc encoding. Cross-implementation
 * interop with the Python module is REQUIRED.
 *
 * Supported algorithms (Specification §13.5):
 *   Ed25519    multicodec prefix 0xed01  (32-byte key)
 *   ML-DSA-44   multicodec prefix 0x1207  (1312-byte key, provisional)
 */

// Multicodec prefixes as 2-byte sequences.
export const ED25519_PUB_PREFIX = new Uint8Array([0xed, 0x01]);
export const ED25519_PRIV_PREFIX = new Uint8Array([0x80, 0x26]);
export const MLDSA44_PUB_PREFIX = new Uint8Array([0x87, 0x24]);
export const MLDSA44_PRIV_PREFIX = new Uint8Array([0x88, 0x24]);

const PREFIX_TABLE: Array<[Uint8Array, string, 'public' | 'private']> = [
  [ED25519_PUB_PREFIX, 'Ed25519', 'public'],
  [ED25519_PRIV_PREFIX, 'Ed25519', 'private'],
  [MLDSA44_PUB_PREFIX, 'ML-DSA-44', 'public'],
  [MLDSA44_PRIV_PREFIX, 'ML-DSA-44', 'private'],
];

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode a 32-byte Ed25519 public key as a Multikey string (z-prefixed
 * base58btc).
 */
export function encodeEd25519Public(rawKey: Uint8Array): string {
  if (rawKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${rawKey.length}`);
  }
  const buf = concat(ED25519_PUB_PREFIX, rawKey);
  return 'z' + b58encode(buf);
}

/**
 * Encode a 1312-byte ML-DSA-44 public key as a Multikey string. Used in
 * the hybrid post-quantum profile (Specification §13.2).
 */
export function encodeMLDSA44Public(rawKey: Uint8Array): string {
  if (rawKey.length !== 1312) {
    throw new Error(`ML-DSA-44 public key must be 1312 bytes, got ${rawKey.length}`);
  }
  const buf = concat(MLDSA44_PUB_PREFIX, rawKey);
  return 'z' + b58encode(buf);
}

/**
 * Decode a Multikey string into algorithm + raw key bytes.
 */
export function decode(multikey: string): { algorithm: string; rawKey: Uint8Array } {
  if (!multikey.startsWith('z')) {
    throw new Error('Multikey must use base58btc encoding (z-prefix)');
  }
  const decoded = b58decode(multikey.slice(1));
  if (decoded.length < 2) throw new Error('Multikey too short');
  const prefix = decoded.slice(0, 2);

  for (const [pat, alg, role] of PREFIX_TABLE) {
    if (prefix[0] === pat[0] && prefix[1] === pat[1]) {
      if (role === 'private') {
        // A verificationMethod must carry a PUBLIC key. Refuse a private-key
        // multicodec prefix so private material is never treated as a key.
        throw new Error('Multikey carries a private-key prefix; a public key is required');
      }
      const rawKey = decoded.slice(2);
      const expected = alg === 'Ed25519' ? 32 : 1312;
      if (rawKey.length !== expected) {
        throw new Error(`${alg} public key must be ${expected} bytes, got ${rawKey.length}`);
      }
      return { algorithm: alg, rawKey };
    }
  }
  throw new Error(
    `Unknown multicodec prefix: ${[...prefix].map(b => b.toString(16).padStart(2, '0')).join('')}`
  );
}

/**
 * Return the algorithm name encoded in a Multikey without exposing raw bytes.
 */
export function algorithmOf(multikey: string): string {
  return decode(multikey).algorithm;
}

// ---------------------------------------------------------------------------
// base58btc primitive (vendored to avoid dependencies)
// ---------------------------------------------------------------------------

export function b58encode(data: Uint8Array): string {
  if (data.length === 0) return '';

  let nZero = 0;
  for (const b of data) {
    if (b === 0) nZero++;
    else break;
  }

  // Convert bytes to a big integer
  let num = 0n;
  for (const b of data) {
    num = (num << 8n) + BigInt(b);
  }

  let encoded = '';
  while (num > 0n) {
    const rem = Number(num % 58n);
    num = num / 58n;
    encoded = B58_ALPHABET[rem] + encoded;
  }

  return '1'.repeat(nZero) + encoded;
}

export function b58decode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array();

  let nZero = 0;
  for (const ch of s) {
    if (ch === '1') nZero++;
    else break;
  }

  let num = 0n;
  for (const ch of s) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base58 character: ${ch}`);
    num = num * 58n + BigInt(idx);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num = num >> 8n;
  }

  const out = new Uint8Array(nZero + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[nZero + i] = bytes[i];
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
