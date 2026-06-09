/**
 * vouch-browser.js — minimal browser-side Vouch primitives.
 *
 * Implements the same eddsa-jcs-2022 cryptosuite as the Python and TypeScript
 * reference impls, so credentials produced here verify in those impls too.
 *
 * Wire-compatible pieces:
 *   - jcsCanonicalize(obj)          → Uint8Array (UTF-8 of RFC 8785 canonical form)
 *   - sha256(bytes)                 → Promise<Uint8Array>
 *   - base58btcEncode(bytes)        → string
 *   - base58btcDecode(str)          → Uint8Array
 *   - ed25519PublicMultibase(pub32) → "z..." (Multikey for Ed25519)
 *   - generateKeypair()             → Promise<{ privateKey, publicKey }>  (raw 32B each)
 *   - signCredential(cred, privKey, vmId)   → Promise<signedCredential>
 *   - verifyCredential(cred, pubKey)        → Promise<{ ok, reason }>
 *
 * Depends on @noble/ed25519 v2.x loaded from a CDN; see seller-app.html for the
 * <script type="module"> wiring.
 */

import * as ed from "https://cdn.jsdelivr.net/npm/@noble/ed25519@2.0.0/index.js";

// ----------------------------------------------------------------------------
// JCS — RFC 8785 minimal implementation.
// Handles the subset used by Vouch credentials: object (sorted keys), array,
// string (escapes per JSON), integer/finite float, true/false/null.
// ----------------------------------------------------------------------------

export function jcsCanonicalize(value) {
  return new TextEncoder().encode(jcsEmit(value));
}

function jcsEmit(value) {
  if (value === null || value === undefined) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("JCS: NaN/Infinity not permitted");
    if (Number.isInteger(value)) return String(value);
    // Shortest round-trip via Number.prototype.toString — close enough to
    // ECMA-262 for our credential payloads (which carry no floats anyway).
    return String(value);
  }
  if (typeof value === "string") {
    return jsonString(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(jcsEmit).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map(k => jsonString(k) + ":" + jcsEmit(value[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof value}`);
}

// JSON string serializer matching JCS §3.2.2.2 escapes.
function jsonString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22)      out += '\\"';
    else if (c === 0x5C) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0A) out += "\\n";
    else if (c === 0x0C) out += "\\f";
    else if (c === 0x0D) out += "\\r";
    else if (c < 0x20)   out += "\\u" + c.toString(16).padStart(4, "0");
    else                 out += s[i];
  }
  out += '"';
  return out;
}

// ----------------------------------------------------------------------------
// SHA-256 via WebCrypto.
// ----------------------------------------------------------------------------
export async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

export async function sha256Hex(bytes) {
  const h = await sha256(bytes);
  return Array.from(h).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ----------------------------------------------------------------------------
// Base58btc encode/decode — required for Multikey and proofValue.
// Bitcoin alphabet, no checksum.
// ----------------------------------------------------------------------------
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btcEncode(bytes) {
  if (bytes.length === 0) return "";
  // Count leading zero bytes
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  // Convert to base58
  let digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let result = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    result += B58_ALPHABET[digits[i]];
  }
  return result;
}

export function base58btcDecode(s) {
  if (s.length === 0) return new Uint8Array(0);
  const idx = new Map();
  for (let i = 0; i < 58; i++) idx.set(B58_ALPHABET[i], i);
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  let bytes = [0];
  for (let i = zeros; i < s.length; i++) {
    const v = idx.get(s[i]);
    if (v === undefined) throw new Error(`invalid base58 char: ${s[i]}`);
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const result = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[zeros + i] = bytes[bytes.length - 1 - i];
  }
  return result;
}

// ----------------------------------------------------------------------------
// Multikey (Ed25519): multicodec prefix 0xed 0x01, then 32 raw pubkey bytes,
// then base58btc-encoded with a "z" multibase prefix.
// ----------------------------------------------------------------------------
export function ed25519PublicMultibase(rawPub32) {
  if (rawPub32.length !== 32) throw new Error("Ed25519 pubkey must be 32 bytes");
  const out = new Uint8Array(34);
  out[0] = 0xed;
  out[1] = 0x01;
  out.set(rawPub32, 2);
  return "z" + base58btcEncode(out);
}

export function multibaseDecodeEd25519Pub(multibase) {
  if (!multibase.startsWith("z")) throw new Error("expected z-prefixed multibase");
  const raw = base58btcDecode(multibase.slice(1));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    throw new Error("not an Ed25519 Multikey");
  }
  return raw.slice(2);
}

// ----------------------------------------------------------------------------
// Ed25519 keypair generation. Returns raw 32-byte keys.
// ----------------------------------------------------------------------------
export async function generateKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

// ----------------------------------------------------------------------------
// Sign / verify a Vouch Credential per eddsa-jcs-2022 §3.1.
// ----------------------------------------------------------------------------
export async function signCredential(credential, privateKey, verificationMethod, opts = {}) {
  const created = opts.created || isoNow();

  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created,
    verificationMethod,
    proofPurpose: "assertionMethod",
  };

  const credWithUnsigned = { ...credential, proof };
  const canonical = jcsCanonicalize(credWithUnsigned);
  const digest = await sha256(canonical);

  const signature = await ed.signAsync(digest, privateKey);
  proof.proofValue = "z" + base58btcEncode(signature);

  return { ...credential, proof };
}

export async function verifyCredential(credential, publicKey) {
  const proof = credential.proof;
  if (!proof) return { ok: false, reason: "no proof attached" };
  if (proof.type !== "DataIntegrityProof") return { ok: false, reason: `unexpected proof type: ${proof.type}` };
  if (proof.cryptosuite !== "eddsa-jcs-2022") return { ok: false, reason: `unexpected cryptosuite: ${proof.cryptosuite}` };
  const proofValue = proof.proofValue;
  if (typeof proofValue !== "string" || !proofValue.startsWith("z")) {
    return { ok: false, reason: "missing or malformed proofValue" };
  }

  const signature = base58btcDecode(proofValue.slice(1));

  const proofWithoutValue = { ...proof };
  delete proofWithoutValue.proofValue;
  const credForVerify = { ...credential, proof: proofWithoutValue };

  const canonical = jcsCanonicalize(credForVerify);
  const digest = await sha256(canonical);

  try {
    const ok = await ed.verifyAsync(signature, digest, publicKey);
    return ok ? { ok: true } : { ok: false, reason: "signature did not verify" };
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------
export function isoNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function uuidV4() {
  // crypto.randomUUID() is widely supported; fall back if not.
  if (crypto.randomUUID) return crypto.randomUUID();
  const r = crypto.getRandomValues(new Uint8Array(16));
  r[6] = (r[6] & 0x0f) | 0x40;
  r[8] = (r[8] & 0x3f) | 0x80;
  const hex = Array.from(r).map(b => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i*2, 2), 16);
  return out;
}
