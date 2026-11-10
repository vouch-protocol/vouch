/**
 * Evidence checks of the grader, ported from vouch/grade.py.
 *
 * The post-quantum, revocation and agent-card signals count only evidence that
 * checks out: a well-formed ML-DSA-44 key in assertionMethod, a signed
 * BitstringStatusListCredential issued by the same DID, and an agent card whose
 * vouchCredential verifies against the domain's DID document. The reasons are
 * part of the contract: the shared vectors in test-vectors/grade/ expect the
 * same text from this file and from Python.
 *
 * Every fetch goes through guardedFetchJson: https only, public hosts only
 * (checked over DNS-over-HTTPS), redirects re-checked hop by hop, and size and
 * time limits.
 */

export const MLDSA44_PUBLIC_KEY_LENGTH = 1312;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const MLDSA44_PUB_PREFIX = [0x87, 0x24];
const ED25519_PUB_PREFIX = [0xed, 0x01];
const STATUS_LIST_SERVICE_TYPES = ["BitstringStatusList"];
export const CARD_PATHS = ["/.well-known/agent.json", "/.well-known/agent-card.json"];
const CARD_STATES = ["no", "declared", "verified"];
const EDDSA_CRYPTOSUITE = "eddsa-jcs-2022";

export const DID_DOCUMENT_MAX_BYTES = 1024 * 1024;
export const STATUS_LIST_MAX_BYTES = 1024 * 1024;
export const CARD_MAX_BYTES = 256 * 1024;
const STATUS_LIST_MIN_BITS = 131072;
const STATUS_LIST_MAX_DECODED_BYTES = 16 * 1024 * 1024;
const STATUS_LIST_MAX_SERVICES = 3;

const DID_RE = /did:[a-z0-9]+:[A-Za-z0-9._:%-]+/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const list = (doc, key) => (Array.isArray(doc[key]) ? doc[key] : []);

function types(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string");
  return [];
}

function absolute(ref, did) {
  if (typeof ref !== "string" || !ref) return null;
  return ref.startsWith("#") ? did + ref : ref;
}

const short = (vmId, did) => (vmId.startsWith(did + "#") ? vmId.slice(did.length) : vmId);

function b58decode(s) {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  let num = 0n;
  for (const ch of s) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.push(Number(num % 256n));
    num /= 256n;
  }
  bytes.reverse();
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

function b64urlDecode(value) {
  if (typeof value !== "string" || !B64URL_RE.test(value) || value.length % 4 === 1) return null;
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of value) {
    buffer = (buffer << 6) | B64URL_ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

const startsWith = (bytes, prefix) => prefix.every((b, i) => bytes[i] === b);

/** RFC 8785 JSON Canonicalization: sorted keys, ECMAScript number and string forms. */
export function jcs(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(value[k]))
      .join(",") +
    "}"
  );
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

// ---------------------------------------------------------------------------
// DID document helpers
// ---------------------------------------------------------------------------

function methods(doc, did) {
  const found = new Map();
  for (const vm of list(doc, "verificationMethod").concat(list(doc, "assertionMethod"))) {
    if (isObject(vm)) {
      const id = absolute(vm.id, did);
      if (id && !found.has(id)) found.set(id, vm);
    }
  }
  return found;
}

function assertionIds(doc, did) {
  const ids = [];
  for (const ref of list(doc, "assertionMethod")) {
    const id = absolute(isObject(ref) ? ref.id : ref, did);
    if (id) ids.push(id);
  }
  return ids;
}

function mldsa44Claim(vm) {
  const mb = vm.publicKeyMultibase;
  if (vm.type === "Multikey" && typeof mb === "string" && mb.startsWith("z")) {
    const raw = b58decode(mb.slice(1));
    if (raw && startsWith(raw, MLDSA44_PUB_PREFIX)) {
      const size = raw.length - 2;
      return [size === MLDSA44_PUBLIC_KEY_LENGTH, `${size} bytes, expected ${MLDSA44_PUBLIC_KEY_LENGTH}`];
    }
  }
  const jwk = vm.publicKeyJwk;
  if (isObject(jwk) && jwk.kty === "AKP" && jwk.alg === "ML-DSA-44") {
    const raw = b64urlDecode(jwk.pub);
    if (!raw) return [false, "unreadable pub value"];
    return [
      raw.length === MLDSA44_PUBLIC_KEY_LENGTH,
      `${raw.length} bytes, expected ${MLDSA44_PUBLIC_KEY_LENGTH}`,
    ];
  }
  return null;
}

export function postQuantumSignal(doc, did) {
  if (!isObject(doc)) return [false, "no DID document"];
  const assertion = assertionIds(doc, did);
  const problems = [];
  for (const [vmId, vm] of methods(doc, did)) {
    const claim = mldsa44Claim(vm);
    if (!claim) continue;
    const [wellFormed, detail] = claim;
    const s = short(vmId, did);
    if (!wellFormed) problems.push(`ML-DSA-44 key ${s} is malformed (${detail})`);
    else if (vm.controller !== did) problems.push(`ML-DSA-44 key ${s} is not controlled by ${did}`);
    else if (!assertion.includes(vmId)) problems.push(`ML-DSA-44 key ${s} is not in assertionMethod`);
    else return [true, `ML-DSA-44 key ${s} in assertionMethod`];
  }
  if (problems.length) return [false, problems[0]];
  return [false, "no ML-DSA-44 verification method"];
}

function ed25519Key(doc, did, ref) {
  const vmId = absolute(ref, did);
  if (vmId === null) return [null, "has a proof that names no verificationMethod"];
  const s = short(vmId, did);
  const vm = methods(doc, did).get(vmId);
  if (!vm) return [null, `is signed by ${s}, which is not in the DID document`];
  if (vm.controller !== did) return [null, `is signed by ${s}, which is not controlled by ${did}`];
  if (!assertionIds(doc, did).includes(vmId)) {
    return [null, `is signed by ${s}, which is not in assertionMethod`];
  }
  const mb = vm.publicKeyMultibase;
  if (typeof mb === "string" && mb.startsWith("z")) {
    const raw = b58decode(mb.slice(1));
    if (raw && startsWith(raw, ED25519_PUB_PREFIX) && raw.length === 2 + ED25519_PUBLIC_KEY_LENGTH) {
      return [raw.slice(2), s];
    }
  }
  const jwk = vm.publicKeyJwk;
  if (isObject(jwk) && jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    const raw = b64urlDecode(jwk.x);
    if (raw && raw.length === ED25519_PUBLIC_KEY_LENGTH) return [raw, s];
  }
  return [null, `is signed by ${s}, which is not an Ed25519 key`];
}

// ---------------------------------------------------------------------------
// Credential checks
// ---------------------------------------------------------------------------

function parseTime(value) {
  if (typeof value !== "string") return null;
  const m = TIME_RE.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  const ms = Number((m[7] || "0").slice(0, 3).padEnd(3, "0"));
  const base = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  const check = new Date(base);
  if (
    check.getUTCFullYear() !== y ||
    check.getUTCMonth() !== mo - 1 ||
    check.getUTCDate() !== d ||
    check.getUTCHours() !== h ||
    check.getUTCMinutes() !== mi ||
    check.getUTCSeconds() !== s
  ) {
    return null;
  }
  const offset = m[8];
  if (offset === "Z") return base;
  const sign = offset[0] === "+" ? 1 : -1;
  return base - sign * (Number(offset.slice(1, 3)) * 3600000 + Number(offset.slice(4, 6)) * 60000);
}

function outsideWindow(cred, now) {
  const start = cred.validFrom ?? cred.issuanceDate;
  const end = cred.validUntil ?? cred.expirationDate;
  if (start !== undefined && start !== null) {
    const begins = parseTime(start);
    if (begins === null) return "has an unreadable validFrom";
    if (now < begins) return `is not valid until ${start}`;
  }
  if (end !== undefined && end !== null) {
    const ends = parseTime(end);
    if (ends === null) return "has an unreadable validUntil";
    if (now >= ends) return `expired ${end}`;
  }
  return null;
}

async function hashData(candidate, proof) {
  const document = { ...candidate };
  delete document.proof;
  const config = { ...proof };
  delete config.proofValue;
  if ("@context" in document) config["@context"] = document["@context"];
  const a = await sha256(jcs(config));
  const b = await sha256(jcs(document));
  const out = new Uint8Array(64);
  out.set(a, 0);
  out.set(b, 32);
  return out;
}

async function legacyDigest(candidate, proof) {
  const unsigned = { ...proof };
  delete unsigned.proofValue;
  return sha256(jcs({ ...candidate, proof: unsigned }));
}

async function verifyEd25519(raw, signature, message) {
  try {
    const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

async function verifyProof(candidate, raw) {
  const proof = candidate.proof;
  if (typeof proof.proofValue !== "string" || !proof.proofValue.startsWith("z")) return false;
  const signature = b58decode(proof.proofValue.slice(1));
  if (!signature) return false;
  if (await verifyEd25519(raw, signature, await hashData(candidate, proof))) return true;
  return verifyEd25519(raw, signature, await legacyDigest(candidate, proof));
}

async function verifyAssertion(cred, doc, did, now) {
  let issuer = cred.issuer;
  if (isObject(issuer)) issuer = issuer.id;
  if (issuer !== did) {
    return [false, `is issued by ${typeof issuer === "string" ? issuer : "an unnamed issuer"}, not ${did}`];
  }
  const outside = outsideWindow(cred, now);
  if (outside) return [false, outside];
  const proofs = Array.isArray(cred.proof) ? cred.proof : [cred.proof];
  const eddsa = proofs.filter((p) => isObject(p) && p.cryptosuite === EDDSA_CRYPTOSUITE);
  if (!eddsa.length) return [false, "has no eddsa-jcs-2022 proof"];
  const base = { ...cred };
  delete base.proof;
  let signer = "";
  for (const item of eddsa) {
    if (item.type !== "DataIntegrityProof" || item.proofPurpose !== "assertionMethod") {
      return [false, "has a proof that is not an assertionMethod DataIntegrityProof"];
    }
    const [raw, detail] = ed25519Key(doc, did, item.verificationMethod);
    if (!raw) return [false, detail];
    if (!(await verifyProof({ ...base, proof: item }, raw))) {
      return [false, `has a proof that does not verify against ${detail}`];
    }
    signer = signer || detail;
  }
  return [true, `is signed by ${signer}`];
}

async function encodedListDecodes(encoded) {
  if (typeof encoded !== "string" || !encoded.startsWith("u")) return false;
  const compressed = b64urlDecode(encoded.slice(1));
  if (!compressed || !compressed.length) return false;
  try {
    const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream("gzip"));
    const reader = stream.getReader();
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > STATUS_LIST_MAX_DECODED_BYTES) {
        await reader.cancel();
        return false;
      }
    }
    return total * 8 >= STATUS_LIST_MIN_BITS;
  } catch {
    return false;
  }
}

async function statusListProblem(lst, doc, did, now) {
  if (!isObject(lst)) return [false, "is not a JSON object"];
  if (!types(lst.type).includes("BitstringStatusListCredential")) {
    return [false, "is not a BitstringStatusListCredential"];
  }
  const subject = lst.credentialSubject;
  if (!isObject(subject) || !types(subject.type).includes("BitstringStatusList")) {
    return [false, "has no BitstringStatusList subject"];
  }
  if (!(await encodedListDecodes(subject.encodedList))) {
    return [false, "has an encodedList that does not decode"];
  }
  const [ok, why] = await verifyAssertion(lst, doc, did, now);
  if (!ok) return [false, why];
  const end = lst.validUntil ?? lst.expirationDate;
  return [true, typeof end === "string" ? `${why}, valid until ${end}` : why];
}

export async function revocationSignal(doc, did, fetchJson, now) {
  if (!isObject(doc)) return [false, "no DID document"];
  const services = list(doc, "service").filter(isObject);
  if (!services.length) return [false, "no service in the DID document"];
  const listed = services.filter((s) => types(s.type).some((t) => STATUS_LIST_SERVICE_TYPES.includes(t)));
  if (!listed.length) {
    const found = [...new Set(services.flatMap((s) => types(s.type)))].sort();
    return [false, `no BitstringStatusList service (found ${found.join(", ") || "untyped services"})`];
  }
  let reason = "";
  for (const service of listed.slice(0, STATUS_LIST_MAX_SERVICES)) {
    let endpoint = service.serviceEndpoint;
    if (Array.isArray(endpoint)) endpoint = endpoint.find((e) => typeof e === "string") ?? null;
    if (typeof endpoint !== "string" || !endpoint.startsWith("https://")) {
      reason = "BitstringStatusList service has no https endpoint";
      continue;
    }
    const lst = await fetchJson(endpoint);
    if (lst === null || lst === undefined) {
      reason = `status list ${endpoint} could not be fetched`;
      continue;
    }
    const [ok, why] = await statusListProblem(lst, doc, did, now);
    reason = `status list ${endpoint} ${why}`;
    if (ok) return [true, reason];
  }
  return [false, reason];
}

export async function cardIdentitySignal(card, doc, did, now) {
  if (!isObject(card)) return ["no", "no agent card"];
  const credential = card.vouchCredential;
  let problem = "carries no vouchCredential";
  if (isObject(credential)) {
    if (!isObject(doc)) {
      problem = "its vouchCredential cannot be checked without a DID document";
    } else {
      let [ok, why] = await verifyAssertion(credential, doc, did, now);
      if (ok) {
        let expected = "a2a:agent";
        if (typeof card.url === "string" && card.url) expected = card.url;
        else if (typeof card.name === "string" && card.name) expected = card.name;
        const subject = credential.credentialSubject;
        const intent = isObject(subject) ? subject.intent : null;
        const target = isObject(intent) ? intent.target : null;
        if (target === expected) return ["verified", `vouchCredential ${why}`];
        why = typeof target === "string" ? `is bound to ${target}, not ${expected}` : "names no target";
      }
      problem = `its vouchCredential ${why}`;
    }
  }
  const named = DID_RE.exec(JSON.stringify(card));
  if (!named) return ["no", "agent card names no DID"];
  return ["declared", `agent card names ${named[0]} but ${problem}`];
}

/** The post-quantum, revocation and agent-card signals for one DID. */
export async function evidenceSignals(did, doc, cards, fetchJson, now) {
  const at = now instanceof Date ? now.getTime() : now;
  const [pqReady, pqReason] = postQuantumSignal(doc, did);
  const [hasRevocation, revocationReason] = await revocationSignal(doc, did, fetchJson, at);
  let best = null;
  for (const card of cards) {
    if (card === null || card === undefined) continue;
    const [state, why] = await cardIdentitySignal(card, doc, did, at);
    if (best === null || CARD_STATES.indexOf(state) > CARD_STATES.indexOf(best[0])) best = [state, why];
  }
  const [state, cardReason] = best || ["no", "no agent card"];
  return {
    pq_ready: pqReady,
    has_revocation: hasRevocation,
    has_card_identity: state === "verified",
    card_identity: state,
    reasons: { pq_ready: pqReason, has_revocation: revocationReason, card_identity: cardReason },
  };
}

// ---------------------------------------------------------------------------
// Guarded fetch
// ---------------------------------------------------------------------------

function ipv4IsPublic(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b, c] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function ipv6IsPublic(ip) {
  const v = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (mapped) return ipv4IsPublic(mapped[1]);
  if (v === "::" || v === "::1") return false;
  const first = parseInt(v.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
  if ((first & 0xffc0) === 0xfe80) return false; // fe80::/10 link local
  if ((first & 0xff00) === 0xff00) return false; // multicast
  if (first === 0x2001 && parseInt(v.split(":")[1] || "0", 16) === 0x0db8) return false;
  if (first === 0x2002 || first === 0x0064 || first === 0) return false; // 6to4, NAT64, embedded v4
  return (first & 0xe000) === 0x2000; // global unicast 2000::/3
}

async function dohAddresses(host, type) {
  const resp = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
    { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(3000) }
  );
  if (resp.status !== 200) throw new Error("dns lookup failed");
  const body = await resp.json();
  const code = type === "A" ? 1 : 28;
  return (body.Answer || []).filter((a) => a.type === code).map((a) => a.data);
}

/** True only for a DNS name whose every A and AAAA answer is a public address. */
export async function hostIsPublic(host) {
  const h = host.toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)) return false; // also rejects IP literals
  if (h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return false;
  try {
    const v4 = await dohAddresses(h, "A");
    const v6 = await dohAddresses(h, "AAAA");
    if (!v4.length && !v6.length) return false;
    return v4.every(ipv4IsPublic) && v6.every(ipv6IsPublic);
  } catch {
    return false;
  }
}

async function readCapped(body, maxBytes, deadline) {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    if (Date.now() > deadline) {
      await reader.cancel();
      return null;
    }
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/**
 * GET a JSON document with the same limits as vouch.ssrf.fetch_json: https
 * only, public hosts only, each redirect re-checked (up to maxRedirects), the
 * body capped at maxBytes, and the whole fetch bounded in time. Returns null
 * when the document is missing or unsafe to fetch.
 */
export async function guardedFetchJson(url, { maxBytes, maxRedirects = 3, timeoutMs = 5000 }) {
  const deadline = Date.now() + 3 * timeoutMs;
  let current = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    let u;
    try {
      u = new URL(current);
    } catch {
      return null;
    }
    if (u.protocol !== "https:" || u.username || u.password) return null;
    if (!(await hostIsPublic(u.hostname))) return null;
    const remaining = deadline - Date.now();
    if (remaining <= 0) return null;
    let resp;
    try {
      resp = await fetch(u.toString(), {
        redirect: "manual",
        headers: { Accept: "application/json, application/did+json, application/ld+json" },
        signal: AbortSignal.timeout(Math.min(timeoutMs, remaining)),
      });
    } catch {
      return null;
    }
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const location = resp.headers.get("Location");
      if (!location) return null;
      current = new URL(location, u).toString();
      continue;
    }
    if (resp.status !== 200) return null;
    const declared = resp.headers.get("Content-Length");
    if (declared && /^\d+$/.test(declared) && Number(declared) > maxBytes) return null;
    const body = await readCapped(resp.body, maxBytes, deadline);
    if (!body) return null;
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
    } catch {
      return null;
    }
  }
  return null;
}
