// Pure conformance logic: fresh challenge generation, server-side re-check,
// level derivation, and credential minting. No Cloudflare or wall-clock
// dependency (timestamps are passed in), so it runs identically in the Worker
// and in the node smoke test. Every crypto operation goes through the canonical
// Vouch core (WASM), so re-check and minting match the reference SDK by
// construction, a submitted transcript cannot be faked by replaying the public
// test vectors because the worker recomputes the expected answers itself.

const CANON_COUNT = 3;

// The checks each level requires. Extend with L3 as those challenges land.
export const LEVEL_CHECKS = {
  L1: ["canonicalization", "sign_verify", "validity_window", "nonce_replay"],
  L2: ["revocation", "delegation_narrowing", "sidecar_allow_deny", "audit_trail"],
};
const LEVEL_ORDER = ["L1", "L2"];

// Audit trail: SHA-256 over the JCS-canonical bytes of the entry content, with
// each entry committing to the previous entry's hash. Matches the reference SDK.
const GENESIS_HASH = "0".repeat(64);

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(text) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

// The hashed content: every field except entry_hash, with null values dropped.
function auditContent(entry) {
  const content = {};
  for (const key of ["seq", "timestamp", "action", "actor", "resource", "decision", "metadata", "prev_hash"]) {
    if (entry[key] !== null && entry[key] !== undefined) content[key] = entry[key];
  }
  return content;
}

function randInt(max) {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return a[0] % max;
}

function randomJson(depth) {
  if (depth <= 0) {
    const kind = randInt(3);
    if (kind === 0) return "v" + randInt(1_000_000);
    if (kind === 1) return randInt(1_000_000);
    return randInt(2) === 1;
  }
  const obj = {};
  const count = 2 + randInt(3);
  for (let i = 0; i < count; i++) obj["k" + randInt(1_000_000)] = randomJson(depth - 1);
  return obj;
}

function credentialSkeleton(issuerDid, intent, validFrom, validUntil) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://vouch-protocol.com/contexts/v1"],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", "VouchCredential"],
    issuer: issuerDid,
    validFrom,
    validUntil,
    credentialSubject: { id: issuerDid, vouchVersion: "1.0", intent },
  };
}

// Build the challenge set plus the server-only expected answers. `expected` is
// stored server-side and never sent to the implementation.
export function buildSession(core, implementation, nowIso) {
  const challenges = [];
  const expected = {};

  // canonicalization: fresh random JSON; the implementation returns RFC 8785 bytes.
  for (let i = 0; i < CANON_COUNT; i++) {
    const input = randomJson(2);
    challenges.push({ challengeId: `canon-${i}`, check: "canonicalization", level: "L1", input });
    expected[`canon-${i}`] = core.canonicalize(JSON.stringify(input));
  }

  // sign_verify: the implementation signs a credential over this intent with its own key.
  const intent = {
    action: "conformance_probe",
    target: `vector:${randInt(1_000_000_000)}`,
    resource: "https://conformance.vouch-protocol.com/probe",
  };
  challenges.push({ challengeId: "sign-0", check: "sign_verify", level: "L1", input: { intent } });

  // validity_window: a credential we sign with a throwaway key, already expired;
  // the implementation must report it invalid.
  const vk = JSON.parse(core.generateEd25519());
  const expired = credentialSkeleton(vk.did_key, intent, "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z");
  const expiredSigned = core.sign(
    JSON.stringify(expired), vk.seed_b64, `${vk.did_key}#key-1`, "2000-01-01T00:00:00Z"
  );
  challenges.push({
    challengeId: "validity-0",
    check: "validity_window",
    level: "L1",
    input: { credential: JSON.parse(expiredSigned), publicKeyB64: vk.public_b64 },
  });
  expected["validity-0"] = { valid: false };

  // nonce_replay: the implementation is shown the same credential id twice and
  // must flag the second presentation as a replay.
  const nk = JSON.parse(core.generateEd25519());
  const fresh = credentialSkeleton(nk.did_key, intent, nowIso, "2100-01-01T00:00:00Z");
  const freshSigned = core.sign(
    JSON.stringify(fresh), nk.seed_b64, `${nk.did_key}#key-1`, nowIso
  );
  challenges.push({
    challengeId: "nonce-0",
    check: "nonce_replay",
    level: "L1",
    input: { credential: JSON.parse(freshSigned), publicKeyB64: nk.public_b64, presentations: 2 },
  });
  expected["nonce-0"] = { firstAccepted: true, secondAccepted: false };

  // revocation: the implementation builds a BitstringStatusList credential with
  // one index revoked and one left active, plus the matching status entries. The
  // worker decodes the list with the canonical core and checks both readings.
  const revokedIndex = randInt(4096);
  let activeIndex = randInt(4096);
  if (activeIndex === revokedIndex) activeIndex = (activeIndex + 1) % 4096;
  challenges.push({
    challengeId: "revocation-0",
    check: "revocation",
    level: "L2",
    input: {
      statusListId: `https://conformance.vouch-protocol.com/status/${randInt(1_000_000)}`,
      revokedIndex,
      activeIndex,
      statusPurpose: "revocation",
    },
  });

  // delegation_narrowing: the implementation issues a child credential chained to
  // this parent, narrowed to the given intent. The worker verifies the child's
  // signature and that the chain records the parent's issuer.
  const pk = JSON.parse(core.generateEd25519());
  const parent = credentialSkeleton(
    pk.did_key,
    { action: "manage", target: "all_records", resource: "https://conformance.vouch-protocol.com/db" },
    nowIso,
    "2100-01-01T00:00:00Z"
  );
  const parentSigned = JSON.parse(
    core.sign(JSON.stringify(parent), pk.seed_b64, `${pk.did_key}#key-1`, nowIso)
  );
  challenges.push({
    challengeId: "delegation-0",
    check: "delegation_narrowing",
    level: "L2",
    input: {
      parentCredential: parentSigned,
      narrowedIntent: {
        action: "read",
        target: "one_record",
        resource: "https://conformance.vouch-protocol.com/db/records/1",
      },
    },
  });
  expected["delegation-0"] = { parentIssuer: pk.did_key };

  // sidecar_allow_deny: one intent the policy allows, one it does not. The
  // allowed intent must be signed, the disallowed one refused with a reason.
  const allowedAction = "read";
  challenges.push({
    challengeId: "sidecar-0",
    check: "sidecar_allow_deny",
    level: "L2",
    input: {
      policy: { allowedActions: [allowedAction] },
      allowedIntent: {
        action: allowedAction,
        target: `vector:${randInt(1_000_000)}`,
        resource: "https://conformance.vouch-protocol.com/allowed",
      },
      deniedIntent: {
        action: "delete",
        target: `vector:${randInt(1_000_000)}`,
        resource: "https://conformance.vouch-protocol.com/denied",
      },
    },
  });

  // audit_trail: a fixed action sequence the implementation records as a
  // hash-linked trail. The worker recomputes every entry hash and the linkage.
  const actions = [
    { action: "ALLOWED", actor: "did:web:conformance.vouch-protocol.com", resource: "read_file" },
    { action: "BLOCKED", actor: "did:web:conformance.vouch-protocol.com", resource: "run_command", decision: "untrusted" },
    { action: "ALLOWED", actor: "did:web:conformance.vouch-protocol.com", resource: "write_file" },
  ].map((a, i) => ({ ...a, timestamp: `2026-01-0${i + 1}T00:00:00Z` }));
  challenges.push({
    challengeId: "audit-0",
    check: "audit_trail",
    level: "L2",
    input: { actions },
  });

  return { implementation, createdAt: nowIso, challenges, expected };
}

// Re-check every response against the server-held expected answers, using the
// canonical core for the cryptographic checks.
export async function recheck(core, session, responses) {
  const byId = Object.fromEntries((responses || []).map((r) => [r.challengeId, r]));
  const checks = [];
  for (const ch of session.challenges) {
    const resp = byId[ch.challengeId];
    let pass = false;
    let detail = "no response submitted";
    try {
      if (ch.check === "canonicalization") {
        pass = resp?.output === session.expected[ch.challengeId];
        detail = pass ? "byte-identical to the canonical core" : "canonical bytes differ";
      } else if (ch.check === "sign_verify") {
        const cred = resp?.output;
        pass = !!cred && core.verifyProof(JSON.stringify(cred), session.implementation.publicKeyB64) === true;
        detail = pass ? "signature verifies against the registered key" : "signature did not verify";
      } else if (ch.check === "validity_window") {
        pass = resp?.output?.valid === false;
        detail = pass ? "expired credential rejected" : "expired credential was not rejected";
      } else if (ch.check === "nonce_replay") {
        const out = resp?.output || {};
        pass = out.firstAccepted === true && out.secondAccepted === false;
        detail = pass ? "replay rejected on the second presentation" : "replay was not detected";
      } else if (ch.check === "revocation") {
        // Decode the submitted status list with the canonical core: the revoked
        // index must read as revoked and the untouched index as active.
        const out = resp?.output || {};
        const listCredential = JSON.stringify(out.statusListCredential);
        const revoked = core.verifyStatus(JSON.stringify(out.revokedEntry), listCredential) === true;
        const active = core.verifyStatus(JSON.stringify(out.activeEntry), listCredential) === false;
        pass = revoked && active;
        detail = pass
          ? "revoked index reads revoked, untouched index reads active"
          : `status readings wrong (revoked=${revoked}, active-clear=${active})`;
      } else if (ch.check === "delegation_narrowing") {
        // The child must carry a valid signature and record its parent in the chain.
        const child = resp?.output;
        const signed =
          !!child && core.verifyProof(JSON.stringify(child), session.implementation.publicKeyB64) === true;
        const chain = child?.credentialSubject?.delegationChain || [];
        const linked = chain.some((link) => link.issuer === session.expected[ch.challengeId]?.parentIssuer);
        pass = signed && linked;
        detail = pass
          ? "child verifies and records its parent in the delegation chain"
          : `chain incomplete (signature=${signed}, parent recorded=${linked})`;
      } else if (ch.check === "sidecar_allow_deny") {
        const out = resp?.output || {};
        const allowedOk =
          !!out.allowed &&
          core.verifyProof(JSON.stringify(out.allowed), session.implementation.publicKeyB64) === true;
        const deniedOk = out.denied?.rejected === true && !!out.denied?.reason;
        pass = allowedOk && deniedOk;
        detail = pass
          ? "allowed intent signed, disallowed intent refused with a reason"
          : `policy not enforced (allowed signed=${allowedOk}, denial structured=${deniedOk})`;
      } else if (ch.check === "audit_trail") {
        // Recompute every entry hash and the chain linkage from the raw entries.
        const entries = resp?.output?.entries || [];
        let previous = GENESIS_HASH;
        let ok = entries.length === ch.input.actions.length;
        for (const entry of entries) {
          if (!ok) break;
          if (entry.prev_hash !== previous) {
            ok = false;
            break;
          }
          const canonical = core.canonicalize(JSON.stringify(auditContent(entry)));
          if ((await sha256Hex(canonical)) !== entry.entry_hash) {
            ok = false;
            break;
          }
          previous = entry.entry_hash;
        }
        pass = ok;
        detail = pass
          ? `${entries.length} entries hash-linked and byte-correct`
          : "entry hashes or chain linkage did not recompute";
      }
    } catch (err) {
      detail = `error: ${err && err.message ? err.message : err}`;
    }
    checks.push({ name: ch.check, level: ch.level, challengeId: ch.challengeId, pass, detail });
  }
  return checks;
}

// Highest level for which every required check passed.
export function deriveLevel(checks) {
  const byName = {};
  for (const c of checks) byName[c.name] = (byName[c.name] ?? true) && c.pass;
  let achieved = null;
  for (const level of LEVEL_ORDER) {
    if (LEVEL_CHECKS[level].every((name) => byName[name] === true)) achieved = level;
    else break;
  }
  return achieved;
}

export function buildConformanceCredential({ implementation, level, issuerDid, nowIso, validUntilIso, transcriptHash }) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://vouch-protocol.com/contexts/v1"],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", "VouchCredential", "VouchConformanceCredential"],
    issuer: issuerDid,
    validFrom: nowIso,
    validUntil: validUntilIso,
    credentialSubject: {
      id: implementation.did || `git:${implementation.repo}@${implementation.commit}`,
      vouchVersion: "1.0",
      conformance: {
        level,
        implementation: {
          name: implementation.name,
          repo: implementation.repo,
          commit: implementation.commit,
        },
        transcriptHash,
      },
      intent: {
        action: "attest",
        target: implementation.repo || implementation.name,
        resource: "https://conformance.vouch-protocol.com",
        role: `conformant-${level}`,
      },
    },
  };
}

export function mint(core, credential, issuerSeedB64, verificationMethod, createdIso) {
  return JSON.parse(
    core.sign(JSON.stringify(credential), issuerSeedB64, verificationMethod, createdIso)
  );
}

export async function transcriptHash(session, responses) {
  const payload = JSON.stringify({
    challenges: session.challenges.map((c) => ({ id: c.challengeId, input: c.input })),
    responses: (responses || []).map((r) => ({ id: r.challengeId, output: r.output })),
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const DARK = "#333333";
const BURGUNDY = "#7C2D3A";
const CHECK = "#34D399";

export function badgeSvg(level, id) {
  const right = `L${level.replace(/^L/, "")} Conformant`;
  return `<svg role="img" aria-label="Vouch Verified, ${right}" viewBox="0 0 252 22" xmlns="http://www.w3.org/2000/svg">
  <clipPath id="r"><rect width="252" height="22" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="132" height="22" fill="${DARK}"/>
    <rect x="132" width="120" height="22" fill="${BURGUNDY}"/>
  </g>
  <path d="M9 11 l2.7 2.7 L17.8 7.4" fill="none" stroke="${CHECK}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  <g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11.5" fill="#fff">
    <text x="79" y="15" text-anchor="middle">Vouch Verified</text>
    <text x="192" y="15" text-anchor="middle">${right}</text>
  </g>
</svg>`;
}
