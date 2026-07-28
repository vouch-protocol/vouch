// End-to-end smoke test for the conformance logic, run with node (no Cloudflare).
// It exercises the full loop against the canonical core: the worker issues fresh
// challenges, an honest implementation answers them, the worker re-checks and
// derives the level, mints and verifies the badge credential, and a cheating
// implementation is caught. Run: node smoke.mjs
import init, * as core from "@vouch-protocol-official/core-wasm";
import { readFileSync } from "fs";
import { gzipSync } from "zlib";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  buildSession,
  recheck,
  deriveLevel,
  buildConformanceCredential,
  mint,
  transcriptHash,
} from "./lib.js";

const wasm = readFileSync(
  new URL("./node_modules/@vouch-protocol-official/core-wasm/vouch_core_wasm_bg.wasm", import.meta.url)
);
await init({ module_or_path: wasm });

const now = "2026-07-03T00:00:00Z";
let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}`);
  cond ? pass++ : fail++;
};

const issuer = JSON.parse(core.generateEd25519());
const impl = JSON.parse(core.generateEd25519());
const implementation = {
  name: "reference",
  repo: "vouch-protocol/vouch",
  commit: "abc123",
  did: impl.did_key,
  publicKeyB64: impl.public_b64,
};

function implCredential(intent) {
  const skel = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://vouch-protocol.com/contexts/v1"],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", "VouchCredential"],
    issuer: impl.did_key,
    validFrom: now,
    validUntil: "2100-01-01T00:00:00Z",
    credentialSubject: { id: impl.did_key, vouchVersion: "1.0", intent },
  };
  return JSON.parse(core.sign(JSON.stringify(skel), impl.seed_b64, `${impl.did_key}#key-1`, now));
}

// --- an honest implementation answering the L2 challenges --------------------

const STATUS_LIST_BYTES = 16384; // 131072 bits, the reference default

function buildStatusList(input) {
  const bits = new Uint8Array(STATUS_LIST_BYTES);
  const set = (index) => {
    bits[Math.floor(index / 8)] |= 1 << (7 - (index % 8));
  };
  set(input.revokedIndex);
  const encodedList = "u" + gzipSync(Buffer.from(bits), { level: 9 }).toString("base64url").replace(/=+$/, "");
  const entry = (index) => ({
    id: `${input.statusListId}#${index}`,
    type: "BitstringStatusListEntry",
    statusPurpose: input.statusPurpose,
    statusListIndex: String(index),
    statusListCredential: input.statusListId,
  });
  return {
    statusListCredential: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: input.statusListId,
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: impl.did_key,
      validFrom: now,
      validUntil: "2100-01-01T00:00:00Z",
      credentialSubject: {
        id: `${input.statusListId}#list`,
        type: "BitstringStatusList",
        statusPurpose: input.statusPurpose,
        encodedList,
      },
    },
    revokedEntry: entry(input.revokedIndex),
    activeEntry: entry(input.activeIndex),
  };
}

function delegatedChild(input) {
  const parent = input.parentCredential;
  const skel = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://vouch-protocol.com/contexts/v1"],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", "VouchCredential"],
    issuer: impl.did_key,
    validFrom: now,
    validUntil: "2100-01-01T00:00:00Z",
    credentialSubject: {
      id: impl.did_key,
      vouchVersion: "1.0",
      intent: input.narrowedIntent,
      delegationChain: [
        {
          issuer: parent.issuer,
          subject: impl.did_key,
          intent: parent.credentialSubject.intent,
          validFrom: parent.validFrom,
          validUntil: parent.validUntil,
          parentProofValue: (parent.proof?.proofValue || "").slice(0, 64),
        },
      ],
    },
  };
  return JSON.parse(core.sign(JSON.stringify(skel), impl.seed_b64, `${impl.did_key}#key-1`, now));
}

async function auditEntries(actions) {
  const GENESIS = "0".repeat(64);
  const entries = [];
  let prev = GENESIS;
  for (let i = 0; i < actions.length; i++) {
    const content = { seq: i, prev_hash: prev, ...actions[i] };
    const ordered = {};
    for (const k of ["seq", "timestamp", "action", "actor", "resource", "decision", "metadata", "prev_hash"]) {
      if (content[k] !== undefined && content[k] !== null) ordered[k] = content[k];
    }
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(core.canonicalize(JSON.stringify(ordered)))
    );
    const entry_hash = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    entries.push({ ...ordered, entry_hash });
    prev = entry_hash;
  }
  return entries;
}

async function honestResponses(session) {
  const out = [];
  for (const ch of session.challenges) {
    if (ch.check === "canonicalization") {
      out.push({ challengeId: ch.challengeId, output: core.canonicalize(JSON.stringify(ch.input)) });
    } else if (ch.check === "sign_verify") {
      out.push({ challengeId: ch.challengeId, output: implCredential(ch.input.intent) });
    } else if (ch.check === "validity_window") {
      const r = JSON.parse(core.verify(JSON.stringify(ch.input.credential), ch.input.publicKeyB64, now, 30));
      out.push({ challengeId: ch.challengeId, output: { valid: r.valid } });
    } else if (ch.check === "nonce_replay") {
      out.push({ challengeId: ch.challengeId, output: { firstAccepted: true, secondAccepted: false } });
    } else if (ch.check === "revocation") {
      out.push({ challengeId: ch.challengeId, output: buildStatusList(ch.input) });
    } else if (ch.check === "delegation_narrowing") {
      out.push({ challengeId: ch.challengeId, output: delegatedChild(ch.input) });
    } else if (ch.check === "sidecar_allow_deny") {
      out.push({
        challengeId: ch.challengeId,
        output: {
          allowed: implCredential(ch.input.allowedIntent),
          denied: { rejected: true, reason: `policy_denied:${ch.input.deniedIntent.action}` },
        },
      });
    } else if (ch.check === "audit_trail") {
      out.push({ challengeId: ch.challengeId, output: { entries: await auditEntries(ch.input.actions) } });
    }
  }
  return out;
}

const session = buildSession(core, implementation, now);
ok("session issues L1 and L2 challenges", session.challenges.length >= 8);

const honest = await honestResponses(session);
const checks = await recheck(core, session, honest);
const failed = checks.filter((c) => !c.pass).map((c) => `${c.name}: ${c.detail}`);
ok(`all honest checks pass${failed.length ? " (" + failed.join("; ") + ")" : ""}`, failed.length === 0);
ok("derives L2", deriveLevel(checks) === "L2");

const th = await transcriptHash(session, honest);
const credential = buildConformanceCredential({
  implementation,
  level: deriveLevel(checks),
  issuerDid: "did:web:vouch-protocol.com:conformance",
  nowIso: now,
  validUntilIso: "2027-07-03T00:00:00Z",
  transcriptHash: th,
});
const signed = mint(core, credential, issuer.seed_b64, "did:web:vouch-protocol.com:conformance#key-1", now);
ok("minted badge credential verifies", core.verifyProof(JSON.stringify(signed), issuer.public_b64) === true);

const cheat = honest.map((r) =>
  r.challengeId.startsWith("canon-") ? { challengeId: r.challengeId, output: r.output + " " } : r
);
const cheatChecks = await recheck(core, session, cheat);
ok("cheating canonicalization is caught", cheatChecks.some((c) => c.name === "canonicalization" && !c.pass));
ok("cheating implementation is denied a level", deriveLevel(cheatChecks) === null);

// A forged audit trail (a tampered entry that keeps its old hash) must not pass.
const forged = honest.map((r) => {
  if (!r.challengeId.startsWith("audit-")) return r;
  const entries = JSON.parse(JSON.stringify(r.output.entries));
  entries[1].resource = "exfiltrate_secrets";
  return { challengeId: r.challengeId, output: { entries } };
});
const forgedChecks = await recheck(core, session, forged);
ok("tampered audit trail is caught", forgedChecks.some((c) => c.name === "audit_trail" && !c.pass));

// A status list that never set the revoked bit must not pass.
const unrevoked = honest.map((r) => {
  if (!r.challengeId.startsWith("revocation-")) return r;
  const out = JSON.parse(JSON.stringify(r.output));
  out.revokedEntry = out.activeEntry;
  return { challengeId: r.challengeId, output: out };
});
const unrevokedChecks = await recheck(core, session, unrevoked);
ok("unset revocation bit is caught", unrevokedChecks.some((c) => c.name === "revocation" && !c.pass));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
