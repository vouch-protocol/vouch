// End-to-end smoke test for the conformance logic, run with node (no Cloudflare).
// It exercises the full loop against the canonical core: the worker issues fresh
// challenges, an honest implementation answers them, the worker re-checks and
// derives the level, mints and verifies the badge credential, and a cheating
// implementation is caught. Run: node smoke.mjs
import init, * as core from "@vouch-protocol-official/core-wasm";
import { readFileSync } from "fs";
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

function honestResponses(session) {
  return session.challenges.map((ch) => {
    if (ch.check === "canonicalization") {
      return { challengeId: ch.challengeId, output: core.canonicalize(JSON.stringify(ch.input)) };
    }
    if (ch.check === "sign_verify") {
      return { challengeId: ch.challengeId, output: implCredential(ch.input.intent) };
    }
    if (ch.check === "validity_window") {
      const r = JSON.parse(
        core.verify(JSON.stringify(ch.input.credential), ch.input.publicKeyB64, now, 30)
      );
      return { challengeId: ch.challengeId, output: { valid: r.valid } };
    }
    return { challengeId: ch.challengeId, output: { firstAccepted: true, secondAccepted: false } };
  });
}

const session = buildSession(core, implementation, now);
ok("session issues at least four challenges", session.challenges.length >= 4);

const honest = honestResponses(session);
const checks = recheck(core, session, honest);
ok("all honest checks pass", checks.every((c) => c.pass));
ok("derives L1", deriveLevel(checks) === "L1");

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
const cheatChecks = recheck(core, session, cheat);
ok("cheating canonicalization is caught", cheatChecks.some((c) => c.name === "canonicalization" && !c.pass));
ok("cheating implementation is denied a level", deriveLevel(cheatChecks) === null);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
