// Vouch conformance worker (Cloudflare). Issues fresh per-session challenges,
// re-checks submitted responses server-side with the canonical Vouch core (WASM),
// derives the conformance level, mints a signed VouchConformanceCredential, and
// serves the badge and a re-verifiable result. A submitted transcript cannot be
// faked by replaying public vectors: the worker recomputes every expected answer.
//
// Endpoints:
//   POST /conformance/session                -> { sessionId, expiresAt, challenges }
//   POST /conformance/session/{id}/submit    -> { levelAchieved, checks, badgeUrl, verifyUrl, credential }
//   GET  /conformance/{id}                   -> { level, credential, transcriptHash, checks }
//   GET  /conformance/{id}/badge.svg         -> SVG badge
import init, * as core from "@vouch-protocol-official/core-wasm";
import wasmModule from "@vouch-protocol-official/core-wasm/vouch_core_wasm_bg.wasm";
import {
  buildSession,
  recheck,
  deriveLevel,
  buildConformanceCredential,
  mint,
  transcriptHash,
  badgeSvg,
} from "./lib.js";

const SESSION_TTL = 600; // seconds

let ready;
async function loadCore() {
  if (!ready) ready = init({ module_or_path: wasmModule });
  await ready;
  return core;
}

const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type" };
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj, null, 2), { status, headers: { "content-type": "application/json", ...CORS } });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    try {
      if (request.method === "POST" && path === "/conformance/session") return await createSession(request, env);

      let m = path.match(/^\/conformance\/session\/([^/]+)\/submit$/);
      if (request.method === "POST" && m) return await submit(request, env, m[1]);

      m = path.match(/^\/conformance\/([^/]+)\/badge\.svg$/);
      if (request.method === "GET" && m) return await badge(env, m[1]);

      m = path.match(/^\/conformance\/([^/]+)$/);
      if (request.method === "GET" && m) return await getResult(env, m[1]);

      return json({ error: "not found" }, 404);
    } catch (err) {
      return json({ error: String(err && err.message ? err.message : err) }, 500);
    }
  },
};

async function createSession(request, env) {
  const c = await loadCore();
  const body = await request.json();
  const implementation = body.implementation || {};
  if (!implementation.publicKeyB64) return json({ error: "implementation.publicKeyB64 is required" }, 400);
  const session = buildSession(c, implementation, new Date().toISOString());
  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_TTL * 1000).toISOString();
  await env.CONFORMANCE.put(`session:${sessionId}`, JSON.stringify({ ...session, expiresAt }), {
    expirationTtl: SESSION_TTL,
  });
  return json({ sessionId, expiresAt, challenges: session.challenges });
}

async function submit(request, env, sessionId) {
  const c = await loadCore();
  const raw = await env.CONFORMANCE.get(`session:${sessionId}`);
  if (!raw) return json({ error: "session not found or expired" }, 404);
  const session = JSON.parse(raw);
  if (session.submitted) return json({ error: "session already submitted" }, 409);

  const body = await request.json();
  const responses = body.responses || [];
  const checks = recheck(c, session, responses);
  const level = deriveLevel(checks);
  const th = await transcriptHash(session, responses);

  let credential = null;
  if (level && env.ISSUER_SEED_B64) {
    const nowIso = new Date().toISOString();
    const validUntilIso = new Date(Date.now() + 365 * 86400 * 1000).toISOString();
    const unsigned = buildConformanceCredential({
      implementation: session.implementation,
      level,
      issuerDid: env.ISSUER_DID,
      nowIso,
      validUntilIso,
      transcriptHash: th,
    });
    credential = mint(c, unsigned, env.ISSUER_SEED_B64, env.ISSUER_VM || `${env.ISSUER_DID}#key-1`, nowIso);
  }

  const resultId = crypto.randomUUID();
  await env.CONFORMANCE.put(
    `result:${resultId}`,
    JSON.stringify({ resultId, level, checks, transcriptHash: th, implementation: session.implementation, credential })
  );
  // Burn the session so it cannot be submitted twice.
  await env.CONFORMANCE.put(`session:${sessionId}`, JSON.stringify({ ...session, submitted: true }), { expirationTtl: 60 });

  const origin = new URL(request.url).origin;
  return json({
    levelAchieved: level,
    checks,
    transcriptHash: th,
    badgeUrl: level ? `${origin}/conformance/${resultId}/badge.svg` : null,
    verifyUrl: `${origin}/conformance/${resultId}`,
    credential,
  });
}

async function getResult(env, resultId) {
  const raw = await env.CONFORMANCE.get(`result:${resultId}`);
  if (!raw) return json({ error: "not found" }, 404);
  const r = JSON.parse(raw);
  return json({ level: r.level, implementation: r.implementation, transcriptHash: r.transcriptHash, credential: r.credential, checks: r.checks });
}

async function badge(env, resultId) {
  const raw = await env.CONFORMANCE.get(`result:${resultId}`);
  const level = raw ? JSON.parse(raw).level : null;
  if (!level) return json({ error: "no conformant result for this id" }, 404);
  return new Response(badgeSvg(level, resultId), {
    headers: { "content-type": "image/svg+xml", "cache-control": "max-age=300", ...CORS },
  });
}
