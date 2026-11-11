/**
 * Agent Trust Index grader, as a Cloudflare Worker.
 *
 * The browser cannot fetch an arbitrary domain's did.json (CORS), so the live
 * "grade your agent" form on the Index page calls this worker, which resolves
 * the DID server-side and returns a grade. It is a faithful port of the Python
 * `vouch grade` scoring: 60 points for a resolvable did:web, 40 for a usable
 * verification method, with post-quantum, revocation, and agent-card identity
 * reported as extra signals that do not change the score. The extra signals
 * come from evidence.js, the same evidence checks as vouch/grade.py, and every
 * fetch goes through its guarded fetcher.
 *
 * Endpoints:
 *   GET /grade?domain=example.com   -> JSON report
 *   GET /badge?domain=example.com   -> SVG badge
 *
 * No secrets, no storage. Public, read-only grading.
 */

import {
  CARD_MAX_BYTES,
  CARD_PATHS,
  DID_DOCUMENT_MAX_BYTES,
  STATUS_LIST_MAX_BYTES,
  evidenceSignals,
  guardedFetchJson,
} from "./evidence.js";

const GRADE_COLORS = { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }
    const domain = normalizeDomain(url.searchParams.get("domain"));
    if (!domain) {
      return json({ error: "invalid_or_missing_domain" }, 400);
    }

    const report = await grade(domain);

    if (url.pathname === "/badge") {
      return new Response(badgeSvg(report), {
        headers: {
          ...CORS,
          "Content-Type": "image/svg+xml",
          "Cache-Control": "public, max-age=300",
        },
      });
    }
    return json(report, 200);
  },
};

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
}

/**
 * Accept only a plausible public hostname. Rejects IP literals, localhost, and
 * internal names so the worker cannot be pointed at private infrastructure.
 */
function normalizeDomain(raw) {
  if (!raw) return null;
  let d = raw.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return null;
  if (d === "localhost" || d.endsWith(".local") || d.endsWith(".internal")) return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(d)) return null; // IPv4 literal
  return d;
}

async function grade(domain) {
  const signals = {
    has_did: false,
    has_verification_method: false,
    did: null,
    method: null,
    pq_ready: false,
    has_revocation: false,
    has_card_identity: false,
    card_identity: "no",
    reasons: {},
  };
  const did = `did:web:${domain}`;

  const didDoc = await guardedFetchJson(`https://${domain}/.well-known/did.json`, {
    maxBytes: DID_DOCUMENT_MAX_BYTES,
  });
  if (didDoc && typeof didDoc === "object") {
    signals.has_did = true;
    signals.did = did;

    const vms = []
      .concat(didDoc.verificationMethod || [])
      .concat(didDoc.assertionMethod || [])
      .filter((v) => v && typeof v === "object");
    for (const vm of vms) {
      if (vm.publicKeyJwk) {
        signals.has_verification_method = true;
        const k = vm.publicKeyJwk;
        signals.method = `did:web, ${k.crv || k.kty || "key"} (JWK)`;
        break;
      }
      if (vm.publicKeyMultibase) {
        signals.has_verification_method = true;
        signals.method = "did:web, Multikey";
        break;
      }
    }
  }

  const cards = [];
  for (const path of CARD_PATHS) {
    cards.push(await guardedFetchJson(`https://${domain}${path}`, { maxBytes: CARD_MAX_BYTES }));
  }
  const doc = signals.has_did && !Array.isArray(didDoc) ? didDoc : null;
  const fetchList = (u) => guardedFetchJson(u, { maxBytes: STATUS_LIST_MAX_BYTES });
  Object.assign(signals, await evidenceSignals(did, doc, cards, fetchList, new Date()));

  return { domain, ...scoreSignals(signals), signals, fixes: fixIts(signals) };
}

function scoreSignals(signals) {
  const breakdown = {
    resolvable_did: signals.has_did ? 60 : 0,
    valid_verification_method: signals.has_verification_method ? 40 : 0,
  };
  const score = breakdown.resolvable_did + breakdown.valid_verification_method;
  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  return { score, grade, breakdown };
}

function found(s, key) {
  const reason = (s.reasons || {})[key];
  return reason ? ` Found: ${reason}.` : "";
}

function fixIts(s) {
  const fixes = [];
  if (!s.has_did)
    fixes.push(
      "Publish a did:web. Run `vouch init --domain yourdomain.com` and serve the DID document at https://yourdomain.com/.well-known/did.json."
    );
  if (!s.has_verification_method)
    fixes.push(
      "Add a verificationMethod with your public key to the DID document, so others can verify what you sign."
    );
  if (!s.pq_ready)
    fixes.push(
      "Add an ML-DSA-44 key to your DID document (a Multikey verification method holding the 1312-byte public key, listed in assertionMethod) and sign with `sign_hybrid`, so credentials survive a future quantum break." +
        found(s, "pq_ready")
    );
  if (!s.has_revocation)
    fixes.push(
      "Publish a signed BitstringStatusListCredential at an https URL and list it in your DID document as a `BitstringStatusList` service, so a revocation can be published and discovered." +
        found(s, "has_revocation")
    );
  if (!s.has_card_identity) {
    const text =
      s.card_identity === "declared"
        ? "Sign your agent card with `sign_agent_card`, using a key in your DID document's assertionMethod, so a counterparty can verify the identity the card names."
        : "Publish an agent card at /.well-known/agent-card.json and sign it with `sign_agent_card`, using a key in your DID document's assertionMethod, so a counterparty can tie the card to a verifiable identity.";
    fixes.push(text + found(s, "card_identity"));
  }
  return fixes;
}

function badgeSvg(report) {
  const color = GRADE_COLORS[report.grade] || "#9ca3af";
  const label = "agent trust";
  const value = `${report.grade} (${report.score})`;
  const labelW = 7 * label.length + 16;
  const valueW = 7 * value.length + 16;
  const total = labelW + valueW;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" ` +
    `aria-label="${label}: ${value}">` +
    `<rect width="${total}" height="20" rx="3" fill="#555"/>` +
    `<rect x="${labelW}" width="${valueW}" height="20" rx="3" fill="${color}"/>` +
    `<rect x="${labelW}" width="4" height="20" fill="${color}"/>` +
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="${Math.round(labelW / 2)}" y="14" text-anchor="middle">${label}</text>` +
    `<text x="${Math.round(labelW + valueW / 2)}" y="14" text-anchor="middle">${value}</text>` +
    `</g></svg>`
  );
}
