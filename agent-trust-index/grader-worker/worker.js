/**
 * Agent Trust Index grader, as a Cloudflare Worker.
 *
 * The browser cannot fetch an arbitrary domain's did.json (CORS), so the live
 * "grade your agent" form on the Index page calls this worker, which resolves
 * the DID server-side and returns a grade. It is a faithful port of the Python
 * `vouch grade` scoring: 60 points for a resolvable did:web, 40 for a usable
 * verification method, with post-quantum, revocation, and agent-card identity
 * reported as extra signals that do not change the score.
 *
 * Endpoints:
 *   GET /grade?domain=example.com   -> JSON report
 *   GET /badge?domain=example.com   -> SVG badge
 *
 * No secrets, no storage. Public, read-only grading.
 */

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

async function getJson(u) {
  try {
    const resp = await fetch(u, { redirect: "follow", signal: AbortSignal.timeout(6000) });
    if (resp.status !== 200) return null;
    return await resp.json();
  } catch {
    return null;
  }
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
  };

  const didDoc = await getJson(`https://${domain}/.well-known/did.json`);
  if (didDoc && typeof didDoc === "object") {
    signals.has_did = true;
    signals.did = `did:web:${domain}`;

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

    if (Array.isArray(didDoc.service) && didDoc.service.length > 0) {
      signals.has_revocation = true;
    }
    const blob = JSON.stringify(didDoc).toLowerCase();
    if (blob.includes("ml-dsa") || blob.includes("mldsa") || blob.includes("dilithium")) {
      signals.pq_ready = true;
    }
  }

  const card =
    (await getJson(`https://${domain}/.well-known/agent.json`)) ||
    (await getJson(`https://${domain}/.well-known/agent-card.json`));
  if (card && typeof card === "object") {
    const blob = JSON.stringify(card).toLowerCase();
    if (blob.includes("did:") || blob.includes("signature")) signals.has_card_identity = true;
  }

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
      "Add a post-quantum key (ML-DSA-44) alongside your Ed25519 key and sign with `sign_hybrid`."
    );
  if (!s.has_revocation)
    fixes.push(
      "Publish a service or revocation endpoint in your DID document, so a compromised key can be revoked."
    );
  if (!s.has_card_identity)
    fixes.push(
      "Reference your DID in your agent card (/.well-known/agent.json), so a counterparty can tie the card to a verifiable identity."
    );
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
