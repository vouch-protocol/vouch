/**
 * Agent Trust Index, self-check grader (Cloudflare Worker).
 *
 * GET /grade?domain=feedoracle.io
 *
 * The browser page cannot fetch a stranger's did.json directly because of CORS,
 * so the Worker does the did:web fetch server-side and returns the score, the
 * breakdown, and fix-it guidance as JSON. The scoring logic mirrors
 * ati/core.py exactly: 60 points for a resolvable did:web, 40 for a usable
 * verification key, plus bonus signals (post-quantum, revocation, signed card)
 * that the breakdown surfaces.
 *
 * Run locally with:  wrangler dev    (do not deploy)
 */

const GRADE_COLORS = {
  A: "#2f7d4f",
  B: "#3fa05f",
  C: "#9a7d1f",
  D: "#b56b28",
  F: "#9b3b44",
};

// Mirrors ati.core CHECKS / grade.py. Order runs foundational -> advanced.
const CHECKS = [
  {
    key: "has_did",
    points: 60,
    scored: true,
    label: "Resolvable identity (did:web)",
    pass_msg: "Your domain publishes a DID document that resolves.",
    fix_title: "Publish a DID document",
    fix: "Publish a DID document at https://{domain}/.well-known/did.json so anyone can look up who your agent is. This is the single biggest thing you can do: it is worth 60 of the 100 points.",
  },
  {
    key: "has_verification_method",
    points: 40,
    scored: true,
    label: "Usable verification key",
    pass_msg: "Your identity document carries a public key others can verify against.",
    fix_title: "Add a verification key",
    fix: "Add a verification method with a public key to your DID document, in either JWK or Multikey form. Without a key, others can find your identity but cannot check a signature against it. Worth 40 points.",
  },
  {
    key: "pq_ready",
    points: 0,
    scored: false,
    label: "Post-quantum ready",
    pass_msg: "Your key set includes a post-quantum key (ML-DSA).",
    fix_title: "Add a post-quantum key",
    fix: "Add an ML-DSA-44 key alongside your Ed25519 key so your identity still holds up once quantum computers can break today's signatures. This is a forward-looking signal the Index will start rewarding.",
  },
  {
    key: "has_revocation",
    points: 0,
    scored: false,
    label: "Service endpoint (revocation, MCP, A2A)",
    pass_msg: "Your DID document publishes a service endpoint others can reach.",
    fix_title: "Publish a service endpoint",
    fix: "Add a service entry to your DID document. The highest value one is a revocation status list (for example BitstringStatusList) so others can confirm your agent's authority has not been pulled, but MCP and A2A endpoints count too.",
  },
  {
    key: "has_card_identity",
    points: 0,
    scored: false,
    label: "Signed agent card",
    pass_msg: "Your agent card carries identity (a DID or a signature).",
    fix_title: "Carry identity in your agent card",
    fix: "Reference your DID or include a signature in your agent card at https://{domain}/.well-known/agent.json so tools that read the card can tie it back to your verifiable identity.",
  },
];

const USER_AGENT = "agent-trust-index-grader/0.1 (+https://vouch-protocol.com)";

function normalizeDomain(value) {
  value = (value || "").trim();
  if (value.startsWith("did:web:")) {
    let rest = value.slice("did:web:".length);
    let host = rest.split(":")[0];
    return host.replace(/%3A/gi, ":");
  }
  if (value.includes("://")) value = value.split("://")[1];
  value = value.split("/")[0];
  value = value.split("?")[0];
  return value;
}

async function getJson(url, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
      signal: controller.signal,
      redirect: "follow",
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Resolve one domain and gather every trust signal we can observe.
 * Mirrors ati.core.resolve_domain: a did:web document is the headline, then we
 * read the raw document for key type, post-quantum readiness, and a service
 * (revocation) entry, and finally look for an agent card that carries identity.
 */
async function resolveDomain(domain) {
  const sig = {
    has_did: false,
    has_verification_method: false,
    did: null,
    method: null,
    pq_ready: false,
    has_revocation: false,
    has_card_identity: false,
  };

  const doc = await getJson(`https://${domain}/.well-known/did.json`);
  if (doc && typeof doc === "object") {
    sig.has_did = true;
    sig.did = `did:web:${domain}`;

    // Find the first verification method and read its key form.
    const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
    let foundKey = false;
    for (const vm of vms) {
      if (vm && typeof vm === "object") {
        if (vm.publicKeyJwk && typeof vm.publicKeyJwk === "object") {
          foundKey = true;
          const jwk = vm.publicKeyJwk;
          const label = jwk.crv || jwk.kty || "key";
          sig.method = `did:web, ${label} (JWK)`;
          break;
        }
        if (vm.publicKeyMultibase) {
          foundKey = true;
          sig.method = "did:web, key (Multikey)";
          break;
        }
      }
    }
    sig.has_verification_method = foundKey;

    // Service entry => a revocation/status endpoint is published.
    if (Array.isArray(doc.service) && doc.service.length > 0) {
      sig.has_revocation = true;
    }

    // Post-quantum if the document mentions an ML-DSA / Dilithium key anywhere.
    const blob = JSON.stringify(doc).toLowerCase();
    if (blob.includes("ml-dsa") || blob.includes("mldsa") || blob.includes("dilithium")) {
      sig.pq_ready = true;
    }
  }

  // A second discovery signal: an agent card that carries identity.
  const card =
    (await getJson(`https://${domain}/.well-known/agent.json`)) ||
    (await getJson(`https://${domain}/.well-known/agent-card.json`));
  if (card && typeof card === "object") {
    const raw = JSON.stringify(card);
    if (raw.toLowerCase().includes("did:") || raw.toLowerCase().includes("signature")) {
      sig.has_card_identity = true;
    }
    // Catch DIDs the card declares that do not live at the bare-domain
    // .well-known: a path-based did:web (host/path/did.json) or a did:key.
    // Mirrors ati.core so the live Index and this self-check agree.
    if (!sig.has_verification_method) {
      const dids = [...new Set(raw.match(/did:(?:web|key):[A-Za-z0-9._:%#-]+/g) || [])];
      for (const found of dids) {
        const did = found.split("#")[0];
        if (did === `did:web:${domain}`) continue;
        if (did.startsWith("did:key:")) {
          sig.has_did = true;
          sig.has_verification_method = true;
          sig.did = did;
          sig.method = "did:key";
          break;
        }
        if (did.startsWith("did:web:")) {
          const segs = did.slice("did:web:".length).split(":").map(decodeURIComponent);
          const host = segs.shift();
          const docUrl = segs.length
            ? `https://${host}/${segs.join("/")}/did.json`
            : `https://${host}/.well-known/did.json`;
          const pdoc = await getJson(docUrl);
          if (pdoc && typeof pdoc === "object") {
            sig.has_did = true;
            sig.did = did;
            const vms = Array.isArray(pdoc.verificationMethod) ? pdoc.verificationMethod : [];
            for (const vm of vms) {
              if (vm && typeof vm === "object") {
                if (vm.publicKeyJwk) {
                  const jwk = vm.publicKeyJwk;
                  sig.has_verification_method = true;
                  sig.method = `did:web (path), ${jwk.crv || jwk.kty || "key"} (JWK)`;
                  break;
                }
                if (vm.publicKeyMultibase) {
                  sig.has_verification_method = true;
                  sig.method = "did:web (path), key (Multikey)";
                  break;
                }
              }
            }
            if (sig.has_verification_method) break;
          }
        }
      }
    }
  }

  return sig;
}

// Mirrors ati.core.score.
function score(signals) {
  const breakdown = {
    resolvable_did: signals.has_did ? 60 : 0,
    valid_verification_method: signals.has_verification_method ? 40 : 0,
  };
  const points = breakdown.resolvable_did + breakdown.valid_verification_method;
  let grade;
  if (points >= 90) grade = "A";
  else if (points >= 75) grade = "B";
  else if (points >= 60) grade = "C";
  else if (points >= 40) grade = "D";
  else grade = "F";
  return { score: points, grade, breakdown };
}

function evaluate(domain, signals) {
  const scored = score(signals);
  const breakdown = [];
  const fixes = [];
  for (const check of CHECKS) {
    const passed = Boolean(signals[check.key]);
    breakdown.push({
      label: check.label,
      passed,
      scored: check.scored,
      points: check.scored && passed ? check.points : 0,
      max_points: check.scored ? check.points : 0,
      message: passed ? check.pass_msg : check.fix.replace("{domain}", domain),
    });
    if (!passed) {
      fixes.push({
        title: check.fix_title,
        detail: check.fix.replace("{domain}", domain),
        points: check.scored ? check.points : 0,
      });
    }
  }
  return {
    domain,
    did: signals.did || `did:web:${domain}`,
    score: scored.score,
    grade: scored.grade,
    badge_color: GRADE_COLORS[scored.grade] || "#7c2d3a",
    badge_url: `https://index.vouch-protocol.com/badge.svg?domain=${encodeURIComponent(domain)}`,
    method: signals.method,
    signals,
    breakdown,
    fixes,
  };
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

// A live, embeddable SVG badge that shows a domain's current grade. Shields-style
// two-part pill, colored to match the public Index.
function badgeSvg(grade) {
  const color = GRADE_COLORS[grade] || "#7c2d3a";
  const label = "agent trust";
  const lw = 78;
  const vw = 26;
  const h = 20;
  const w = lw + vw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="${label}: ${grade}">
<title>${label}: ${grade}</title>
<rect width="${w}" height="${h}" rx="3" fill="#0f172a"/>
<rect x="${lw}" width="${vw}" height="${h}" rx="3" fill="${color}"/>
<rect x="${lw}" width="4" height="${h}" fill="${color}"/>
<g fill="#ffffff" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11" text-anchor="middle">
<text x="${lw / 2}" y="14">${label}</text>
<text x="${lw + vw / 2}" y="14" font-weight="bold">${grade}</text>
</g>
</svg>`;
}

export default {
  async fetch(request) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }
    const url = new URL(request.url);

    if (url.pathname === "/badge.svg") {
      const domain = normalizeDomain(url.searchParams.get("domain") || "");
      let grade = "F";
      if (domain && domain.includes(".")) {
        try {
          grade = score(await resolveDomain(domain)).grade;
        } catch (e) {
          grade = "F";
        }
      }
      return new Response(badgeSvg(grade), {
        headers: {
          "Content-Type": "image/svg+xml; charset=utf-8",
          "Cache-Control": "max-age=3600",
          ...CORS,
        },
      });
    }

    if (url.pathname !== "/grade") {
      return json(
        { error: "Not found. Try GET /grade?domain=example.com or GET /badge.svg?domain=example.com" },
        404
      );
    }
    const raw = url.searchParams.get("domain");
    if (!raw) {
      return json({ error: "Missing ?domain= parameter." }, 400);
    }
    const domain = normalizeDomain(raw);
    if (!domain || !domain.includes(".")) {
      return json({ error: "Could not read a valid domain from that input." }, 400);
    }
    try {
      const signals = await resolveDomain(domain);
      return json(evaluate(domain, signals));
    } catch (e) {
      return json({ error: "Could not resolve that domain.", detail: String(e) }, 502);
    }
  },
};
