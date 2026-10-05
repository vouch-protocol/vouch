// Generated from the Agent Trust Index sweep (agent-trust-index/data/results.json).
// Do not edit by hand; regenerate with scripts/extract-ati.py.

export const ATI_SUMMARY = {
  "total": 1846,
  "verifiable": 19,
  "cannot": 1827,
  "gradeA": 8,
  "pctVerifiable": 1.0,
  "pctCannot": 99.0,
  "pctCard": 6.4,
  "pctRev": 0.3,
  "pctPq": 0.1,
  "cardCount": 118,
  "revCount": 5,
  "pqCount": 2,
  "generated": "5 October 2026"
} as const;

export type AtiAgent = { grade: string; score: number; name: string; domains: string; method: string; did: string };

export const ATI_AGENTS: AtiAgent[] = [
  {
    "grade": "A",
    "score": 100,
    "name": "ai.councilof/gspc",
    "domains": "councilof.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:councilof.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.councilof/gspc-free",
    "domains": "councilof.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:councilof.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.inflowpay.app/inflow",
    "domains": "app.inflowpay.ai",
    "method": "did:web, P-256 (JWK)",
    "did": "did:web:app.inflowpay.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.pubfi/mcp",
    "domains": "mcp.pubfi.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:mcp.pubfi.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.snowdata/live-snow",
    "domains": "mcp.snowdata.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:mcp.snowdata.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.snowsure/snow",
    "domains": "www.snowsure.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.snowsure.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.universalagents/universal-agents",
    "domains": "universalagents.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:universalagents.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "ai.upgradeagent/upgrade-agent",
    "domains": "www.upgradeagent.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.upgradeagent.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.law.mcp/lawyer-search",
    "domains": "mcp.law.ai",
    "method": "did:web",
    "did": "did:web:mcp.law.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.law/lawyer-search",
    "domains": "mcp.law.ai",
    "method": "did:web",
    "did": "did:web:mcp.law.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.openhelm/deep-research",
    "domains": "mcp.openhelm.ai",
    "method": "did:web",
    "did": "did:web:mcp.openhelm.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.openhelm/dev-changes",
    "domains": "mcp.openhelm.ai",
    "method": "did:web",
    "did": "did:web:mcp.openhelm.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.openhelm/email-outreach",
    "domains": "mcp.openhelm.ai",
    "method": "did:web",
    "did": "did:web:mcp.openhelm.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.openhelm/monitoring",
    "domains": "mcp.openhelm.ai",
    "method": "did:web",
    "did": "did:web:mcp.openhelm.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.openhelm/openhelm",
    "domains": "mcp.openhelm.ai",
    "method": "did:web",
    "did": "did:web:mcp.openhelm.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.openhelm/seo-growth",
    "domains": "mcp.openhelm.ai",
    "method": "did:web",
    "did": "did:web:mcp.openhelm.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.rallyprop/gov-funding",
    "domains": "mcp.rallyprop.ai",
    "method": "did:web",
    "did": "did:web:mcp.rallyprop.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.stealthstack/discovery",
    "domains": "stealthstack.ai",
    "method": "did:web",
    "did": "did:web:stealthstack.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.websitepublisher/mcp",
    "domains": "mcp.websitepublisher.ai",
    "method": "did:web",
    "did": "did:web:mcp.websitepublisher.ai"
  }
];
