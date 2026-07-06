// Generated from the Agent Trust Index sweep (agent-trust-index/data/results.json).
// Do not edit by hand; regenerate with scripts/extract-ati.py.

export const ATI_SUMMARY = {
  "total": 15183,
  "verifiable": 181,
  "cannot": 15002,
  "gradeA": 77,
  "pctVerifiable": 1.2,
  "pctCannot": 98.8,
  "pctCard": 0.8,
  "pctRev": 0.5,
  "pctPq": 0.0,
  "cardCount": 129,
  "revCount": 81,
  "pqCount": 0,
  "generated": "6 July 2026"
} as const;

export type AtiAgent = { grade: string; score: number; name: string; domains: string; method: string; did: string };

export const ATI_AGENTS: AtiAgent[] = [
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
    "name": "ai.upgradeagent/upgrade-agent",
    "domains": "www.upgradeagent.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.upgradeagent.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.entidex/entidex",
    "domains": "entidex.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:entidex.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.hemmabo/hemmabo-mcp-server",
    "domains": "www.hemmabo.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.hemmabo.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "de.carbon-cashmere.api/crypto-intelligence",
    "domains": "api.carbon-cashmere.de",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:api.carbon-cashmere.de"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.feedoracle/compliance",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.AgentNOMOS/nomos-crossborder-broker",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.MarcinDudekDev/the-data-collector",
    "domains": "frog03-20494.wykr.es",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:frog03-20494.wykr.es"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.MarkovianProtocol/provenance",
    "domains": "api.quantsynth.net",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.quantsynth.net"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.craigmbrown/blindoracle",
    "domains": "craigmbrown.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:craigmbrown.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.feedoracle/feedoracle-macro-mcp",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.feedoracle/stablecoin-risk",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.mikeslone/skilimone-travel",
    "domains": "www.skilimone.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.skilimone.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.rnwy/mcp",
    "domains": "rnwy.com",
    "method": "did:web, P-256 (JWK)",
    "did": "did:web:rnwy.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.vdineshk/dominion-observatory",
    "domains": "dominion-observatory.sgdata.workers.dev",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:dominion-observatory.sgdata.workers.dev"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/accessoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/agentguard",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/aml",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/ampel",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/arbitrumoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/baseoracle",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/bnboracle",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/changeoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/cloudoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/conductor",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/contractoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/cybershield",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/dealoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/dependencyoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/dora",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/doraeventfabric",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/driftoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/ecommerceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/flareoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/flightoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/governanceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/healthguard",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/hederaoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/hoteloracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/incidentoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/insuranceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/invoiceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/iso20022oracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/joboracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/law",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/leadoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/macroooracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/memeoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/memoryoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/mica",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/newsoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/paymentoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/policyoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/predictionguard",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/predictoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/priceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/quantum",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/rankoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/registeroracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/reporting",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/researchoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/reserveoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/resilienceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/revieworacle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/riskoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/seooraclev2",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/shoporacle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/smartmoneyoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/solanaoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/suioracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/tlpt",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/tonoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/trustlayer",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/xrploracle",
    "domains": "feedoracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:feedoracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/yieldoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.tooloracle/zkevidenceoracle",
    "domains": "tooloracle.io",
    "method": "did:web, secp256k1 (JWK)",
    "did": "did:web:tooloracle.io"
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
    "name": "ai.rallyprop/gov-funding",
    "domains": "mcp.rallyprop.ai",
    "method": "did:web",
    "did": "did:web:mcp.rallyprop.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ai.websitepublisher/mcp",
    "domains": "mcp.websitepublisher.ai",
    "method": "did:web",
    "did": "did:web:mcp.websitepublisher.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "cc.thecolony/mcp-server",
    "domains": "thecolony.cc",
    "method": "did:web",
    "did": "did:web:thecolony.cc"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.ai2fin/ai2fin-tax-mcp",
    "domains": "taxmcp.ai2fin.com",
    "method": "did:web",
    "did": "did:web:taxmcp.ai2fin.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.anots/directory",
    "domains": "api.anots.com",
    "method": "did:web",
    "did": "did:web:api.anots.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.bushdrum/events",
    "domains": "bushdrum.com",
    "method": "did:web",
    "did": "did:web:bushdrum.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.eventescapes/event-escapes",
    "domains": "mcp.eventescapes.com",
    "method": "did:web",
    "did": "did:web:mcp.eventescapes.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.melvea/local-discovery",
    "domains": "mcp.melvea.com",
    "method": "did:web",
    "did": "did:web:mcp.melvea.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.tkawen/intelligence-gateway",
    "domains": "mcp.tkawen.com",
    "method": "did:web",
    "did": "did:web:mcp.tkawen.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ge.meni/admin",
    "domains": "api.meni.ge",
    "method": "did:web",
    "did": "did:web:api.meni.ge"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ge.meni/guest",
    "domains": "api.meni.ge",
    "method": "did:web",
    "did": "did:web:api.meni.ge"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.ahel/ahel",
    "domains": "mcp.ahel.io",
    "method": "did:web",
    "did": "did:web:mcp.ahel.io"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.dxbdata/dxb-data",
    "domains": "dxbdata.io",
    "method": "did:web",
    "did": "did:web:dxbdata.io"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.eventify/mcp-server",
    "domains": "amcp.eventify.io",
    "method": "did:web",
    "did": "did:web:amcp.eventify.io"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.0580iris-lang/x711-gas-station",
    "domains": "x711.io",
    "method": "did:web",
    "did": "did:web:x711.io"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.BricePourLe13/merx",
    "domains": "mcp.merxprotocol.eu",
    "method": "did:web",
    "did": "did:web:mcp.merxprotocol.eu"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.GaetanGermain/emotion-dictionary",
    "domains": "mcp.emotioninside.org",
    "method": "did:web",
    "did": "did:web:mcp.emotioninside.org"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.ShieldZCash/mcp",
    "domains": "shieldz.cash",
    "method": "did:web",
    "did": "did:web:shieldz.cash"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.Waysway-app/waysway",
    "domains": "api.waysway.com",
    "method": "did:web",
    "did": "did:web:api.waysway.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.astuto-ai/onelens-mcp",
    "domains": "mcp.onelens.cloud",
    "method": "did:web",
    "did": "did:web:mcp.onelens.cloud"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.jaymiller-cmg/dealsync-mcp-server",
    "domains": "dealsync-mcp-server.jaymiller.workers.dev",
    "method": "did:web",
    "did": "did:web:dealsync-mcp-server.jaymiller.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.kimny1143/hoo-mcp",
    "domains": "hoo-mcp.glasswerkskimny.workers.dev",
    "method": "did:web",
    "did": "did:web:hoo-mcp.glasswerkskimny.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/a11y-scorer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/agent-loop-detector",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/agent-memory",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/agent-trace-auditor",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/agent-workflow-engine",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-agent-scratchpad",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-budget-planner",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-changelog-writer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-cost-optimizer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-crawler-policy",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-eval",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-gateway",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-guardrails",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-model-router",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-prompt-optimizer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-provider-status",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-rate-limit-tracker",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/ai-token-counter",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-changelog-tracker",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-composition-gateway",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-contract-validator",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-diff-monitor",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-flow-analyzer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-landing",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-mock-server",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-payload-auditor",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-perf-analyzer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-request-deduplicator",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-response-cost-analyzer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/api-schema-drift-detector",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/blog",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/citation-verifier",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/claude-skill-validator",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/code-explainer",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/code-pattern-risk-scanner",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/color-palette",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/cron-collision-detector",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/cron-monitor",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/cron-parser",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/crypto-signal",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/data-transform",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/diff-patch-tools",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/domain-intel",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/email-validator",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/embedding-search",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/env-blueprint-validator",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/font-metadata",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/form-backend",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/govdata-korea",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/graphql-dos-shield",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/graphql-rest-bridge",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/interactive-api-playground",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/llm-output-quality-monitor",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.lazymac2x/smart-data-extractor",
    "domains": "api.lazy-mac.com",
    "method": "did:web",
    "did": "did:web:api.lazy-mac.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.majorelalexis-stack/maxia",
    "domains": "maxiaworld.app",
    "method": "did:web",
    "did": "did:web:maxiaworld.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.mambaventures/nzxplorer-mcp",
    "domains": "mcp.nzxplorer.co.nz",
    "method": "did:web",
    "did": "did:web:mcp.nzxplorer.co.nz"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.mikeslone/storylayer",
    "domains": "app.storylayer.ai",
    "method": "did:web",
    "did": "did:web:app.storylayer.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.mirabello-consultancy/mcp-server",
    "domains": "mcp.mirabelloconsultancy.com",
    "method": "did:web",
    "did": "did:web:mcp.mirabelloconsultancy.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexus-api-lab/chrono-mcp",
    "domains": "chrono-mcp.dokasukadon.workers.dev",
    "method": "did:web",
    "did": "did:web:chrono-mcp.dokasukadon.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexus-api-lab/codebook-mcp",
    "domains": "codebook-mcp.dokasukadon.workers.dev",
    "method": "did:web",
    "did": "did:web:codebook-mcp.dokasukadon.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexus-api-lab/digest-mcp",
    "domains": "digest-mcp.dokasukadon.workers.dev",
    "method": "did:web",
    "did": "did:web:digest-mcp.dokasukadon.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexus-api-lab/ident-mcp",
    "domains": "ident-mcp.dokasukadon.workers.dev",
    "method": "did:web",
    "did": "did:web:ident-mcp.dokasukadon.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexus-api-lab/textops-mcp",
    "domains": "textops-mcp.dokasukadon.workers.dev",
    "method": "did:web",
    "did": "did:web:textops-mcp.dokasukadon.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexusforge-tools/mcp-eu-finance",
    "domains": "api.nexusforge.tools",
    "method": "did:web",
    "did": "did:web:api.nexusforge.tools"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nikhilgogulwar/universalbench",
    "domains": "universalbench-mcp.penantiaglobal.workers.dev",
    "method": "did:web",
    "did": "did:web:universalbench-mcp.penantiaglobal.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.ogasurfproject-jpg/horizon-shield",
    "domains": "hs-mcp.oga-surf-project.workers.dev",
    "method": "did:web",
    "did": "did:web:hs-mcp.oga-surf-project.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.ogasurfproject-jpg/horizon-shield-webmcp",
    "domains": "hs-webmcp.oga-surf-project.workers.dev",
    "method": "did:web",
    "did": "did:web:hs-webmcp.oga-surf-project.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.quotor/home-auto-insurance-quotes",
    "domains": "mcp.quotor.ai",
    "method": "did:web",
    "did": "did:web:mcp.quotor.ai"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.rootsbymenda/pharma-regulatory",
    "domains": "pharma-mcp-server.rootsbybenda.workers.dev",
    "method": "did:web",
    "did": "did:web:pharma-mcp-server.rootsbybenda.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.ruvendors5-ops/content-intelligence-api",
    "domains": "content-intelligence-mcp.wajih-hyder55.workers.dev",
    "method": "did:web",
    "did": "did:web:content-intelligence-mcp.wajih-hyder55.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.squidcode/tapwatermap",
    "domains": "mcp.tapwatermap.com",
    "method": "did:web",
    "did": "did:web:mcp.tapwatermap.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hive-gate",
    "domains": "hivegate.onrender.com",
    "method": "did:web",
    "did": "did:web:hivegate.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hive-mcp-connector",
    "domains": "hive-mcp-connector.onrender.com",
    "method": "did:web",
    "did": "did:web:hive-mcp-connector.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hive-mcp-swap",
    "domains": "hive-mcp-swap.onrender.com",
    "method": "did:web",
    "did": "did:web:hive-mcp-swap.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hive-mcp-vault",
    "domains": "hive-mcp-vault.onrender.com",
    "method": "did:web",
    "did": "did:web:hive-mcp-vault.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hivebank",
    "domains": "hivebank.onrender.com",
    "method": "did:web",
    "did": "did:web:hivebank.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hivegate",
    "domains": "hivegate.onrender.com",
    "method": "did:web",
    "did": "did:web:hivegate.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.srotzin/hivetrust",
    "domains": "hivetrust.onrender.com",
    "method": "did:web",
    "did": "did:web:hivetrust.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "space.0/space0",
    "domains": "mcp.0.space",
    "method": "did:web",
    "did": "did:web:mcp.0.space"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "tech.tessa/tessa-mcp-server",
    "domains": "aiagent.tessa.tech",
    "method": "did:web",
    "did": "did:web:aiagent.tessa.tech"
  }
];
