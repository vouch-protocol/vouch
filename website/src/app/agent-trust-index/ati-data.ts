// Generated from the Agent Trust Index sweep (agent-trust-index/data/results.json).
// Do not edit by hand; regenerate with scripts/extract-ati.py.

export const ATI_SUMMARY = {
  "total": 28278,
  "verifiable": 538,
  "cannot": 27740,
  "gradeA": 382,
  "pctVerifiable": 1.9,
  "pctCannot": 98.1,
  "pctCard": 2.4,
  "pctRev": 1.4,
  "pctPq": 1.0,
  "cardCount": 677,
  "revCount": 389,
  "pqCount": 277,
  "generated": "7 September 2026"
} as const;

export type AtiAgent = { grade: string; score: number; name: string; domains: string; method: string; did: string };

export const ATI_AGENTS: AtiAgent[] = [
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
    "name": "ai.upgradeagent/upgrade-agent",
    "domains": "www.upgradeagent.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.upgradeagent.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "cloud.bisque/presentations",
    "domains": "bisque.cloud",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:bisque.cloud"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "co.itseasy/easy-mcp",
    "domains": "mcp.itseasy.co, www.itseasy.co",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.itseasy.co"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.aicontentdrop/ai-content-drop",
    "domains": "aicontentdrop.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:aicontentdrop.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.dominionobservatory/observatory",
    "domains": "dominionobservatory.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:dominionobservatory.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.eformogi/records-vault",
    "domains": "eformogi.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:eformogi.com"
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
    "name": "com.gadgethumans.api/api-hub",
    "domains": "api.gadgethumans.com",
    "method": "did:key, Ed25519",
    "did": "did:key:z6MkjdjQBbm4T3ZGeAuddRPzJs8KuKUbLBhaVkqML2z9hQjj"
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
    "name": "eco.reeco/reecopedia",
    "domains": "ia.reeco.eco",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:ia.reeco.eco"
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
    "name": "io.github.Abracadabrastartup/deusproof-mcp",
    "domains": "deusproof.com",
    "method": "did:key, key",
    "did": "did:key:z6Mk..."
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
    "name": "io.github.AgentTanuki/agent-guild",
    "domains": "agent-guild-5d5r.onrender.com",
    "method": "did:web, Ed25519 (Multikey)",
    "did": "did:web:agent-guild-5d5r.onrender.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.AgentTanuki/x402-payment-safety",
    "domains": "agent-guild-5d5r.onrender.com",
    "method": "did:web, Ed25519 (Multikey)",
    "did": "did:web:agent-guild-5d5r.onrender.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.CHANGCHINFU/mcp-gauge",
    "domains": "aeml-x402.zeabur.app",
    "method": "did:key, Ed25519",
    "did": "did:key:z6MkiGjPjUHhdcFaxe3Na22b2XpFEAc5Deih5fjxzSgHDm7h"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.CSOAI-ORG/gspc",
    "domains": "councilof.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:councilof.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/3d-meshweaver-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/3d-pallet-packing-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/4-20ma-analog-converter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/5g-core-nfv-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/90-percent-liquidity-advance-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/accounts-receivable-ledger-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/acoustic-reverb-simulator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/active-seat-metering-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/actuarial-life-table-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ad-fraud-click-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ad-sniper-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ad-spend-auditor-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/adsb-flight-tracker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/adversarial-prompt-shield-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/adversarial-suffix-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/aegis-policy-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/affiliate-link-attribution-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/afforestation-satellite-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-collision-preventer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-collusion-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-council-voting-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-credit-history-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-phone-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-reputation-zk-shield-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-slashing-protocol-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agent-telephony-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agentic-credit-line-issuer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agentic-ip-reputation-guard-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agentic-payroll-processor-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agentphone-ai-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/agile-sprint-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ai-fleet-cards-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ai-humanizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ai-right-to-opt-out-gate-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ai-safety-incident-logger-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ai-watermark-provenance-verifier-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/air-freight-waybill-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/airbnb-host-analyzer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/airbnb-smart-lock-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/airport-slot-allocator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ais-vessel-tracker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/akamai-bot-manager-bypass-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/albedo-delighter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/algorithmic-bias-scrubber-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/alibaba-supplier-intel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/aliexpress-dropship-finder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/amazon-price-tracker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ambient-occlusion-map-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ambisonics-b-format-encoder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/amr-fleet-dispatcher-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/angellist-startup-jobs-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/anomaly-detection-sentinel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/anonymous-credential-issuer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/anti-collusion-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/anti-sandwich-slippage-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/anti-stuxnet-plc-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/api-key-load-balancer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/api-quota-balancer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/api-rate-limit-enforcer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/apify-native-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/apollo-io-lead-gen-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/app-store-builder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/apple-vision-pro-optimizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ar-kit-blendshape-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ar-plane-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/arabic-calligraphy-parser-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/arbitration-fee-splitter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/architecture-dna-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ashrae-compliance-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/atomic-swap-coordinator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/audio-anonymizer-voice-scrambler-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/audio-description-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/audio-watermarking-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/auth-sentinel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/auto-telematics-policy-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/automated-amendment-negotiator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/automated-debt-collector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/automated-dpia-reporter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/automated-invoice-factoring-gate-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/automated-xml-invoicing-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/automation-weaver-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/autonomous-haul-truck-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/autonomous-tractor-path-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/aws-builder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/aws-key-revoker-webhook-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/b2b-contract-renewal-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/b2b-lead-closer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/b2b-legal-contract-parser-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/backhaul-empty-return-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/backrun-arbitrage-blocker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bacnet-ip-discovery-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/baidu-china-search-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bandwidth-micro-marketplace-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bankruptcy-asset-liquidator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/barcode-qr-decoder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/base-to-polygon-relayer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/base64-payload-decoder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/batch-request-bundler-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/battery-return-home-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/battery-swap-station-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/behance-portfolio-scraper-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/best-and-final-offer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bestbuy-deal-alerter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bft-swarm-vote-aggregator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bias-auditor-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bias-drift-monitor-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bid-clarification-q-and-a-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bidding-strategy-optimizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/binance-orderbook-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/binary-exploitation-shield-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bing-ai-results-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bio-data-parser-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bio-safe-audit-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/blendshape-mapper-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/blind-signature-voting-gate-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/blinded-macaroon-signer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bms-schedule-override-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/body-gesture-synthesizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/boids-flocking-algorithm-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/boiler-water-temp-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bone-rig-retargeter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/booking-hotel-prices-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/botnet-behavior-analyzer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/breach-of-contract-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/brotli-prompt-compressor-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bug-bounty-hunter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bulk-shipping-negotiator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bulletproofs-range-check-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/bunker-fuel-prices-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/can-bus-decoder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/captcha-bypass-attestation-gate-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/carbon-aware-inference-router-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/carbon-tax-auto-withholder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/carbon-tax-compliance-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cargo-insurance-broker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cargo-load-balancer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/catalog-engine-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ccs-chademo-protocol-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cdn-cache-warmup-agent-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cell-balancing-algorithm-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cell-tower-handoff-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/certora-rule-generator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cgroup-cpu-throttler-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chain-agnostic-escrow-reader-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chainalysis-aml-risk-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/charge-curve-optimizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chargeback-insurance-pool-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cheap-compute-sniper-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chembl-affinity-oracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chicago-grain-prices-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chiller-cop-efficiency-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chinese-scroll-digitizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chirpstack-lorawan-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/chroot-filesystem-jail-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/claim-denial-appeal-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/clarity-gate-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/clause-risk-score-evaluator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/clawback-prevention-sentinel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cleancode-ai-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/clinical-phase-analyzer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/clinical-trial-matcher-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cloth-physics-solver-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cloudflare-turnstile-bypass-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cloudscale-sim-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/co2-inference-calculator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cobot-safety-zone-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/codevulnerability-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/coingecko-historical-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/coinmarketcap-prices-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cold-chain-reefer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cold-vault-migrator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/collusion-detection-sentinel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/commodity-futures-oracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/computer-vision-damage-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/computer-vision-defect-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/conflict-minerals-audit-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/consensus-voter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/container-ship-router-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/context-deduplicator-oracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/context-targeting-oracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/context-window-optimizer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/context-window-overflow-router-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/contractoracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cookie-stuffing-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cooperative-dividend-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cooperative-swarm-incentiver-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/copyrighted-music-fingerprint-matcher-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/coq-proof-assistant-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/coral-tpu-delegate-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/corporate-kyc-registry-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/corporate-tax-bracket-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/corporate-tax-jurisdiction-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/corporate-treasury-multisig-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cost-optimal-model-selector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/counter-offer-bot-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cpm-cpa-arbitrage-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/craigslist-local-deals-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/credit-risk-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crispr-cas9-offtarget-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crop-pest-diagnostic-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crop-yield-insurance-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-chain-contract-relayer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-chain-escrow-bridge-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-chain-l402-verifier-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-company-agent-dispute-court-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-device-attribution-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-docking-coordinator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-modal-embedding-aligner-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cross-shard-state-sync-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crunchbase-funding-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crypto-capital-gains-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crypto-dispute-mediator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crypto-price-oracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/crypto-tax-loss-harvester-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cuneiform-tablet-reader-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/customs-clearance-bot-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/customs-duty-calculator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/cyber-breach-liability-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/damaged-text-inpainter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dan-jailbreak-filter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dark-pool-liquidity-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/darknet-address-filter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/darkweb-breach-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/darkweb-threat-feed-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/darwin-ideation-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/data-diode-unidirectional-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/data-observability-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/data-poisoning-detector-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/datadome-bypass-agent-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/datahealth-observer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ddos-mitigation-shield-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/ddos-scrubbing-proxy-node-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/deadlock-resolver-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/debt-collection-bot-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/decentralized-credit-bureau-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/deepfake-lens-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/deepfake-sentinel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/deepsort-object-tracker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/deepvoice-guard-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/default-probability-model-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/default-risk-oracle-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/defi-sentinel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/defi-yield-tax-reporter-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/defillama-tvl-tracker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/delegatecall-vulnerability-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/depreciation-value-calculator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/depth-map-estimator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/devrel-amplifier-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dex-arbitrage-router-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dhl-shipment-tracker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dialogue-distiller-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dicom-imaging-analyzer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/diesel-anti-theft-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dilithium-signature-verifier-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/direct-air-capture-bidder-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/discount-coupon-validator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/displacement-height-map-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dispute-penalty-calculator-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/distributed-lock-service-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dnp3-protocol-analyzer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/docdigest-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dockerfile-credential-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/document-layout-analyzer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dolby-atmos-metadata-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/domain-authority-checker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/domain-dnssec-trust-verifier-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/draco-mesh-compressor-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/drayage-port-scheduler-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/dribbble-designer-intel-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/drill-core-logger-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/driver-fatigue-camera-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/drone-crop-sprayer-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/drone-delivery-router-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/drone-map-stitcher-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/drug-interaction-checker-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.Evozim/duckduckgo-privacy-search-mcp",
    "domains": "api.m2mcent.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.m2mcent.com"
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
    "name": "io.github.Vortx-AI/emem",
    "domains": "emem.dev",
    "method": "did:web, Ed25519 (Multikey)",
    "did": "did:web:emem.dev"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.XRPDomains/xrpname-mcp-server",
    "domains": "xrpdomains.xyz",
    "method": "did:web, X25519 (JWK)",
    "did": "did:web:xrpdomains.xyz"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.agentready-market/audit",
    "domains": "www.agentready.market",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:www.agentready.market"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.ariffazil/arifos",
    "domains": "arifos.arif-fazil.com",
    "method": "did:web, Ed25519 (Multikey)",
    "did": "did:web:arifos.arif-fazil.com"
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
    "name": "io.github.moelayyan90/xguard",
    "domains": "xguardgate.com",
    "method": "did:web, P-256 (JWK)",
    "did": "did:web:xguardgate.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.moelayyan90/xguard-control-plane",
    "domains": "api.xguardgate.com",
    "method": "did:web, P-256 (JWK)",
    "did": "did:web:api.xguardgate.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/ibm-x402-mcp-remote",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/three.ws",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/threews-3d-studio",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/threews-3d-studio-free",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/threews-agent",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/threews-pumpfun",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.nirholas/threews-x402-bazaar",
    "domains": "three.ws",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:three.ws"
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
    "name": "io.github.rudedoggg/ace-memory",
    "domains": "ais.agentsandswarms.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:ais.agentsandswarms.ai"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "io.github.yonatangross/orchestkit",
    "domains": "orchestkit.yonyon.ai",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:orchestkit.yonyon.ai"
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
    "grade": "A",
    "score": 100,
    "name": "store.scvd/general-store",
    "domains": "scvd.store",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:scvd.store"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "tech.vrsai/mcp",
    "domains": "api.vrsai.tech",
    "method": "did:web, P-256 (JWK)",
    "did": "did:web:api.vrsai.tech"
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
    "name": "app.steadywrk/mcp-dispatch",
    "domains": "steadywrk.app",
    "method": "did:web",
    "did": "did:web:steadywrk.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ar.com.muovi/mcp-server",
    "domains": "mcp.muovi.com.ar",
    "method": "did:web",
    "did": "did:web:mcp.muovi.com.ar"
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
    "name": "com.530amodel/calculator",
    "domains": "mcp.530amodel.com",
    "method": "did:web",
    "did": "did:web:mcp.530amodel.com"
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
    "name": "com.angelmoncada/consulting",
    "domains": "mcp.angelmoncada.com",
    "method": "did:web",
    "did": "did:web:mcp.angelmoncada.com"
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
    "name": "com.dribba/dribba",
    "domains": "dribba.com",
    "method": "did:web",
    "did": "did:web:dribba.com"
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
    "name": "com.ghostavo/retail-media-measurement",
    "domains": "mcp.ghostavo.com",
    "method": "did:web",
    "did": "did:web:mcp.ghostavo.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.greencalculus/api",
    "domains": "mcp.greencalculus.com",
    "method": "did:web",
    "did": "did:web:mcp.greencalculus.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.handsofflinks/link-followability",
    "domains": "handsofflinks-mcp.lipmichal.workers.dev",
    "method": "did:web",
    "did": "did:web:handsofflinks-mcp.lipmichal.workers.dev"
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
    "name": "com.neurobird/search",
    "domains": "search.neurobird.com",
    "method": "did:web",
    "did": "did:web:search.neurobird.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.neuronto/agents-tools-search-discovery-ard-registry",
    "domains": "neuronto.com",
    "method": "did:web",
    "did": "did:web:neuronto.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.payforapi/saymon-ru-data-api",
    "domains": "payforapi.com",
    "method": "did:web",
    "did": "did:web:payforapi.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.secondopinionx402/second-opinion",
    "domains": "secondopinionx402.com",
    "method": "did:web",
    "did": "did:web:secondopinionx402.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.shipshapedata/shipshape-data",
    "domains": "shipshapedata.com",
    "method": "did:web",
    "did": "did:web:shipshapedata.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.shipshapedata/shipshape-data-docs",
    "domains": "shipshapedata.com",
    "method": "did:web",
    "did": "did:web:shipshapedata.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.thefomite/fomite",
    "domains": "thefomite.com",
    "method": "did:web",
    "did": "did:web:thefomite.com"
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
    "name": "com.tools-berry/paycheck",
    "domains": "mcp.tools-berry.com",
    "method": "did:web",
    "did": "did:web:mcp.tools-berry.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.toolsthatrank/serp-metrics",
    "domains": "toolsthatrank-mcp.lipmichal.workers.dev",
    "method": "did:web",
    "did": "did:web:toolsthatrank-mcp.lipmichal.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "dev.fly.obol-x402/obol",
    "domains": "obol-mcp.fly.dev",
    "method": "did:web",
    "did": "did:web:obol-mcp.fly.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "dev.fly.solidus-x402/solidus",
    "domains": "solidus-mcp.fly.dev",
    "method": "did:web",
    "did": "did:web:solidus-mcp.fly.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "dev.jobspipe/mcp",
    "domains": "jobspipe.dev",
    "method": "did:web",
    "did": "did:web:jobspipe.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "dev.workers.3labsio.policy-gate/policy-gate",
    "domains": "policy-gate.3labsio.workers.dev",
    "method": "did:web",
    "did": "did:web:policy-gate.3labsio.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "eco.unreasonable/mcp",
    "domains": "unreasonable.eco",
    "method": "did:web",
    "did": "did:web:unreasonable.eco"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "eu.ansvar/us-law-mcp",
    "domains": "us-law-mcp.vercel.app",
    "method": "did:web",
    "did": "did:web:us-law-mcp.vercel.app"
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
    "name": "io.github.0xDanielLopez/phishunt",
    "domains": "mcp.phishunt.io",
    "method": "did:web",
    "did": "did:web:mcp.phishunt.io"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.0xDanielLopez/tweetfeed",
    "domains": "mcp.tweetfeed.live",
    "method": "did:web",
    "did": "did:web:mcp.tweetfeed.live"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.AEGISGOVDAO/aegisgov-contracts-mcp",
    "domains": "aegisgov-contracts.vercel.app",
    "method": "did:web",
    "did": "did:web:aegisgov-contracts.vercel.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.ArtyKOMarkets/warda",
    "domains": "mcp.wardaprotocol.com",
    "method": "did:web",
    "did": "did:web:mcp.wardaprotocol.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.Br0ski777/image-generator",
    "domains": "image-generator-x402-production.up.railway.app",
    "method": "did:web",
    "did": "did:web:image-generator-x402-production.up.railway.app"
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
    "name": "io.github.Elemzir/kta-oracle",
    "domains": "kta-oracle.vercel.app",
    "method": "did:web",
    "did": "did:web:kta-oracle.vercel.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.Evozim/organic-text",
    "domains": "organic-text-mcp.vercel.app",
    "method": "did:web",
    "did": "did:web:organic-text-mcp.vercel.app"
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
    "name": "io.github.JadeSparrow/sqlai-dev-sql-verifier",
    "domains": "mcp.sqlai.dev",
    "method": "did:web",
    "did": "did:web:mcp.sqlai.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.Larshiensch99/flowvolt",
    "domains": "flowvolt-strike-engine.vercel.app",
    "method": "did:web",
    "did": "did:web:flowvolt-strike-engine.vercel.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.MastadoonPrime/agent-memory",
    "domains": "agent-memory-production-6506.up.railway.app",
    "method": "did:web",
    "did": "did:web:agent-memory-production-6506.up.railway.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.MastadoonPrime/sylex-search",
    "domains": "mcp-server-production-38c9.up.railway.app",
    "method": "did:web",
    "did": "did:web:mcp-server-production-38c9.up.railway.app"
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
    "name": "io.github.TencentCloudBase/cloudbase-mcp",
    "domains": "tcb-api.cloud.tencent.com",
    "method": "did:web",
    "did": "did:web:tcb-api.cloud.tencent.com"
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
    "name": "io.github.ahmedEid1/atlas-research",
    "domains": "atlas-sooty-delta.vercel.app",
    "method": "did:web",
    "did": "did:web:atlas-sooty-delta.vercel.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.anmols/frontdesko-mcp",
    "domains": "mcp.frontdesko.app",
    "method": "did:web",
    "did": "did:web:mcp.frontdesko.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.apayne1987-droid/payne-machine-revenue",
    "domains": "payne-machine-revenue-mcp.apayne1987.workers.dev",
    "method": "did:web",
    "did": "did:web:payne-machine-revenue-mcp.apayne1987.workers.dev"
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
    "name": "io.github.benseverndev-oss/goldenpipe",
    "domains": "goldenpipe-mcp-production.up.railway.app",
    "method": "did:web",
    "did": "did:web:goldenpipe-mcp-production.up.railway.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.benseverndev-oss/infermap",
    "domains": "infermap-mcp-production.up.railway.app",
    "method": "did:web",
    "did": "did:web:infermap-mcp-production.up.railway.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.danielasalgadov/fiscal",
    "domains": "menteorama-fiscal-mcp.menteorama.workers.dev",
    "method": "did:web",
    "did": "did:web:menteorama-fiscal-mcp.menteorama.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.hycore220/k-work-trust",
    "domains": "k-work-trust-api.fly.dev",
    "method": "did:web",
    "did": "did:web:k-work-trust-api.fly.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.imoldyoung/e-invoice",
    "domains": "e-invoice-mcp.601096790.workers.dev",
    "method": "did:web",
    "did": "did:web:e-invoice-mcp.601096790.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.jackfieldman/buildercheck",
    "domains": "buildercheck-mcp.jaco-veldsman.workers.dev",
    "method": "did:web",
    "did": "did:web:buildercheck-mcp.jaco-veldsman.workers.dev"
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
    "name": "io.github.jmrplens/gitlab-mcp-server",
    "domains": "gitlab-mcp-server.fly.dev, {host}",
    "method": "did:web",
    "did": "did:web:gitlab-mcp-server.fly.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.johnanleitner1-Coder/lastminute-booking",
    "domains": "web-production-dc74b.up.railway.app",
    "method": "did:web",
    "did": "did:web:web-production-dc74b.up.railway.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.jongko54/web-embedding",
    "domains": "webembedding-mcp.vercel.app",
    "method": "did:web",
    "did": "did:web:webembedding-mcp.vercel.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.kadopi/x402-mcp-starter",
    "domains": "x402-mcp-starter.kadopi.workers.dev",
    "method": "did:web",
    "did": "did:web:x402-mcp-starter.kadopi.workers.dev"
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
    "name": "io.github.kindrat86/vc-deal-flow-signal",
    "domains": "signals.gitdealflow.com",
    "method": "did:web",
    "did": "did:web:signals.gitdealflow.com"
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
    "name": "io.github.mambaventures/nzxplorer-mcp",
    "domains": "mcp.nzxplorer.co.nz",
    "method": "did:web",
    "did": "did:web:mcp.nzxplorer.co.nz"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.michu5696/agora402",
    "domains": "agora402.fly.dev",
    "method": "did:web",
    "did": "did:web:agora402.fly.dev"
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
    "name": "io.github.nach-dakwale/domaincheckr",
    "domains": "domaincheckr.fly.dev",
    "method": "did:web",
    "did": "did:web:domaincheckr.fly.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nao1234g/calibration-routing",
    "domains": "nowpattern.com",
    "method": "did:web",
    "did": "did:web:nowpattern.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.nexus-mcp-infra/useful-data-source-for-agents-doing-product-price-sdk",
    "domains": "useful-data-source-for-agents-production.up.railway.app",
    "method": "did:web",
    "did": "did:web:useful-data-source-for-agents-production.up.railway.app"
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
    "name": "io.github.ogasurfproject-jpg/horizon-shield-webmcp",
    "domains": "hs-webmcp.oga-surf-project.workers.dev",
    "method": "did:web",
    "did": "did:web:hs-webmcp.oga-surf-project.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.pain2hustle/cloudflare-ops-mcp",
    "domains": "cfops.nothingunseen.com",
    "method": "did:web",
    "did": "did:web:cfops.nothingunseen.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.r2hb-assistant/propscorer",
    "domains": "mcp.propscorer.com",
    "method": "did:web",
    "did": "did:web:mcp.propscorer.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.rccola990-cloud/x402-agent-store",
    "domains": "store.agentexchange.work",
    "method": "did:web",
    "did": "did:web:store.agentexchange.work"
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
    "name": "io.github.tankstellen/firmenliste-mcp",
    "domains": "firmenliste-mcp.cf-firmenliste.workers.dev",
    "method": "did:web",
    "did": "did:web:firmenliste-mcp.cf-firmenliste.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.tony8713/casa",
    "domains": "casa-agents.fly.dev",
    "method": "did:web",
    "did": "did:web:casa-agents.fly.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.vassiliylakhonin/agenda-intelligence-md",
    "domains": "agenda-intelligence-a2a.vassiliy-lakhonin.workers.dev, agent-output-verification-a2a.vassiliy-lakhonin.workers.dev, agentic-interaction-trust-a2a.vassiliy-lakhonin.workers.dev, cis-secondary-sanctions-a2a.vassiliy-lakhonin.workers.dev, corridor-sanctions-assistant-a2a.vassiliy-lakhonin.workers.dev, critical-minerals-due-diligence-a2a.vassiliy-lakhonin.workers.dev, dual-use-technology-export-a2a.vassiliy-lakhonin.workers.dev, gulf-maritime-exposure-a2a.vassiliy-lakhonin.workers.dev, kazakhstan-market-entry-readiness-a2a.vassiliy-lakhonin.workers.dev, middle-corridor-deal-risk-gate-a2a.vassiliy-lakhonin.workers.dev",
    "method": "did:web",
    "did": "did:web:agenda-intelligence-a2a.vassiliy-lakhonin.workers.dev"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.vndpal/sentinelscan-cloud-mcp",
    "domains": "sentinelscan-cloud-mcp.vercel.app",
    "method": "did:web",
    "did": "did:web:sentinelscan-cloud-mcp.vercel.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.github.yyphilo/openfab",
    "domains": "openfab-22100483453.us-central1.run.app",
    "method": "did:web",
    "did": "did:web:openfab-22100483453.us-central1.run.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "io.sslip.128.221.67.45.agent-exec/agent-exec",
    "domains": "agent-exec.45.67.221.128.sslip.io",
    "method": "did:web",
    "did": "did:web:agent-exec.45.67.221.128.sslip.io"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "net.csclear/wire",
    "domains": "mcp.csclear.net",
    "method": "did:web",
    "did": "did:web:mcp.csclear.net"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "net.glyt/glyt",
    "domains": "glyt.net",
    "method": "did:web",
    "did": "did:web:glyt.net"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "org.aviationhs/private-jet-charter",
    "domains": "mcp.aviationhs.org",
    "method": "did:web",
    "did": "did:web:mcp.aviationhs.org"
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
    "name": "space.mysoma/kpn",
    "domains": "persona-mcp-server.onrender.com",
    "method": "did:web",
    "did": "did:web:persona-mcp-server.onrender.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "tech.tessa/tessa-mcp-server",
    "domains": "aiagent.tessa.tech",
    "method": "did:web",
    "did": "did:web:aiagent.tessa.tech"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "tools.extrabold/gridfinity",
    "domains": "mcp.extrabold.tools",
    "method": "did:web",
    "did": "did:web:mcp.extrabold.tools"
  }
];
