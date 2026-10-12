// Generated from the Agent Trust Index sweep (agent-trust-index/data/results.json).
// Do not edit by hand; regenerate with scripts/extract-ati.py.

export const ATI_SUMMARY = {
  "total": 10707,
  "verifiable": 78,
  "cannot": 10629,
  "gradeA": 25,
  "pctVerifiable": 0.7,
  "pctCannot": 99.3,
  "pctCard": 3.1,
  "pctRev": 0.3,
  "pctPq": 0.0,
  "cardCount": 334,
  "revCount": 32,
  "pqCount": 2,
  "generated": "12 October 2026"
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
    "grade": "A",
    "score": 100,
    "name": "br.com.wikijuridica/acervo-juridico",
    "domains": "wikijuridica.com.br",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:wikijuridica.com.br"
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
    "name": "com.agentavow/agentavow-trust",
    "domains": "agentavow.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:agentavow.com"
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
    "name": "com.gadgethumans/api-hub",
    "domains": "api.gadgethumans.com",
    "method": "did:key, Ed25519",
    "did": "did:key:z6MkjdjQBbm4T3ZGeAuddRPzJs8KuKUbLBhaVkqML2z9hQjj"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.getacqpath/acqpath",
    "domains": "api.getacqpath.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:api.getacqpath.com"
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
    "name": "com.jenriks/photo-archive",
    "domains": "jenriks.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:jenriks.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.kimchi-sushi/agent-mcp",
    "domains": "kimchi-sushi.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:kimchi-sushi.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.mart402/extract",
    "domains": "mart402.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:mart402.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.patrickjv/profile",
    "domains": "patrickjv.com",
    "method": "did:web, P-256 (JWK)",
    "did": "did:web:patrickjv.com"
  },
  {
    "grade": "A",
    "score": 100,
    "name": "com.quantlix/content",
    "domains": "quantlix.com",
    "method": "did:web, Ed25519 (JWK)",
    "did": "did:web:quantlix.com"
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
  },
  {
    "grade": "C",
    "score": 60,
    "name": "app.postflow/mcp",
    "domains": "api.postflow.app",
    "method": "did:web",
    "did": "did:web:api.postflow.app"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "app.quantcalc/retirement-engine",
    "domains": "mcp.quantcalc.app",
    "method": "did:web",
    "did": "did:web:mcp.quantcalc.app"
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
    "name": "at.vorausgedacht/mcp",
    "domains": "vorausgedacht.at",
    "method": "did:web",
    "did": "did:web:vorausgedacht.at"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "ca.omniapps/sairen",
    "domains": "sairen.omniapps.ca",
    "method": "did:web",
    "did": "did:web:sairen.omniapps.ca"
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
    "name": "com.ai-for-av/ai-for-av",
    "domains": "ai-for-av.com",
    "method": "did:web",
    "did": "did:web:ai-for-av.com"
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
    "name": "com.australiawidefirstaid/courses",
    "domains": "www.australiawidefirstaid.com",
    "method": "did:web",
    "did": "did:web:www.australiawidefirstaid.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.australiawidefirstaid/docs",
    "domains": "www.australiawidefirstaid.com",
    "method": "did:web",
    "did": "did:web:www.australiawidefirstaid.com"
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
    "name": "com.corbah/open-line",
    "domains": "corbah-agents.corbah.workers.dev",
    "method": "did:web",
    "did": "did:web:corbah-agents.corbah.workers.dev"
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
    "name": "com.fieldrobin/fieldrobin",
    "domains": "fieldrobin.com",
    "method": "did:web",
    "did": "did:web:fieldrobin.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.getmandatorytraining/courses",
    "domains": "getmandatorytraining.com",
    "method": "did:web",
    "did": "did:web:getmandatorytraining.com"
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
    "name": "com.goodrecmovies/mcp",
    "domains": "goodrecmovies.com",
    "method": "did:web",
    "did": "did:web:goodrecmovies.com"
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
    "name": "com.growaify/mcp",
    "domains": "growaify.com",
    "method": "did:web",
    "did": "did:web:growaify.com"
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
    "name": "com.ifreework/content",
    "domains": "ifreework.com",
    "method": "did:web",
    "did": "did:web:ifreework.com"
  },
  {
    "grade": "C",
    "score": 60,
    "name": "com.linkbreakers/docs-mcp",
    "domains": "linkbreakers.com",
    "method": "did:web",
    "did": "did:web:linkbreakers.com"
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
    "name": "com.neuronto/x402-payments-facilitator",
    "domains": "pay.neuronto.com",
    "method": "did:web",
    "did": "did:web:pay.neuronto.com"
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
    "name": "com.socialcasinoindex/toplist",
    "domains": "dddc2d2qtq6jpgf3ucaorgozpe0lbqtj.lambda-url.us-east-1.on.aws",
    "method": "did:web",
    "did": "did:web:dddc2d2qtq6jpgf3ucaorgozpe0lbqtj.lambda-url.us-east-1.on.aws"
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
    "name": "com.voxodds/voxodds",
    "domains": "voxodds.com",
    "method": "did:web",
    "did": "did:web:voxodds.com"
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
  }
];
