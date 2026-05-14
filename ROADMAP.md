# Vouch Protocol: Development Roadmap

> "SSL for AI Agents": The Identity Layer for the Agentic Web

## Current State (v1.5.0)

Vouch Protocol is **feature-complete** across core identity, signing, verification, media, audio, and integrations. 22 PADs establish prior art. The protocol is ready for Linux Foundation AAIF submission and external specification review.

---

## Phase 1: Standards & Ecosystem Polish (Now → Launch Week)

**Goal:** Make the protocol installable, documented, and presentation-ready for Manu Sporny and standards bodies.

### 1.1 PyPI & Installation Experience
- [ ] Verify `pip install vouch-protocol` works cleanly on Python 3.9-3.12
- [ ] Ensure `vouch init` → `vouch sign` → `vouch verify` flow works in under 60 seconds
- [ ] First-run experience: `vouch init` should print a clear, beautiful welcome with DID
- [ ] Add `vouch demo` command , guided walkthrough of sign → verify → git sign

### 1.2 Documentation Site
- [ ] Host docs at vouch-protocol.com/docs (or ReadTheDocs)
- [ ] Quick Start guide (5-minute identity to first signature)
- [ ] CLI reference (all commands with examples)
- [ ] MCP integration guide (Claude Desktop, Cursor, Windsurf)
- [ ] Python SDK reference (Signer, Verifier, Passport classes)
- [ ] Architecture overview (DID resolution, token format, delegation)

### 1.3 Standards Documents
- [ ] Finalize Vouch Specification (v1.6 normative)
- [ ] Convert IETF Internet-Draft to xml2rfc format
- [ ] Prepare LFAI submission materials
- [ ] Create "Vouch Protocol in 5 Minutes" deck for Manu Sporny call

### 1.4 Test Hardening
- [ ] Run full `red_team.py` suite and fix any findings
- [ ] Add fuzzing tests for credential parsing (malformed VCs, tampered Data Integrity proofs, malformed JWS inputs for the legacy path)
- [ ] CI/CD pipeline with GitHub Actions (lint + test + type-check)

---

## Phase 2: Developer Experience & Adoption (Post-Launch → Month 1)

**Goal:** Make it dead simple for developers to adopt Vouch in their AI agents.

### 2.1 MCP as the Primary Adoption Path
*PAD-009 (Localhost Bridge), PAD-010 (Semantic Consent)*
- [ ] Publish MCP server to npm/PyPI as standalone package
- [ ] One-line install: `npx vouch-mcp` or `pip install vouch-mcp`
- [ ] Auto-discovery: MCP server auto-creates identity on first run
- [ ] Claude Desktop config generator: `vouch mcp setup`
- [ ] Cursor/Windsurf integration guides

### 2.2 Git Signing UX
*PAD-008 (Hybrid Identity Bootstrapping)*
- [ ] `vouch git setup` , one-command SSH key generation + GitHub upload
- [ ] Automatic `Vouched-By: did:vouch:name` trailer injection
- [ ] GitHub verification badge via SSH public key
- [ ] README badge: "Commits signed with Vouch Protocol"

### 2.3 Framework Integration Quality
- [ ] Publish `vouch-langchain` as standalone PyPI package
- [ ] Publish `vouch-crewai` as standalone PyPI package
- [ ] LangChain cookbook example (multi-agent pipeline with provenance)
- [ ] CrewAI cookbook example (crew with verified agent identities)
- [ ] Google ADK integration guide

### 2.4 Bridge Server Improvements
- [ ] Docker image: `docker run vouch-bridge`
- [ ] Helm chart for Kubernetes deployment
- [ ] Health check dashboard
- [ ] Request/response logging for debugging

### 2.5 Hosted Vouch Assistant: backend deployment
*Added 2026-05-15. Owner: editor. Trigger: post Leaders Connect.*

The chat assistant on vouch-protocol.com currently runs in graceful "coming soon" mode because no public backend exists yet. Steps to bring it live:

- [ ] Choose host: Fly.io (best technical fit for FastAPI + SSE) or Vercel (matches the downstream stack but needs SSE rework). Default plan: Fly.io.
- [ ] Provision `fly.toml`, deploy `website-agent/backend/` with the existing `Dockerfile`.
- [ ] DNS: `agent.vouch-protocol.org` pointing at the deployed app.
- [ ] Configure secrets: `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` or `GEMINI_API_KEY`, `VOUCH_SIDECAR_URL`, `VOUCH_AGENT_DID`, `VOUCH_CORS_ORIGINS` (must include https://vouch-protocol.com).
- [ ] Decide on rate limiting (per-IP, per-day) before going public; budget the LLM provider's monthly cost cap.
- [ ] Deploy the Go sidecar alongside (KMS-backed key in production, not the dev sidecar).
- [ ] Set `NEXT_PUBLIC_VOUCH_AGENT_URL=https://agent.vouch-protocol.org` in `.github/workflows/deploy-website.yml`. The website's graceful-fallback mode auto-switches to live mode when this is set.
- [ ] Verify end-to-end: open the live site, click "Ask the assistant", confirm streaming response and credential card render.
- [ ] Add backend monitoring (uptime, error rate, LLM provider latency) to observability.

### 2.6 Structured error-code system (full implementation)
*Added 2026-05-15. Owner: editor. Trigger: post Leaders Connect, paired with 2.5.*

The chat widget today ships a frontend-only error-code registry at `website/src/lib/error-codes.ts` (codes `VCH-NET-001` through `VCH-UNK-001`). This is intentionally minimal: it catches what JavaScript can detect (network failures, HTTP status, parsed error events) and surfaces stable codes the user can quote in issues. Full implementation extends this into:

- [ ] **Backend-issued codes.** Every error response from `website-agent/backend/` returns `{ "error": { "code": "VCH-XXX", "message": "...", "hint": "..." } }` instead of free-form strings. Update `vouch_agent/main.py` and `vouch_agent/signer.py`.
- [ ] **`vouch.errors` Python module.** Typed exceptions in the SDK with stable `.code` attribute.
- [ ] **Verifier reason mapping.** The Python `Verifier` already returns structured `reasons`. Add a `code` per reason mapped to `VCH-VRF-NNN`. Update the W3C CCG report's §8.4 (Failure Modes) to cite codes alongside reason strings.
- [ ] **Docs page.** A single page at `/help/error-codes/` listing every code with description and remediation. Auto-generated where possible.
- [ ] **TypeScript SDK.** Equivalent error classes in `packages/sdk-ts/`.
- [ ] **Go sidecar.** Return structured errors from `/sign` with the same shape.
- [ ] **Cross-language contract test.** Same malformed input produces the same `VCH-XXX` code across all three SDKs.

Codes are **stable and append-only**. Once published, a code's meaning does not change; new conditions get new numbers.

---

## Phase 3: PAD-Driven Innovation (Month 1-3)

**Goal:** Implement the novel capabilities described in PADs to differentiate Vouch from competitors.

### 3.1 Heartbeat Protocol (PAD-016)
*Dynamic Credential Renewal*
- [ ] Auto-renewing tokens with configurable heartbeat interval
- [ ] Grace period before token expiry
- [ ] Heartbeat failure → automatic credential revocation
- [ ] Dashboard showing live agent heartbeat status

### 3.2 Proof of Reasoning (PAD-017)
*Cryptographic Proof of Reasoning Traces*
- [ ] Sign chain-of-thought reasoning steps alongside outputs
- [ ] Verifiable reasoning provenance (prove HOW an agent reached a conclusion)
- [ ] Integration with LLM tool-use patterns
- [ ] Selective disclosure (share reasoning without revealing prompts)

### 3.3 Model Birth Certificate (PAD-018)
*Model Lineage Provenance*
- [ ] Sign model metadata at training/fine-tuning time
- [ ] Verifiable lineage chain: base model → fine-tune → deployment
- [ ] Model card integration (Hugging Face format)
- [ ] C2PA manifests for model files

### 3.4 Glass Channel (PAD-019)
*Transparent Agent Communication*
- [ ] Signed message bus between agents
- [ ] Every inter-agent message carries a Vouch credential (v1.0 VC + Data Integrity)
- [ ] Audit trail of all agent-to-agent communications
- [ ] Integration with LangGraph and CrewAI flows

### 3.5 Covenant Protocol Enhancement (PAD-012)
*Executable Usage Policies*
- [ ] Policy DSL for media usage rights (e.g., "no-AI-training", "attribution-required")
- [ ] Covenant verification at point of use
- [ ] Browser extension that checks covenants before allowing download
- [ ] Integration with C2PA do-not-train assertions

### 3.6 Ambient Witness (PAD-015)
*BLE Crowdsourced Verification*
- [ ] Mobile SDK for BLE-based proximity witnessing
- [ ] Multi-device co-signing for high-assurance events
- [ ] Geographic attestation without GPS (privacy-preserving)

---

## Phase 4: Enterprise & Scale (Month 3-6)

**Goal:** Make Vouch Protocol production-grade for enterprise deployments.

### 4.1 Distributed Registry
*PAD-011 (Hierarchical Discovery)*
- [ ] Federated DID registry (organizations run their own resolvers)
- [ ] DNS-based DID discovery (TXT records → DID documents)
- [ ] Registry replication and consistency protocols
- [ ] SLA-backed registry uptime (99.9%)

### 4.2 Ratchet Lock (PAD-020)
*Capability Containment*
- [ ] Monotonic capability restriction (agents can never gain more permissions than they started with)
- [ ] Policy enforcement at the protocol level
- [ ] Containment breach detection and alerting

### 4.3 Swarm Governance (PAD-022)
*Agent Population Limits*
- [ ] Maximum agent population per organization
- [ ] Spawn-rate limiting
- [ ] Agent lifecycle management (creation → active → decommission)
- [ ] Fleet-level reputation aggregation

### 4.4 Performance & Scale
- [ ] Token verification < 1ms (with warm cache)
- [ ] 100K verifications/second throughput
- [ ] Key rotation without downtime (KMS integration)
- [ ] Prometheus/Grafana dashboards for production monitoring

---

## Phase 5: Ecosystem & Standards (Month 6+)

### 5.1 Browser Extension
- [ ] "Vouch Verified" badge on web content
- [ ] Right-click → "Verify this image" using C2PA
- [ ] Show signer identity and reputation score
- [ ] Chrome Web Store + Firefox Add-ons

### 5.2 TypeScript SDK
- [ ] `npm install @vouch-protocol/sdk`
- [ ] Browser-compatible Ed25519 signing (WebCrypto API)
- [ ] Token verification in the browser
- [ ] React hooks: `useVouchVerify()`, `useVouchSign()`

### 5.3 Standards Milestones
- [ ] Independent specification review forum established
- [ ] First Vouch Specification Working Draft (post v1.6)
- [ ] IETF BOF session
- [ ] C2PA membership contribution (agent identity assertions)
- [ ] LFAI AAIF reference implementation recognition

### 5.4 Systems Whitepaper on arXiv (6-12 months post-launch)
- [ ] Accumulate six to twelve months of real-world Amnesia + Vouch usage data
- [ ] Empirical evaluation: rule retention over long sessions, cross-IDE compatibility, override frequency, post-quantum overhead measurements
- [ ] Theoretical framing: recorder/enforcer separation, write-only ledger composition with capability-based security, hybrid PQ signatures as audit-credential primitive
- [ ] Submit to arXiv (cs.CR primary, cs.SE secondary) with PADs 048-060 cited as the underlying disclosure portfolio
- [ ] Solicit endorsement if needed; coordinate publication timing with the W3C standards-track transition (§5.3)

---

## PAD Coverage Matrix

| PAD | Title | Implemented | Roadmap Phase |
|-----|-------|-------------|---------------|
| 001 | Cryptographic Agent Identity | ✅ Complete | , |
| 002 | Delegation Chains | ✅ Complete | , |
| 003 | Identity Sidecar | ✅ Complete | , |
| 004 | DOM Signature Matching | ✅ Complete | , |
| 005 | Detached Signature Recovery | ✅ Complete | , |
| 006 | URL Credential Chaining | ✅ Complete | , |
| 007 | Automated Provenance Telemetry | ✅ Complete | , |
| 008 | Hybrid Identity Bootstrapping | ✅ Core | Phase 2.2 |
| 009 | Localhost Bridge | ✅ Core | Phase 2.1 |
| 010 | Semantic Consent | Partial | Phase 2.1 |
| 011 | Hierarchical Discovery | Partial | Phase 4.1 |
| 012 | Executable Covenants | ✅ Audio | Phase 3.5 |
| 013 | Air-Gapped Psychoacoustic | ✅ Complete | , |
| 014 | Robust Acoustic Provenance | ✅ Complete | , |
| 015 | Ambient Witness (BLE) | Not started | Phase 3.6 |
| 016 | Heartbeat Protocol | Not started | Phase 3.1 |
| 017 | Proof of Reasoning | Not started | Phase 3.2 |
| 018 | Model Birth Certificate | Not started | Phase 3.3 |
| 019 | Glass Channel | Not started | Phase 3.4 |
| 020 | Ratchet Lock | Not started | Phase 4.2 |
| 021 | Inverse Capability Scaling | Not started | Phase 4.2 |
| 022 | Swarm Governance | Not started | Phase 4.3 |

---

## Next Feature to Build

**Recommendation: Phase 2.1 , MCP as Primary Adoption Path**

MCP is the fastest path to developer adoption. Every Claude Code, Cursor, and Windsurf user is a potential Vouch user. One-line install, zero-config identity, instant provenance. This is the "npm install" moment for agent identity.
