# Vouch Protocol: Sponsor Brief

**For prospective charter sponsors and W3C voting members**

*26 April 2026*

---

## TL;DR for the busy reader

Autonomous AI agents are now operating inside your organization's regulated workflows. The standards bodies are actively defining how agent identity, authorization, and accountability will work. **You can shape that outcome at very low cost.**

Vouch Protocol is an open W3C-track specification for **continuous state verifiability** of AI agents, a layer that sits beneath, and complements, existing agent identity and delegation specifications. It is built entirely on existing W3C primitives (Verifiable Credentials, Data Integrity, DIDs) with no commercial dependencies.

We are seeking ~20 charter sponsors who recognize that AI agent accountability is a strategic priority. **Sponsorship requires no commercial commitment**, only a signal that your organization wants this work to advance through W3C.

---

## 1. The agent identity ecosystem in 2026

Several specifications are now active in the agent identity space:

- **W3C Verifiable Credentials, Data Integrity, DIDs**: the foundational credential and identity primitives.
- **OAuth 2.1 with mTLS**: API authorization for human-driven sessions, increasingly extended to agents.
- **Adjacent agent identity and delegation specifications** active in standards bodies including DIF: address verifiable agent identity, principal-to-agent delegation, and revocation within an agent session.
- **Vouch Protocol**: this specification, the continuous state verifiability layer.

These specifications address adjacent layers. They are designed to compose, not to compete.

## 2. What Vouch Protocol uniquely contributes

Vouch contributes the operational primitives that activate *after* an agent has been identified and authorized. The 13 contributions below are additive, they do not require replacing or modifying existing identity specifications.

| # | Contribution | Why it matters |
|---|---|---|
| 1 | **Hybrid post-quantum signature profile** (Ed25519 + ML-DSA-44) | Aligns with NIST CNSA 2.0 / NSM-10 migration mandates. Currently the only published PQ migration roadmap in the agent identity space. |
| 2 | **Continuous trust decay (Trust Entropy)** | Replaces static session TTLs with adaptive, risk-proportional trust. Sub-second granularity for high-stakes operations. |
| 3 | **Heartbeat Protocol with Merkle action root** | Cryptographic continuity across long-running agent sessions. A 32-byte Merkle root proves an entire action history. |
| 4 | **Federated Validator Quorum** (M-of-N) | Independent policy, behavioral, and budget validators. No single point of compromise. |
| 5 | **Cryptographic Mortality Protocol** (canary commitments) | Distinguishes a silent agent from a dead/substituted agent. |
| 6 | **Behavioral attestation** (intent-drift score) | Runtime evidence that the agent is still behaving as authorized, required for EU AI Act high-risk system auditability. |
| 7 | **Framework-agnostic transport** | Operates with MCP, LangChain, CrewAI, AutoGPT, AutoGen, and custom frameworks. Not bound to a specific message format. |
| 8 | **Cryptographic alternative to centralized reputation** | Mathematical, deterministic trust decay complementing community reputation registries. No dependency on third-party trust services. |
| 9 | **Content provenance integration** (C2PA, Sonic) | Identity bound to media artifacts, not just API calls. |
| 10 | **Single conformance level, uniform cryptographic floor** | Vouch v1.0 requires DID + Data Integrity end-to-end. No fallback to bearer tokens or session cookies. |
| 11 | **Pure W3C Data Integrity** (`eddsa-jcs-2022` cryptosuite) | Aligned cleanly with the W3C-blessed cryptosuite path; no JOSE/JWS dependency in v1.0. |
| 12 | **Multikey verification methods** | Algorithm-agnostic key encoding; ready for ML-DSA-44 the moment regulatory pressure increases. |
| 13 | **38 published defensive disclosures (CC0)** | A documented prior-art portfolio protects the open ecosystem from patent capture by any single vendor. |

## 3. Why this matters in your industry

### Banking and financial services

U.S. SR 11-7 and the OCC's 2024 AI bulletins require model-risk governance that includes provenance, accountability, and human-in-the-loop attestation. The EU's MiFID II and SEC Rule 15c3-5 require pre-trade risk evidence. Agent-driven trading and payment authorization need a cryptographic chain from the human compliance officer through every intermediate agent to the executing transaction. Vouch provides that chain with continuous attestation.

### Healthcare and life sciences

HIPAA and HITECH require auditable access to protected health information. FDA's SaMD guidance contemplates AI-driven clinical decision support. 21 CFR Part 11 requires electronic records that are tamper-evident and bound to identifiable actors. Vouch's behavioral attestation and cryptographic mortality enable agents to access PHI under a continuously-verifiable trust envelope rather than a one-time session token.

### Insurance

NAIC's 2024 AI Model Bulletin and NYDFS Part 500 require AI-system governance and incident-response readiness. Claims-authorization agents and underwriting agents create liability exposure that requires non-repudiation. Vouch's hybrid post-quantum profile ensures that today's authorizations remain provable in the post-quantum era, critical for insurance contracts that may be litigated decades after issuance.

### Pharmaceuticals

GxP and 21 CFR Part 11 govern electronic records in clinical trials and regulatory submissions. Agent-driven data capture and submission workflows require cryptographic continuity that survives both the trial duration and post-quantum migration. Vouch provides both.

### Government and defense

NIST CNSA 2.0, CNSSP-15, and NSM-10 mandate quantum-resistant cryptography on defined timelines. The agent identity layer must migrate before the deadlines, not after. Vouch v1.0 already publishes the hybrid Ed25519 + ML-DSA-44 profile.

### Cross-cutting EU exposure

The EU AI Act, applicable from 2025, imposes auditability and human-oversight obligations on high-risk AI systems. Vouch's behavioral attestation, delegation chain, and validator quorum produce the kind of continuous, tamper-evident audit trail that satisfies these obligations natively.

## 4. What we are asking for

| If you are... | We are asking you to... | Cost / commitment |
|---|---|---|
| A W3C voting member | Indicate support for advancing this CG Report and, in due course, support a VCWG/DIWG recharter that includes State Verifiability | Time only; no IP or commercial commitment |
| A regulated-sector enterprise (banking, healthcare, insurance, pharma) | Be listed as a Charter Sponsor and indicate that AI agent state verifiability is a strategic priority for your organization | Public name on a sponsor list; optional internal review of the spec |
| An AI platform or cloud vendor | Indicate Implementer Interest and commit to a reference implementation or interop test | Engineering review; no exclusive commitment |
| A DIF member or contributor to adjacent agent identity work | Engage at the layer-boundary discussion to ensure Vouch and adjacent specifications compose cleanly | Time and cross-WG participation |

## 5. The strategic case for sponsoring an open standard now

Three observations that motivate the timing:

1. **The agent identity layer is being standardized now.** Adjacent specifications are in active development at DIF and W3C. The shape of the standards is being decided this year. The cost of *not* engaging is downstream: vendor lock-in, integration tax, retroactive compliance work.

2. **Voting in favor of an open, vendor-neutral specification reduces lock-in risk.** Vouch is published with no commercial dependencies, no "Powered by ..." footers, and a 38-disclosure CC0 prior-art portfolio. Every concept your organization adopts via Vouch is unencumbered.

3. **Post-quantum migration deadlines are not negotiable.** NSM-10 and CNSA 2.0 set hard timelines. Specifications that lack a PQ migration roadmap will be retrofitted under deadline pressure. Vouch v1.0 already includes the hybrid Ed25519 + ML-DSA-44 profile and a clear v1.0 → v1.1 → v2.0 migration path.

## 6. Collaboration with adjacent specifications

Vouch Protocol is designed as a **complementary layer** alongside other agent identity and delegation specifications active at DIF and W3C. Where adjacent specifications provide verifiable identity and delegation within an agent session, Vouch provides continuous state verifiability across sessions, post-quantum migration, federated validator quorum, and behavioral attestation. We have engaged with the relevant working groups and welcome cross-pollination through shared test vectors and aligned interop profiles. Manu Sporny (W3C) has reviewed early drafts of this specification.

## 7. How to engage

| Channel | Purpose |
|---|---|
| **W3C CCG Wednesday calls** | Primary venue for discussion. APAC-friendly time windows under request. |
| **W3C TPAC (June 2026, Brussels)** | Face-to-face: editor will be in attendance. |
| **W3C TPAC (Sep/Oct 2026, Dublin)** | Face-to-face: charter discussion target. |
| **DIF Trusted AI Agents WG** | Cross-WG coordination with adjacent agent identity specifications. |
| **GitHub** | https://github.com/vouch-protocol/vouch, issues, PRs, conformance test results. |
| **Editor direct** | ram@vouch-protocol.com |

---

**Editor**: Ramprasad Gaddam, ram@vouch-protocol.com
**Specification**: https://vouch-protocol.com/specs/CG-REPORT/2026-04-26/
**Executive Summary**: https://vouch-protocol.com/specs/cg-report-executive-summary
**License**: Apache License 2.0 (specification); CC0 (prior-art portfolio)

*This brief is intended for distribution to prospective charter sponsors and W3C voting members. It is not a marketing document. Technical claims are referenced to the specification or the public defensive disclosure portfolio.*
