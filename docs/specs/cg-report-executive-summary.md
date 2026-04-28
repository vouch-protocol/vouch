# Vouch Protocol: Executive Summary

**Continuous State Verifiability for Autonomous AI Agents**

*Companion to the W3C CG Report, 26 April 2026*

---

## The Problem

Autonomous AI agents are now executing real-world actions in regulated sectors, authorizing financial transactions, accessing protected health information, submitting regulatory filings, and operating critical infrastructure. Existing authentication mechanisms (API keys, OAuth bearer tokens, session cookies) were designed for human users and stateless services. They cannot answer the questions that auditors, regulators, and incident responders actually ask:

- *Which specific agent, controlled by which principal, performed this action?*
- *Was the agent's runtime state still aligned with its authorization at the moment of action?*
- *Has the agent been substituted, hijacked, or silently failed since its last verification?*
- *Will the cryptographic proof we accept today still bind the agent in 2030, after quantum-capable adversaries arrive?*

## The Solution

**Vouch Protocol** defines a continuous-state-verifiability layer for autonomous AI agents, built entirely on existing W3C primitives:

- **W3C Verifiable Credentials** as the credential format.
- **W3C Data Integrity** with the `eddsa-jcs-2022` cryptosuite for tamper-evident, human-readable proofs.
- **W3C Decentralized Identifiers** (`did:web`, `did:key`) for agent and principal identity.
- **W3C Multikey** for algorithm-agnostic verification methods, enabling smooth migration to post-quantum signatures.

On top of these primitives, Vouch contributes:

1. **Identity Sidecar pattern**, private keys are physically isolated from the LLM context window, neutralizing prompt injection as a key-exfiltration vector.
2. **Heartbeat Protocol**, continuous credential renewal with adaptive TTL, replacing static session timeouts with risk-proportional trust.
3. **Trust Entropy**, deterministic, mathematical decay of credential trust over time, providing an objective alternative to subjective reputation scores.
4. **Federated Validator Quorum**, independent M-of-N approval across policy, behavioral, and budget validators; no single compromise can issue valid credentials.
5. **Resource-bound delegation chains**, every delegation link is bound to a specific resource URI, preventing confused-deputy attacks at the authorization layer.
6. **Hybrid post-quantum profile**, optional Ed25519 + ML-DSA-44 composite signatures aligned with NIST CNSA 2.0 migration timelines.

## Why This Matters Across Industries

| Sector | Regulatory Driver | Vouch Capability That Addresses It |
|---|---|---|
| **Banking** | SR 11-7, FFIEC AI guidance, OCC bulletins | Cryptographic chain-of-custody from human principal to executing agent |
| **Healthcare** | HIPAA, HITECH, FDA SaMD | Behavioral attestation and continuous trust verification for agents accessing PHI |
| **Insurance** | NAIC AI Bulletin, NYDFS Part 500 | Auditability and non-repudiation for agent-authorized claims |
| **Pharma** | 21 CFR Part 11, GxP | Cryptographic continuity of agent-driven electronic records |
| **Capital Markets** | SEC Rule 15c3-5, MiFID II | Pre-trade risk attestation for algorithmic-trading agents |
| **EU horizontal** | EU AI Act (high-risk systems) | Required auditability and human-oversight evidence |
| **Cross-cutting** | NIST CNSA 2.0, NSM-10 | Hybrid Ed25519 + ML-DSA quantum migration profile |

## Path to Standard

| Phase | Body | Gating signal | Outcome |
|---|---|---|---|
| Incubation | W3C Credentials Community Group | Active now | CG Report v1.0, multi-vendor implementations, test vectors |
| Transition Proposal | W3C VCWG / DIWG | When community traction supports it (multiple implementations, broad agreement, charter readiness) | Charter or rechartering proposal |
| Standards Track | W3C VCWG / DIWG | Following transition | Working Draft to Candidate Recommendation to Recommendation |

## What We Are Asking For

**For implementers**: Run the reference implementation, file conformance test results, contribute to the test vector suite.

**For potential charter sponsors (CVS, UHG, JPMorgan Chase, Wells Fargo, Pfizer, Microsoft, Cloudflare, AWS, and similarly-positioned organizations)**: Indicate interest. Voting in favor of a recharter to add agent state verifiability does not require commercial commitment, only signal that this is a problem your organization recognizes.

**For W3C members**: Review, comment, and engage at upcoming Wednesday CCG calls (with Asia-Pacific-friendly times under request), and at the Brussels (June 2026) and Dublin (September/October 2026) face-to-face meetings.

**For DIF members and contributors to adjacent agent identity specifications**: Vouch Protocol is designed to compose with your work. We welcome cross-pollination on the State Verifiability layer that sits beneath identity and authorization.

---

**Editor**: Ramprasad Gaddam, ram@vouch-protocol.com
**Repository**: https://github.com/vouch-protocol/vouch
**Full specification**: https://vouch-protocol.com/specs/CG-REPORT/2026-04-26/
**License**: Apache License 2.0 (specification); CC0 (38-disclosure prior-art portfolio)
