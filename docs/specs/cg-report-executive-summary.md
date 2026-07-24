# Vouch Protocol: Executive Summary

**Continuous State Verifiability for Autonomous AI Agents**

*Companion to the W3C CG Report, 31 May 2026 (v1.6.2)*

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
6. **Dual-proof post-quantum profile**, pairing of an `eddsa-jcs-2022` Data Integrity proof with an `mldsa44-jcs-2024` Data Integrity proof on the same credential, both signing identical JCS-canonicalized bytes. Recommended for regulated deployments and long-lived credentials, optional elsewhere. Aligned with NIST CNSA 2.0 migration timelines, the June 2026 US federal post-quantum signature mandate (EO 14412), and the W3C Quantum-Resistant Cryptosuites v1.0 First Public Working Draft.
7. **Algorithm Quorum Verification (optional)**, M-of-N cryptosuite diversity for defense-in-depth during the post-quantum transition; the dual-proof profile of (6) is the simplest 2-of-2 case, generalizable to any M-of-N.
8. **LLM-specific threat coverage**, including RAG-anchored reasoning attestation and model-weight-binding for detection of weight substitution and unauthorized fine-tuning.
9. **Cross-implementation determinism**, RFC 8785 JCS-canonicalized credentials reproduce byte-identically across the three reference implementations (Python, TypeScript, Go), eliminating ambiguity in multi-party trust state.

## Regulatory Drivers by Sector

| Sector | Regulatory Driver | Vouch Capability That Addresses It |
|---|---|---|
| **Banking** | SR 11-7, FFIEC AI guidance, OCC bulletins | Cryptographic chain-of-custody from human principal to executing agent |
| **Healthcare** | HIPAA, HITECH, FDA SaMD | Behavioral attestation and continuous trust verification for agents accessing PHI |
| **Insurance** | NAIC AI Bulletin, NYDFS Part 500 | Auditability and non-repudiation for agent-authorized claims |
| **Pharma** | 21 CFR Part 11, GxP | Cryptographic continuity of agent-driven electronic records |
| **Capital Markets** | SEC Rule 15c3-5, MiFID II | Pre-trade risk attestation for algorithmic-trading agents |
| **EU horizontal** | EU AI Act (high-risk systems) | Required auditability and human-oversight evidence |
| **Cross-cutting** | NIST CNSA 2.0, NSM-10 | Dual-proof Ed25519 + ML-DSA-44 post-quantum migration profile |

## What We Are Asking For

**For implementers.** Run the reference implementations (Python, TypeScript, Go), file conformance test results, contribute to the cross-language test-vector suite, and report interoperability findings against your existing identity stack.

**For organizations in regulated sectors with autonomous-agent deployments.** Read the Report and the regulatory mapping table above. If agent state verifiability is a problem your organization recognizes, indicate that on the public-credentials@w3.org list or in this work item's GitHub Issue thread. Such an indication carries no commercial commitment; it is a community signal that helps the CCG calibrate incubation priority.

**For W3C Credentials Community Group members.** Review, comment, and engage on the public-credentials list and at the CCG's regular calls.

**For contributors to adjacent agent identity specifications.** Vouch Protocol is designed to compose with identity and authorization specifications rather than replace them. Cross-pollination on the State Verifiability layer (the runtime trust and behavioral attestation surface that sits beneath identity and authorization) is welcomed; the editor will coordinate review threads with any related work item the CCG flags during incubation.

---

**Editor**: Ramprasad Gaddam, ram@vouch-protocol.com
**Authors**: Ramprasad Gaddam (Vouch Protocol), Manu Sporny (Digital Bazaar)
**Co-sponsor**: Manu Sporny (Digital Bazaar), msporny@digitalbazaar.com
**Repository**: https://github.com/vouch-protocol/vouch
**Full specification**: https://vouch-protocol.com/specs/CG-REPORT/2026-05-31/
**Tagged release (GitHub)**: https://github.com/vouch-protocol/vouch/releases/tag/v1.6.2
**License**: Apache License 2.0 (reference implementations); CC0 (60-disclosure prior-art portfolio). Specification contributions are governed by the W3C Community Contributor License Agreement.
