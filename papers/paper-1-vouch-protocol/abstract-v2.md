# Abstract (v2)

Standalone rewrite of the abstract for `paper-1-vouch-protocol`, calibrated
for active voice, concrete verbs, and varied sentence rhythm. Technical
content is unchanged from v1. This file is the canonical reference; the
same text is mirrored into `paper-1-vouch-protocol.tex` and
`paper-1-vouch-protocol.md`.

---

## Vouch Protocol: Cryptographic Identity and Continuous State Verifiability for Autonomous AI Agents

**Author:** Ramprasad Anandam Gaddam
**Affiliation:** Independent (open-source maintainer, Vouch Protocol)
**Contact:** ram@vouch-protocol.com · https://github.com/vouch-protocol/vouch
**Version:** v0.1, May 2026
**Vouch-signed:** https://vch.sh/arxiv-1
**License:** CC BY 4.0 (paper); Apache 2.0 (reference implementations); CC0 (defensive disclosures)

---

### Abstract

Autonomous AI agents now make decisions that matter: they move money, submit regulated filings, read clinical records, commit code. The credentials those agents use to do this (API keys, OAuth bearer tokens, shared service accounts) were designed for a human clicking through a session. They prove *access*. They do not prove *who authorized that action*, what the agent *intends* to do, or whether the agent is still trustworthy by the time it acts.

We present the **Vouch Protocol**: an open specification and a reference implementation in Python, TypeScript, and Go for cryptographically identifying autonomous AI agents and binding every action they take to a signed Verifiable Credential. Each credential carries the agent's identity, the specific intent (action, target, resource), the delegation chain from the original human principal down to the agent, and a freshness window after which the credential stops being valid.

Per-action signing is necessary but not sufficient. Once an agent has been admitted, the next question is whether it is still behaving correctly *right now*, after we let it through the door. The protocol's **State Verifiability layer** answers that with four mechanisms: (1) **trust entropy decay**, where credential trust falls exponentially over time and must be renewed before consequential actions; (2) **behavioral attestation digests**, lightweight per-interval summaries of the agent's API calls, resources accessed, and intent drift; (3) **canary commit/reveal chains**, providing cryptographic detection of silent agent failure or substitution; and (4) **M-of-N validator quorum**, distributing trust evaluation across role-specialized validators (policy, behavior, budget).

The protocol is built on W3C Verifiable Credentials Data Model 2.0 with Data Integrity proofs: the `eddsa-jcs-2022` cryptosuite, which signs Ed25519 over RFC 8785 JCS-canonicalized payloads. For the post-quantum transition, an optional hybrid cryptosuite `hybrid-eddsa-mldsa44-jcs-2026` binds an Ed25519 signature and an ML-DSA-44 signature (FIPS 204) to the same canonical bytes. Verifiers can downgrade gracefully, and we can migrate forward without changing the canonical payload.

This paper covers the credential format, the Identity Sidecar pattern that isolates an agent's signing key from the LLM process, delegation-chain construction with resource narrowing and depth-limited validation, the BitstringStatusList revocation mechanism, the Heartbeat Protocol's renewal cycle, the hybrid post-quantum profile and its byte-identical-canonicalization construction, and the State Verifiability runtime. We then work through the adversarial cases that motivated the design (prompt injection, key exfiltration, replay across resources, post-quantum cryptographic obsolescence) and what the protocol does about each. Cross-language test vectors show that three independent implementations produce byte-identical credentials.

The implementation is open-source under Apache 2.0. Sixty defensive prior-art disclosures accompany the specification under CC0 to keep design innovations openly available.

**Index Terms:** AI agent identity, Verifiable Credentials, decentralized identifiers, post-quantum cryptography, hybrid signatures, JCS canonicalization, prompt injection, delegation, continuous attestation, behavioral provenance.

---

### What changed from v1 (notes for reviewers)

- **Para 1**: Active opening ("agents now make decisions that matter") and concrete verbs ("move money, submit regulated filings, read clinical records, commit code") instead of abstract nouns. "do not prove who authorized that action" replaces the original "do not prove intent, do not bind who authorized what".
- **Para 2**: A 60-word sentence broken into two. "the delegation chain from the original human principal down to the agent" makes the root of the chain explicit.
- **Para 3**: Opens with a flat assertion ("Per-action signing is necessary but not sufficient") instead of "Beyond per-action signing, the protocol defines...".
- **Para 4**: Active voice ("Verifiers can downgrade gracefully, and we can migrate forward") instead of "allowing graceful verifier downgrade and forward migration".
- **Para 5**: Drops the "We describe... We discuss... We provide..." rhythm. "Cross-language test vectors show that three independent implementations produce byte-identical credentials" replaces the original passive phrasing.

Technical content is byte-equivalent to v1; all section pointers, cryptosuite names, mechanism names, and counts remain unchanged.
