# Vouch Protocol: Cryptographic Identity and Continuous State Verifiability for Autonomous AI Agents

**Author:** Ramprasad Anandam Gaddam
**Affiliation:** Independent (open-source maintainer, Vouch Protocol)
**Contact:** groups.rampy1@gmail.com  ·  https://github.com/vouch-protocol/vouch
**Version:** Pre-print draft, 14 May 2026
**License:** This paper is released under CC BY 4.0. The Vouch Protocol reference implementations are released under Apache 2.0. The fifty-eight defensive disclosures cited herein are released under CC0.
**Repository:** https://github.com/vouch-protocol/vouch
**Specification:** Spec v0.1-draft, Vouch Protocol CG Report (https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md)

---

## Abstract

Autonomous AI agents are increasingly delegated decisions with real-world consequences: financial transfers, regulated submissions, clinical record access, code commits. The credentials those agents use today — API keys, OAuth bearer tokens, shared service accounts — were designed for human-driven sessions. They prove *access*. They do not prove *intent*, do not bind *who authorized what*, and offer no operational mechanism to continuously verify that an agent is still behaving correctly while running.

We present the **Vouch Protocol**: an open specification and reference implementation in Python, TypeScript, and Go for cryptographically identifying autonomous AI agents and binding every action they take to a signed Verifiable Credential whose payload includes the agent's identity, the specific intent (action, target, resource), the chain of principals who delegated authority down to the agent, and a freshness window beyond which the credential expires.

Beyond per-action signing, the protocol defines a **State Verifiability layer** that addresses operational questions arising after an agent has been identified and authorized: is the agent still behaving correctly *right now*, after we let it through the door? The mechanisms are (1) **trust entropy decay**, where credential trust falls exponentially over time and must be renewed before consequential actions; (2) **behavioral attestation digests**, lightweight per-interval summaries of the agent's API calls, resources accessed, and intent drift; (3) **canary commit/reveal chains**, providing cryptographic detection of silent agent failure or substitution; and (4) **M-of-N validator quorum**, distributing trust evaluation across role-specialized validators (policy, behavior, budget).

The protocol is built on W3C Verifiable Credentials Data Model 2.0 with Data Integrity proofs (the `eddsa-jcs-2022` cryptosuite for Ed25519 over RFC 8785 JCS-canonicalized payloads). For the post-quantum transition, an optional hybrid cryptosuite `hybrid-eddsa-mldsa44-jcs-2026` binds an Ed25519 signature and an ML-DSA-44 signature (FIPS 204) to the same canonical bytes, allowing graceful verifier downgrade and forward migration without changing the canonical payload.

We describe the credential format, the Identity Sidecar pattern for isolating agent signing keys from the LLM process, the delegation-chain construction with resource narrowing and depth-limited validation, the BitstringStatusList revocation mechanism, the Heartbeat Protocol's renewal cycle, the hybrid post-quantum profile and its byte-identical-canonicalization construction, and the State Verifiability runtime. We discuss adversarial threats (prompt injection, key exfiltration, replay across resources, post-quantum cryptographic obsolescence) and the protocol's defenses. We provide cross-language test vectors verifying byte-identical credentials across three independent implementations.

The implementation is open-source under Apache 2.0. Fifty-eight defensive prior-art disclosures accompany the specification under CC0 to keep design innovations openly available.

**Index Terms:** AI agent identity, Verifiable Credentials, decentralized identifiers, post-quantum cryptography, hybrid signatures, JCS canonicalization, prompt injection, delegation, continuous attestation, behavioral provenance.

---

## 1. Introduction

### 1.1 The Accountability Gap

Modern AI agents — LangChain pipelines, CrewAI swarms, AutoGPT-style autonomous workers, Model Context Protocol-driven assistants — increasingly take actions that human-level credentials were never designed to authorize. An LLM-driven agent submitting an insurance claim, placing a stock order, querying a patient's electronic health record, or auto-committing code to a production branch is performing a real action with real consequences. When that action requires audit, dispute resolution, or regulatory review, the only artefact available is a log entry naming an API key. The key is shared, was rotated three months ago, and gives no insight into which specific agent generation, which orchestration layer, which prompt, or which user-level principal authorized the action.

The accountability gap has three structural sources:

1. **Identity opacity.** Bearer credentials (API keys, JWTs, OAuth access tokens) prove access by possession, not by signature over an intent. An entity in possession of the bearer can take any action the bearer permits; nothing in the credential reflects which specific entity, in which specific context, with which specific upstream authorization, did so.

2. **Intent omission.** Even when an action is logged, the intent it represented is recorded in application-specific log formats with no cryptographic binding. A log entry "agent-prod-2 called `submit_claim`" can be forged by anyone with access to the log writer. The action's parameters, the resource it targeted, and the authorization chain are not cryptographically bound to the agent's identity.

3. **Trust monotonicity.** Existing identity systems trust credentials until they are explicitly revoked. A compromised agent continues operating until a human detects misbehavior and pushes a revocation. For autonomous agents — which may operate in regulated, latency-sensitive, or sparsely-monitored contexts — the gap between compromise and revocation may span hours or days, during which the compromised agent has uninterrupted authority.

### 1.2 The Vouch Protocol Approach

The Vouch Protocol addresses these failures with three composing layers:

1. A **credential layer** in which every agent action is issued as a W3C Verifiable Credential signed by the agent's Decentralized Identifier (DID) via a Data Integrity proof. The credential's `credentialSubject.intent` field carries the action verb, the target identifier, and the resource URI bound together. The credential's `validUntil` is short (commonly 5 minutes). The proof is `eddsa-jcs-2022` over the JCS-canonicalized credential bytes, or optionally the hybrid post-quantum cryptosuite.

2. A **delegation layer** in which credentials chain together, each link cryptographically attesting to a principal-to-sub-principal authorization. Resource scope must narrow at each link; chain depth is bounded; the root principal is verifiable. Multi-agent systems gain end-to-end attribution: "the patient authorized the clinician, who authorized their EHR agent, who authorized the prior-auth sub-agent, who submitted this credential" is a single auditable chain.

3. A **state verifiability layer** in which long-running agents renew their credentials on a heartbeat schedule. Trust decays exponentially over time; behavioral attestation digests are computed per interval; canary commit/reveal chains detect silent failures; an M-of-N validator quorum distributes trust evaluation across role-specialized policy / behavior / budget validators. An agent that cannot heartbeat — because it crashed, is compromised, or has drifted out of policy — loses authority by entropy decay; a missed heartbeat is cryptographically detectable.

Together, the three layers move from "the agent had a key" to "the agent issued a signed credential at time T, declaring action A on resource R, with the authorization of principals P₁ → P₂ → P_n, verifiable against the agent's published DID Document and the issuer's revocation registry, with a freshness window of 300 seconds and a running behavioral attestation showing the agent is operating within its declared scope."

### 1.3 Design Goals

Six design goals shaped the protocol:

- **Standards alignment over invention.** Where existing open standards suffice — W3C VC 2.0, Data Integrity, DIDs, BitstringStatusList, RFC 8785 JCS, NIST FIPS 204 — the protocol composes with them and does not introduce new primitives.
- **LLM-isolated key material.** The agent's private signing key must never appear in the LLM's context window. The Identity Sidecar pattern isolates the key in a separate process that the LLM cannot reach.
- **Byte-identical canonicalization across languages.** Credentials signed by the Python SDK must verify against credentials signed by the TypeScript or Go SDK with the same input. JCS (RFC 8785) is the canonical form.
- **Cryptographic agility.** The protocol must accommodate the post-quantum transition without changing the canonical payload format. The hybrid cryptosuite signs the same bytes with two algorithms; verifiers select the trust level they require.
- **Continuous verifiability, not point-in-time authentication.** Trust must be renewed under observation; an agent that goes silent must lose authority automatically.
- **Open prior art.** Every novel design pattern is published as a defensive disclosure (Apache 2.0 code, CC0 disclosure) to keep the design space open.

### 1.4 Contribution Summary

This paper contributes:

1. The Vouch Credential format and its Data Integrity proof construction (`eddsa-jcs-2022`).
2. The Identity Sidecar pattern with intent allow-list enforcement at the sidecar layer, defended against prompt injection by construction.
3. The delegation chain mechanism with resource narrowing, depth-limit, and trusted-principal anchoring.
4. The BitstringStatusList integration for per-credential revocation, plus DID-level revocation for issuer-key compromise.
5. The hybrid post-quantum cryptosuite `hybrid-eddsa-mldsa44-jcs-2026`, with concatenated signatures bound to the same JCS canonical bytes.
6. The State Verifiability runtime: trust entropy decay, behavioral attestation digests, canary commit/reveal chains, M-of-N validator quorum.
7. Cross-language test vectors and three reference implementations (Python, TypeScript, Go).

### 1.5 Paper Organization

Section 2 reviews related work and clarifies Vouch's position in the agent-identity landscape. Section 3 defines the credential format. Section 4 presents the Identity Sidecar architecture. Section 5 develops the delegation chain construction and its verification. Section 6 details the revocation mechanisms. Section 7 presents the hybrid post-quantum cryptosuite. Section 8 introduces the State Verifiability layer. Section 9 analyses the protocol's security properties against an adversarial threat model. Section 10 reports cross-language interoperability results. Section 11 discusses limitations and future work. Section 12 concludes.

---

## 2. Related Work and Positioning

### 2.1 Workload Identity Systems

SPIFFE and SPIRE [Strong2018] define workload identity for service-to-service communication in cloud environments. SPIFFE issues short-lived X.509 SVIDs or JWT-SVIDs to workloads via attestation against the host platform. SPIFFE establishes *that* a workload is who it claims to be (via attestation against the runtime), but does not bind the workload's actions to the identity at the per-action level. A SPIFFE-authenticated workload making an HTTP call to a downstream service authenticates the call via mutual TLS; the call's intent (target resource, requested action, authorization chain) is not part of the authenticated payload.

Vouch composes with SPIFFE: a SPIFFE-attested workload may also be a Vouch issuer, holding a Vouch DID whose verification methods are bootstrapped from the SVID. The Vouch credential then provides the per-action binding that SPIFFE does not.

### 2.2 OAuth 2.0 / OAuth 2.1 and Token-Based Access

OAuth 2.x [RFC 6749, RFC 9700] is the dominant access-grant protocol for HTTP APIs. Access tokens are bearer credentials authorizing the client to call defined scopes on the resource server. OAuth makes no claim about which specific agent within a client used the token, what the agent intended, or whether the agent's runtime state remains within policy.

Vouch is complementary to OAuth at the application layer. A Vouch credential may accompany an OAuth-authorized HTTP request, providing the agent-identity, intent, and delegation that OAuth's bearer model omits. Resource servers may verify both — OAuth for coarse access authorization and Vouch for action-specific identity and intent — or may use Vouch alone for agent-to-agent communication where OAuth's session model does not fit.

### 2.3 Decentralized Identifiers and Verifiable Credentials

The W3C Decentralized Identifiers (DID) Core [DID-CORE] and Verifiable Credentials Data Model 2.0 [VC-DM-2.0] specifications define the underlying identity and credential primitives Vouch uses. Vouch issues VCs as defined by VC-DM-2.0, with DIDs as the issuer identifier. Vouch does not introduce a new identity primitive; it specifies a credential subtype (`VouchCredential`) and a per-action issuance pattern.

Among the many credential subtypes the VC ecosystem has produced — student transcripts, professional certifications, vaccination records, employment letters — Vouch occupies a distinct niche: per-action, short-validity, agent-issued credentials describing what the agent is about to do, not what it has been authorized to be.

### 2.4 ZCAP-LD and Capability-Based Authorization

ZCAP-LD [ZCAP-LD] is a JSON-LD capability authorization format that supports attenuation through delegation. ZCAP capabilities are attenuated at each delegation: a parent capability is restricted as it is delegated downward. The result is similar in shape to a Vouch delegation chain.

Vouch's delegation differs in three respects:

1. **Canonicalization**: Vouch uses RFC 8785 JCS, not JSON-LD canonicalization. JCS is simpler, has no external context dependencies, and produces byte-identical output across implementations more reliably.
2. **Resource binding**: Each Vouch delegation link explicitly binds a `resource` URI. The chain validator enforces that child resources be sub-paths of parent resources, preventing capability widening at any link.
3. **Chain semantics**: Vouch delegations are credentials in their own right (each link is a VC); ZCAP capabilities are stand-alone documents with their own data model.

Vouch's chain construction is documented as defensive disclosure PAD-002 (Chain of Custody Delegation).

### 2.5 C2PA Content Credentials

The Coalition for Content Provenance and Authenticity (C2PA) defines content-binding credentials for media assets [C2PA-1.4]. C2PA Content Credentials embed signed provenance into media files (images, audio, video). Vouch is complementary: a content-creation agent may sign a Vouch credential authorizing the act of generating an image, then bind the image's C2PA manifest to the same agent identity. PAD-014 (Vouch Sonic) and PAD-024 (Temporal Video Fingerprinting) detail content-bound applications.

### 2.6 Post-Quantum Signature Migration Frameworks

NIST's selection of ML-DSA-44 (FIPS 204) and SLH-DSA (FIPS 205) as standardized post-quantum digital signature algorithms creates the migration pressure Vouch addresses. The IETF's `draft-ietf-jose-pq-composite-sigs` defines composite signatures for JOSE; the W3C Data Integrity community has discussed parallel constructions. Vouch's `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite is a Data-Integrity-native realization: a single Vouch credential carries a `proofValue` that is the byte-concatenation of the Ed25519 signature and the ML-DSA-44 signature, both computed over the same JCS canonical bytes. Verifiers in classical-only mode validate the first 64 bytes; verifiers in PQ-aware mode validate both. The construction is documented as PAD-040 (Hybrid Composite Signature Bound to Same Canonical Bytes).

### 2.7 Honeypot and Adversarial-Detection Approaches

Several adjacent works treat agent and identity systems defensively rather than only protectively. Vouch's design includes adversarial-detection mechanisms (PAD-031 Canary Provenance Honeypots, PAD-047 VDF-rate-limited actions, PAD-058 Auto-Rotation on Leak Detection) that compose with the core protocol. These are referenced in this paper where relevant but treated in greater depth in the accompanying defensive-disclosure portfolio.

---

## 3. The Vouch Credential

### 3.1 Format

A Vouch Credential is a W3C Verifiable Credential 2.0 with a `VouchCredential` type tag, a `credentialSubject` carrying the agent's intent, and a Data Integrity proof over the JCS-canonicalized credential bytes. The format is defined in Section 5 of the Vouch Protocol specification.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vouch-protocol.com/contexts/v1"
  ],
  "id": "urn:uuid:b8b5c7bd-8271-4805-8973-70968c4dd46f",
  "type": ["VerifiableCredential", "VouchCredential"],
  "issuer": "did:web:agent.example.com",
  "validFrom": "2026-05-13T05:41:10Z",
  "validUntil": "2026-05-13T05:46:10Z",
  "credentialSubject": {
    "id": "did:web:agent.example.com",
    "vouchVersion": "1.0",
    "intent": {
      "action": "submit_claim",
      "target": "claim:HC-001",
      "resource": "https://insurance.example.com/claims/HC-001"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-05-13T05:41:10Z",
    "verificationMethod": "did:web:agent.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z77CAhFw1rKB1wLQ541oZ55WD1rVcmkiHFnF8EcVs2A4zX6Y4rYwcdxY5To2YDkNusLdkXYX8EgXVrLcZyTpPGxh"
  }
}
```

The required fields, beyond the VC 2.0 baseline:

- `type` MUST include `VouchCredential`.
- `credentialSubject.vouchVersion` MUST be present and equal to the protocol version this credential conforms to.
- `credentialSubject.intent.action`, `intent.target`, `intent.resource` MUST all be non-empty strings. Empty strings are treated as missing.
- `validFrom` MUST be in RFC 3339 form with `Z` UTC indicator (not `+00:00`).
- `validUntil` SHOULD be set to a short window (default 300 seconds from `validFrom`); credentials with no `validUntil` are accepted but operationally discouraged.

### 3.2 The eddsa-jcs-2022 Cryptosuite

The default cryptosuite is `eddsa-jcs-2022` (W3C Data Integrity registered identifier). The signing procedure:

1. Construct the credential dictionary with all required fields, including the `proof` object except `proofValue`.
2. Canonicalize the entire credential using RFC 8785 JCS. JCS specifies a strict deterministic ordering, escaping, and number formatting; the output is byte-identical across conforming implementations.
3. Compute the Ed25519 signature over the canonical bytes using the issuer's private key.
4. Encode the signature in multibase base58btc form (the `z` prefix), producing approximately 88 characters.
5. Set `proof.proofValue` to the multibase-encoded signature.

Verification reverses the process:
1. Extract `proof.proofValue`, decode from multibase base58btc.
2. Reconstruct the credential dictionary excluding `proof.proofValue` (other proof fields are part of the signed payload).
3. JCS-canonicalize.
4. Resolve the issuer's DID Document, locate the verification method indicated by `proof.verificationMethod`, extract the Ed25519 public key (encoded as Multikey in the DID Document).
5. Verify the Ed25519 signature.

### 3.3 JCS Determinism Across Languages

JSON Canonicalization Scheme (RFC 8785) fixes the serialization that Ed25519 signs. The protocol's three reference implementations (Python, TypeScript, Go) produce byte-identical JCS output given byte-identical inputs. Cross-language test vectors in `test-vectors/jcs/` verify the property on every release. PAD-039 (Cross-Implementation Deterministic Multi-Party Trust State via JCS-Canonicalized Verifiable Credentials) documents the design choice and its rationale.

The byte-identity property is foundational: without it, a credential signed by Python and a credential with the same logical content signed by TypeScript would have different signatures, breaking interoperability and federation across implementations.

### 3.4 Verification Method Resolution

`proof.verificationMethod` is a URI of the form `did:web:agent.example.com#key-1`. The verifier resolves this:

1. Fetch the DID Document at `https://agent.example.com/.well-known/did.json`.
2. Locate the `verificationMethod` array entry with id `did:web:agent.example.com#key-1`.
3. Confirm the entry is referenced from the appropriate verification relationship (for credential issuance, `assertionMethod`).
4. Extract `publicKeyMultibase` and decode to obtain the Ed25519 public key.

The verifier caches DID Documents with a configurable TTL. On verification failure, the verifier forces refresh, ensuring rotation is detected within the operator's chosen latency window.

### 3.5 Intent Replay Resistance

Each credential carries a unique `id` (typically a UUID URN). Verifiers maintain a nonce store keyed on `id`. A credential whose `id` has previously been seen is rejected (`nonce_replay`). The nonce store's TTL must be at least the longest plausible credential `validUntil` to prevent a credential from being replayed after the nonce store has forgotten it.

Replay resistance is also enforced at the intent level: `intent.target` and `intent.resource` are part of the signed payload. A credential authorizing `submit_claim` on `claim:HC-001` cannot be replayed against `claim:HC-002` without re-signing — the JCS canonical bytes differ.

---

## 4. The Identity Sidecar Pattern

### 4.1 Motivation

Modern AI agents are typically built around a Large Language Model. The LLM is stochastic, non-deterministic, and vulnerable to prompt injection. Exposing the agent's private signing key to the LLM's context window creates three failure modes:

- **Key leak via prompt injection.** Adversarial content in retrieved documents, tool outputs, or user input can instruct the LLM to print the key as part of its output.
- **Unauthorized signing via jailbreak.** A jailbroken LLM may use the key to sign arbitrary intents, including intents not authorized by the principal.
- **Persistence in training data and logs.** Key material that passed through the LLM may end up in logged conversation transcripts, fine-tuning corpora, or vendor-side analytics.

Direct key exposure to the LLM is incompatible with the protocol's security model.

### 4.2 Architecture

The Identity Sidecar pattern (defensive disclosure PAD-003) separates the agent into two processes:

1. **The Brain (stochastic).** The LLM. Holds zero cryptographic secrets. Reasons about which action to take and proposes intents to the Sidecar.
2. **The Passport (deterministic).** A small, auditable process holding the private signing keys in its address space. Receives intent proposals from the Brain, applies a deterministic policy check, and issues credentials only when policy passes.

The Brain and the Passport communicate over a local IPC channel — typically localhost HTTP, a UNIX domain socket, or an MCP transport. The IPC boundary is the trust boundary.

### 4.3 Just-In-Time Signing Flow

A signing operation proceeds:

1. The Brain decides an action is appropriate. It constructs a proposed intent.
2. The Brain submits the intent to the Sidecar over IPC.
3. The Sidecar applies its policy: structural validation (required fields present), allow-list check (PAD-056: action type is in the deployed allow-list), and rate-limit check.
4. If policy passes, the Sidecar constructs the full credential, signs it with the held private key, and returns the credential to the Brain.
5. If policy fails, the Sidecar returns a structured error. No credential is produced.

The Sidecar's policy check is the **last line of defence** against a compromised Brain. A prompt-injected LLM may propose any intent it likes; the Sidecar refuses to sign anything outside the allow-list. The capability bound on a compromised Brain is therefore structural (PAD-056), not behavioural.

### 4.4 Reference Implementations and Tier Hierarchy

Three reference Sidecar implementations accompany the protocol:

- **Go** (`go-sidecar/`): production-tier, KMS/HSM-backed, hybrid PQ supported, sensitive-mode JWE wrapping, multi-tenant.
- **Python** (`vouch.sidecar.*`): lightweight tier for self-hosted Python stacks. File or environment keys. Intentionally omits KMS, hybrid PQ, JWE, and multi-tenancy.
- **TypeScript** (`packages/sdk-ts/sidecar/`): lightweight tier for Node stacks. Same omissions as Python.

The HTTP wire contract is identical across all three:
- `GET /health` — liveness probe
- `GET /did` — the sidecar's configured DID
- `GET /.well-known/did.json` — optional DID Document serving
- `POST /sign` — sign a Vouch credential for an intent

A shared contract test suite (`test-vectors/sidecar-contract/`) verifies that all three implementations accept and reject the same inputs and emit semantically equivalent credentials. The tier hierarchy is informative guidance: deployers requiring KMS, FIPS, hybrid PQ, or multi-tenancy run the Go sidecar; deployers with simpler requirements may run Python or TypeScript.

### 4.5 MCP Integration

The Model Context Protocol (MCP) [MCP-2025] is a standard for exposing tools and resources to LLM clients. A Vouch Sidecar may expose its signing capability as an MCP tool:

```json
{
  "name": "vouch_sign",
  "description": "Issue a Vouch Credential for an intent payload.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "intent": {
        "type": "object",
        "required": ["action", "target", "resource"]
      }
    },
    "required": ["intent"]
  }
}
```

An MCP-aware LLM client invokes `vouch_sign` exactly as it would any other tool. The Sidecar's allow-list and rate-limit policies are unchanged; the MCP layer is transport, not authority.

---

## 5. Delegation Chains

### 5.1 Motivation

Multi-agent systems present an attribution problem: an action taken by a leaf agent may have been authorized by a chain of principals — a user authorized an assistant, which authorized a research agent, which authorized a web-scraping sub-agent. When the action requires audit, the leaf-only signing model loses the chain.

Vouch delegations are themselves Verifiable Credentials. Each link in a chain is a credential signed by the delegating principal and identifying the delegate. A leaf-action credential includes the full chain (or a reference to it) so a verifier can reconstruct the authorization path from root principal to leaf agent.

### 5.2 Delegation Link Structure

A delegation link is a Vouch credential whose `credentialSubject` is shaped:

```json
{
  "credentialSubject": {
    "id": "did:web:research-agent.example.com",
    "delegatedBy": "did:web:assistant.example.com",
    "scope": {
      "actions": ["web_search", "scrape_page"],
      "resource": "https://research-agent.example.com/agents/research-agent/scope/2026"
    },
    "validUntil": "2026-05-14T08:00:00Z"
  }
}
```

The link's `issuer` is the delegating principal. The link's `credentialSubject.id` is the delegate. `scope.actions` enumerates which actions are delegated; `scope.resource` is the resource URI under which all delegated actions must fall.

### 5.3 Chain Construction and the Resource Narrowing Rule

A chain is a list of delegation-link credentials, ordered from root principal to leaf agent. At each link, the child's `scope.resource` MUST be a sub-URI of the parent's `scope.resource`. Concretely, with parent resource `https://x.example.com/department/finance/` and child resource `https://x.example.com/department/finance/accounts-payable/`, the narrowing is valid. With child resource `https://x.example.com/department/legal/`, narrowing is violated and the chain is rejected.

The narrowing rule prevents capability widening at any link. A delegate cannot grant a sub-delegate more authority than it itself holds.

### 5.4 Depth Limit

Chain depth is bounded to **five links maximum** (specification §9.4). This limit prevents pathological chains from inflating verification cost and from obscuring the actual authorization path. Deployments requiring deeper chains MUST restructure (e.g., introduce a single mid-level principal acting on behalf of multiple sub-principals).

### 5.5 Chain Validation

A verifier validating a leaf credential with an attached chain:

1. Verifies the leaf credential's signature as in §3.2.
2. Identifies the chain root: the first link's `issuer` MUST be in the verifier's set of **trusted principals** for the leaf action. If not, validation fails with `untrusted_principal`.
3. For each adjacent pair (parent, child) in the chain, verifies the child's `scope.resource` is a sub-URI of the parent's.
4. Verifies each link's `delegatedBy` matches the previous link's `credentialSubject.id`.
5. Verifies each link's signature.
6. Verifies the leaf credential's `intent.action` is in the deepest link's `scope.actions`.
7. Verifies the leaf credential's `intent.resource` is a sub-URI of the deepest link's `scope.resource`.

Any failure produces a structured rejection reason: `untrusted_principal`, `chain_depth_exceeded`, `resource_not_narrowed`, `link_signature_invalid`, `parent_proof_mismatch`, or `action_not_in_scope`.

### 5.6 Trusted Principal Anchoring

The chain root is the only link not validated by signature alone — the verifier must know to trust the root principal independently. This anchoring is part of deployment policy: a verifier for a healthcare claim system may anchor at the patient's verified-identity DID; a verifier for a corporate spending agent may anchor at the CFO's DID; a verifier for general public services may anchor at the user's federated identity provider.

Trust-set bootstrap is out of scope of the protocol itself. PAD-008 (Hybrid Identity Bootstrapping) describes one common approach: use existing identity infrastructure (GitHub SSH, mobile-phone identity providers, employer SSO) as the source of trusted-principal DIDs.

---

## 6. Revocation

### 6.1 Two Mechanisms

Vouch supports two complementary revocation mechanisms:

- **DID-level revocation**: revoke an entire DID, invalidating all credentials it has issued or ever will issue.
- **Credential-level revocation**: revoke a specific credential without affecting other credentials from the same issuer.

Most production deployments run both. DID-level revocation is appropriate for blanket kill switches (key compromise, agent decommissioning); credential-level revocation is appropriate for surgical retraction (regulatory hold on a specific transaction, suspension pending review).

### 6.2 DID-Level Revocation Registry

The protocol defines a revocation registry interface (`RevocationStoreInterface`). A revoked DID is recorded as a `RevocationRecord` with `did`, `revoked_at`, `reason`, and `revoked_by`. Reference implementations include in-memory, file, and Redis backends.

Verifiers consult the registry on every credential verification. If the issuing DID is in the registry, the credential is rejected with `issuer_revoked`. The registry's cache TTL is operator-configurable; a typical default is 60 seconds.

### 6.3 BitstringStatusList for Per-Credential Revocation

For per-credential revocation, Vouch uses W3C BitstringStatusList [VC-BITSTRING-STATUS-LIST]. The issuer maintains a published `BitstringStatusListCredential` whose `credentialSubject.encodedList` is a gzip-compressed, base64url-encoded bitstring. Each Vouch credential includes a `credentialStatus` property:

```json
"credentialStatus": {
  "id": "https://issuer.example/status/1#42",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "42",
  "statusListCredential": "https://issuer.example/status/1"
}
```

A verifier fetches the status list, decompresses, reads bit 42; if the bit is set, the credential is revoked. The protocol's `StatusListFetcher` caches the status list with a configurable TTL and supports conditional GETs (`If-None-Match`, `If-Modified-Since`) for efficient re-validation.

### 6.4 Cross-Language Equivalence

The three reference implementations produce semantically equivalent BitstringStatusList credentials:

- **Python and TypeScript**: byte-identical encoded output. Both use zlib DEFLATE through their language's standard library.
- **Go**: produces a valid DEFLATE stream from `compress/flate`. The bytes differ slightly from Python/TypeScript (different DEFLATE encoder choices), but the decompressed bitstring is identical. The spec mandates equivalence of the decompressed bitstring, not byte-identity of the gzip envelope.

All three implementations are verified against a cross-language test vector at `test-vectors/bitstring-status-list/vector.json`.

### 6.5 Sizing and Cursor Persistence

The W3C BitstringStatusList minimum length is 131,072 bits (16 KiB uncompressed; tens of bytes compressed when sparse). One status list accommodates 131,072 credentials. For larger issuers, a fresh status list is allocated as exhaustion approaches; the `credentialStatus.statusListCredential` URL on each credential identifies its list.

The issuer's allocation cursor (next free index) must persist across restarts; it is **not recoverable** from the bitstring alone. The reference implementations expose a `to_state_dict`/`from_state_dict` pattern for durable storage in Redis, Postgres, or S3.

---

## 7. Hybrid Post-Quantum Cryptosuite

### 7.1 Motivation

NIST's selection of ML-DSA-44 (FIPS 204) as a standardized post-quantum digital signature [NIST-FIPS-204] places a known cryptographic transition on the protocol's horizon. Ed25519 will not survive a sufficiently large fault-tolerant quantum computer. The transition window is uncertain but real, and credentials with multi-year audit retention requirements (regulated healthcare, financial settlement) cannot afford to be signed with an algorithm that will be broken before the retention window expires.

The protocol's response is `hybrid-eddsa-mldsa44-jcs-2026`: a cryptosuite that binds an Ed25519 signature and an ML-DSA-44 signature to the same JCS-canonicalized payload, allowing graceful verifier downgrade and forward migration.

### 7.2 Construction

The hybrid `proofValue` is the byte-concatenation:

```
proofValue = base58btc( ed25519_signature || mldsa44_signature )
            (64 bytes)    (2,420 bytes)
            ───────────── 2,484 bytes total
```

Both signatures are computed over the same JCS-canonical credential bytes (the credential minus `proof.proofValue`, JCS-canonicalized). The Ed25519 signature is exactly 64 bytes; the ML-DSA-44 signature is exactly 2,420 bytes. The concatenation is then multibase base58btc-encoded for the `proofValue` string.

The construction is documented as PAD-040 (Hybrid Composite Signature Bound to Same Canonical Bytes).

### 7.3 Verifier Modes

A verifier may operate in any of three modes:

1. **Classical-only**: validate only the first 64 bytes (Ed25519). Useful when ML-DSA-44 libraries are unavailable or computationally expensive.
2. **PQ-aware single**: validate either signature; accept the credential if either verifies. Useful during transition periods when not all verifiers support both algorithms.
3. **Both-required**: validate both signatures; reject if either fails. The cautious mode, recommended for long-retention credentials.

The verifier's mode is policy, not part of the credential. The same credential is verifiable under any verifier mode without re-signing.

### 7.4 DID Document Representation

A signing DID supporting the hybrid cryptosuite publishes two verification methods in its DID Document — one Ed25519 Multikey, one ML-DSA-44 Multikey:

```json
"verificationMethod": [
  {
    "id": "did:web:agent.example.com#key-1",
    "type": "Multikey",
    "controller": "did:web:agent.example.com",
    "publicKeyMultibase": "z6Mki..."        // Ed25519
  },
  {
    "id": "did:web:agent.example.com#pq-key-1",
    "type": "Multikey",
    "controller": "did:web:agent.example.com",
    "publicKeyMultibase": "uMIIH..."        // ML-DSA-44 (multicodec discrimination)
  }
]
```

The Multikey multicodec prefix distinguishes the two algorithms; PAD-041 (Multikey Algorithm-Agnostic Verification Method Resolution) defines the discrimination rules.

### 7.5 Migration Path

A deployment migrates from classical to hybrid in three steps:

1. **Adopt hybrid signing**: the signer issues hybrid-cryptosuite credentials alongside or in place of classical credentials. Existing classical-only verifiers continue working (they read the first 64 bytes).
2. **Update verifiers**: deploy a verifier release that supports ML-DSA-44. Configure the verifier's mode (classical-only, PQ-aware-single, or both-required) based on the deployment's risk tolerance.
3. **Retire classical signing**: once all verifiers are PQ-aware, switch the signer to ML-DSA-44-only (a future cryptosuite). The hybrid cryptosuite is the migration vehicle, not the destination.

### 7.6 Performance and Size

Per-credential signing cost (Apple M3 Max, reference Python implementation):

- Ed25519 alone: ~50 µs
- ML-DSA-44 alone: ~3 ms
- Hybrid (concatenated): ~3 ms (dominated by ML-DSA-44)

Per-credential signature size (base58btc-encoded `proofValue`):

- Ed25519 alone: ~88 characters
- Hybrid: ~3,400 characters

The size delta matters for HTTP-header-conveyed credentials and for credentials embedded in QR codes. For application-body conveyance the overhead is negligible.

---

## 8. The State Verifiability Layer

### 8.1 Motivation: From Point-in-Time to Continuous

The credential layer addresses *did the agent claim authorization at time T*. The State Verifiability layer addresses operational questions arising *after* that: is the agent still behaving correctly *now*? Has it drifted out of policy? Has it been substituted? Has it crashed silently and been replayed by an adversary?

A long-running agent without continuous attestation accumulates risk. The longer it runs, the wider the window during which a compromise or substitution may go undetected. Heartbeat-style renewal makes that window bounded: the agent must demonstrate, on a schedule, that it is still the agent it was at credential issuance and that its behaviour is within policy.

### 8.2 The Heartbeat Protocol

The Heartbeat Protocol (defensive disclosure PAD-016) defines a periodic renewal cycle:

1. The agent's `HeartbeatSession` records actions and behavioural signals during each interval.
2. At the heartbeat boundary (default 60 seconds), the session constructs a `HeartbeatRequest`: it includes a behavioural digest, the running Merkle root of actions performed since the last heartbeat (PAD computed via RFC 6962 domain separation, see §8.4), the canary commit/reveal pair, and an interval index.
3. The agent submits the request to a validator (or quorum of validators).
4. The validator(s) check schema, behavioural digest structure, canary chain integrity, interval-index monotonicity, and trust policy.
5. On success, the validator returns a fresh `SessionVoucher` credential with the agent's renewed trust parameters.
6. On failure (broken canary, stale interval index, behavioural drift), no voucher is issued; the agent's existing voucher expires; the agent loses authority.

The Heartbeat Protocol inverts the traditional PKI trust model from "trusted until revoked" to **"untrusted until renewed."**

### 8.3 Trust Entropy Decay

Each SessionVoucher carries `initialTrust` and `decayLambda`. The effective trust at time `t` after the voucher's `issuedAt`:

$$\text{trust}(t) = \text{initialTrust} \cdot e^{-\lambda(t - t_0)}$$

Sensitive actions are gated by current trust. The protocol defines three reference thresholds:

- `TRUST_THRESHOLD_HIGH_STAKES = 0.9` — financial transfers, code deployment, regulated submissions.
- `TRUST_THRESHOLD_MEDIUM_STAKES = 0.75` — protected-health-information read, customer-data access.
- `TRUST_THRESHOLD_LOW_STAKES = 0.5` — status queries, idle activity.

Operators choose thresholds per deployment. The protocol's trust-entropy primitives (`compute_trust_at`, `check_trust_threshold`, `half_life_seconds`) provide the mathematical machinery; the threshold values are policy.

Heartbeat interval should be set to less than half the half-life so renewal stays ahead of decay. For $\lambda = 0.01$, half-life is approximately 69 seconds; a 30-second heartbeat is appropriate.

### 8.4 Behavioural Attestation

Per-interval, the `BehavioralCollector` records:

- API calls made by the agent (URL, token count, optional intent-drift score)
- Resources accessed
- Any policy-defined custom signals

At each heartbeat, the collector produces a `behavioralDigest`:

```json
{
  "apiCalls": 7,
  "tokensConsumed": 1340,
  "resourcesAccessed": ["order:42", "order:51"],
  "intentDriftScore": 0.13
}
```

Three reference intent-drift scorers ship with the SDK: arithmetic mean (`mean_drift_scorer`), maximum-of-samples (`max_drift_scorer`), and exponential-weighted moving average (`ewma_drift_scorer`). The drift score quantifies the divergence of the agent's recent activity from a baseline; a sharp rise across consecutive intervals signals a potential prompt-injection or policy-drift event.

To prevent unbounded growth, the collector caps the resources list at a configurable maximum (default 64); beyond the cap, the `apiCalls` count is still accurate but individual URIs are not enumerated.

### 8.5 Canary Commitments

The canary commit/reveal chain (PAD-032) provides cryptographic detection of silent agent failure. Each heartbeat commits to a fresh 256-bit secret hash; the next heartbeat reveals the prior secret. A missed heartbeat means the prior secret is never revealed; no subsequent heartbeat can resume the chain because the validator expects the missing reveal.

```python
# Agent side, managed by HeartbeatSession
chain = CanaryChain()
msg = chain.next_heartbeat()
# msg.commitment is included in this heartbeat
# msg.reveal is the previous secret (None on first interval)

# Validator side, managed by HeartbeatValidator
verifier = CanaryVerifier()
ok = verifier.observe(msg.commitment, msg.reveal)
if not ok:
    revoke_session_voucher()
```

The validator state per agent is one string (the last commitment). The state is cheap to persist (`MemoryHeartbeatStore`, `RedisHeartbeatStore`) and survives validator restarts.

### 8.6 Action Merkle Roots

A `HeartbeatRequest` includes the Merkle root of actions performed since the last heartbeat, computed over RFC 6962-domain-separated Merkle trees. Each action is hashed with `0x00` prefix (leaf); internal nodes are hashed with `0x01` prefix. This prevents the classical second-preimage attack on Merkle trees.

The validator does not validate every action — it cannot, the actions are application-specific — but it records the root. If an action is later disputed, the agent can produce an inclusion proof against the recorded root. The Merkle root is a tamper-evident commitment to the agent's claimed activity per interval.

### 8.7 Validator Quorum

Single validators are single points of failure. The `HeartbeatQuorum` distributes trust evaluation across multiple validators with different responsibilities:

```python
quorum = HeartbeatQuorum(
    validators=[
        QuorumValidator(validator=policy_validator,     role=ROLE_POLICY),
        QuorumValidator(validator=behavioral_validator, role=ROLE_BEHAVIORAL),
        QuorumValidator(validator=budget_validator,     role=ROLE_BUDGET),
    ],
    threshold=2,                  # 2-of-3
)
```

Roles are reference tags; deployments choose their own role taxonomy. The quorum threshold is M-of-N. Trust parameter aggregation across approving validators is configurable; the defaults (`initial_trust` takes minimum, `decay_lambda` takes maximum, `scope` is intersection) bias toward caution.

Weighted voting is supported: a senior validator may carry weight 2, a junior weight 1; the threshold is then evaluated against the weighted sum. PAD-046 (Algorithm Quorum Verification) describes the M-of-N machinery; the State Verifiability layer uses the same construction at the validator level.

### 8.8 Pluggable Persistence

`HeartbeatValidator` accepts an injected `HeartbeatStoreInterface` backend. The reference implementation ships `MemoryHeartbeatStore` (in-process, suitable for tests) and demonstrates the contract via tests. Production backends (Redis, Postgres, S3 with optimistic concurrency) are implementor-supplied. The state per agent is a JSON-serializable dictionary (`last_commitment`, `expecting_reveal`, `last_interval`); the schema is stable across the validator's lifetime.

---

## 9. Security Analysis

### 9.1 Threat Model

The protocol assumes:

- The cryptographic primitives (Ed25519, ML-DSA-44, SHA-256) are sound under their respective security assumptions.
- The verifier can resolve the issuer's DID Document via the agent's chosen DID method (`did:web` via HTTPS, `did:key` via decoding).
- The verifier has access to the revocation registry and to BitstringStatusList endpoints.
- The Identity Sidecar's process boundary is enforced by the host operating system: a malicious LLM process cannot read the Sidecar's memory.

The protocol does **not** assume:

- The LLM is trustworthy. Prompt injection, jailbreak, and model substitution attacks are within the threat model.
- The transport layer is confidential. Credentials are designed to be exposed in transit (the signature establishes authenticity even when an adversary observes the credential).
- The agent's host platform is uncompromised. Root-level compromise of the host defeats any application-level defence, including this one.

### 9.2 Defended Threats

**Bearer-credential theft.** Vouch credentials are bound to the issuer's DID by signature; an adversary who copies a credential cannot reuse it to issue new credentials. The original credential is bound to its `intent.target` and `intent.resource`; it cannot be replayed against a different resource. Within its `validUntil` it could be replayed against the same resource, but the nonce store rejects repeat `id`s. After `validUntil`, the credential is no longer accepted.

**Prompt injection causing key exfiltration.** The Identity Sidecar (PAD-003) makes this attack class structurally impossible: the LLM process has no access to the private key.

**Prompt injection causing unauthorized credential issuance.** The Sidecar's intent allow-list (PAD-056) makes this attack class capability-bounded: the LLM may propose any intent it likes, but the Sidecar refuses to sign intents outside the deployment's allow-list.

**Replay across resources.** Each credential's `intent.resource` is part of the signed payload. Replaying against a different resource invalidates the signature.

**Delegation chain forgery.** Each link is a signed credential; forging a link requires possessing the delegating principal's key. Trusted-principal anchoring ensures the chain root is known to the verifier independently.

**Resource widening at delegation.** The chain validator's resource-narrowing rule rejects chains where any link grants access beyond its parent's scope.

**Long-running agent silent failure.** The Heartbeat Protocol's canary chain detects missed heartbeats: the next heartbeat cannot produce the expected reveal, the chain breaks, and the validator refuses to renew.

**Key compromise.** DID-level revocation invalidates all credentials issued by the compromised key. The auto-rotation pipeline (PAD-058) automates rotation when leak detection fires.

**Post-quantum cryptanalysis.** The hybrid cryptosuite carries an ML-DSA-44 signature in addition to Ed25519, allowing the credential to be re-verified against the PQ signature once Ed25519 is broken. Verifiers in `both-required` mode are immune to single-algorithm cryptanalysis.

### 9.3 Residual Threats and Mitigations

**Within-allow-list abuse.** The Sidecar's allow-list bounds capability *type*, not *abuse within type*. A `send_email` capability granted to the assistant can be invoked against legitimate or illegitimate recipients within the operator's regex constraints. Mitigations: pattern strictness, rate limits, downstream verifier policy, and human-in-the-loop confirmation for ambiguous cases.

**DID resolution failures.** If the issuer's DID Document is unreachable (DNS issue, server outage, expired TLS certificate), the credential cannot be verified. Verifiers MUST fail closed (`did_resolution_failed`) rather than accept unverified credentials. Operators SHOULD monitor DID Document availability.

**Trusted-principal anchor compromise.** If a trusted-principal DID is compromised, the adversary can construct delegation chains rooted at that DID that authorize arbitrary leaf actions within the principal's scope. Defence: rotate trusted-principal keys regularly; require multi-key signing at the root for high-stakes deployments.

**Side-channel attacks on the Sidecar.** Timing, power, or cache-side channels could in principle extract key material from the Sidecar process. Defence is implementation-dependent: KMS/HSM backends with side-channel-protected hardware are appropriate for high-assurance deployments.

---

## 10. Cross-Language Interoperability

### 10.1 Test Vectors

The protocol ships cross-language test vectors verifying that Python, TypeScript, and Go implementations produce byte-identical credentials given identical inputs:

- `test-vectors/jcs/` — JSON Canonicalization Scheme reference outputs.
- `test-vectors/eddsa-jcs-2022/` — full credential signing test vectors for the classical cryptosuite.
- `test-vectors/hybrid-eddsa-mldsa44/` — full credential signing test vectors for the hybrid cryptosuite.
- `test-vectors/bitstring-status-list/vector.json` — BitstringStatusList encoding test vector. Python and TypeScript produce byte-identical output; Go produces a semantically equivalent DEFLATE stream (different encoder, identical decompressed bitstring).
- `test-vectors/sidecar-contract/` — HTTP wire-contract test suite covering `/health`, `/did`, `/sign` endpoints; verifies all three sidecar implementations accept and reject the same inputs.

### 10.2 Reference Implementation Properties

| Implementation | Language | Lines of code | Tests | Cryptosuites | Sidecar tier |
|---|---|---|---|---|---|
| `vouch/` | Python 3.10+ | ~4,500 | 350 | classical + hybrid | Lightweight + Dev |
| `packages/sdk-ts/` | TypeScript 5+ | ~3,200 | 120 | classical + hybrid | Lightweight |
| `go-sidecar/` | Go 1.21+ | ~2,800 | 75 | classical + hybrid | Production |

All three pass the cross-language test vectors. CI runs the vectors on every commit, and rejects merges that introduce divergence.

### 10.3 Known Implementation Divergences

The only documented divergence is in BitstringStatusList byte-encoding: Python and TypeScript use `zlib`'s DEFLATE encoder, which produces byte-identical output for identical bitstrings; Go's `compress/flate` produces a valid but different DEFLATE stream. The spec requires equivalence of the **decompressed** bitstring; all three implementations agree on the decompressed bitstring and therefore on every credential's revocation status. Verifiers and issuers interoperate across all three.

---

## 11. Discussion

### 11.1 Limitations

**State Verifiability is Python-only at the runtime level.** The data formats (SessionVoucher, behavioural digest, canary commitment, heartbeat request) are cross-language and verifiable in any of the three implementations. The runtime orchestration (`HeartbeatSession`, `HeartbeatScheduler`, `HeartbeatValidator`, `HeartbeatQuorum`) is implemented in Python only. TypeScript and Go ports are work in progress at the time of publication.

**Trusted-principal anchoring is deployment-specific.** The protocol does not standardize how a verifier discovers its trusted principals. Each deployment configures this independently. Standardization here would benefit cross-deployment federation but is outside this paper's scope.

**Confidentiality of sensitive intents is not addressed in v0.1-draft.** Vouch credentials are non-confidential; an observer in the credential's transit path reads its intent. For deployments handling regulated content (PHI, financial routing instructions), the next minor revision will add an optional confidentiality profile using post-quantum key encapsulation (ML-KEM-768). This is reserved future work.

**The Identity Sidecar's allow-list is a static configuration.** Dynamic capability adjustment (granting `send_money` for a specific 60-second window, then auto-revoking) is achievable through the protocol's normal credential validity windows but requires care to compose with the Sidecar's static allow-list. PAD-053 (Time-Bounded Ephemeral Rules) describes one approach for related contexts.

### 11.2 Adoption Path

The protocol has been validated against three reference implementations and a cross-language test-vector battery. Adoption requirements for a new deployment:

1. Generate an issuer DID and publish its DID Document.
2. Choose a Sidecar tier (Go for production, Python or TypeScript for lighter deployments).
3. Configure the Sidecar's allow-list with the deployment's action vocabulary.
4. Wire the agent's tool-call layer to call the Sidecar's `/sign` endpoint instead of directly calling external APIs.
5. Deploy a verifier — either as a library at the API boundary, or as a separate service — for the deployment's external services.
6. For long-running agents, deploy at least one Heartbeat validator (or a quorum of three for regulated deployments).

End-to-end onboarding effort is on the order of one to two engineering days for the credential layer alone, and another two to four days for state verifiability and quorum.

### 11.3 Standards Alignment

The protocol is currently in W3C Credentials Community Group incubation as of the publication date. The W3C CG Report (Spec v0.1-draft) is available at the URL given in the front matter. The protocol composes with — does not replace — existing standards (VC 2.0, DID Core, Data Integrity, Controlled Identifiers, BitstringStatusList, JCS, FIPS 204).

### 11.4 Open Prior Art

Fifty-eight defensive prior-art disclosures (PAD-001 through PAD-058) accompany the protocol. The full disclosure portfolio is available at `https://github.com/vouch-protocol/vouch/tree/main/docs/disclosures/`. Each disclosure is licensed under CC0 (the disclosure document itself) and Apache 2.0 (the corresponding reference implementation, where applicable).

The disclosure portfolio establishes that the design choices documented in this paper are public prior art, not patentable claims. We invite the community to build, fork, and extend the protocol; we expect that the spec will continue to evolve as deployment experience accumulates.

### 11.5 Future Work

Four directions are actively under development at the time of publication:

1. **TypeScript and Go ports of the State Verifiability runtime.** The data formats are cross-language; the orchestration is currently Python-only.
2. **Confidentiality profile for sensitive intents** using ML-KEM-768 key encapsulation.
3. **Hosted continuous leak monitor** that closes the loop from PAD-058: webhook-driven repository scanning, automated DID rotation, dual-signed migration credentials, verifier broadcast. Open-source CLI scanner and Gatekeeper extension; hosted continuous component as a commercial extension.
4. **AI-assisted developer tooling distributed as Claude Skills / Custom GPTs / Gemini Gems** (PAD-057), allowing developers to receive Vouch integration guidance through their own AI tool subscriptions with zero protocol-vendor inference cost.

The protocol's State Verifiability runtime, the hybrid post-quantum cryptosuite, the dual-signed migration credential format of PAD-058, and the validator-quorum composition each merit follow-up papers; outlines are in preparation.

---

## 12. Conclusion

We have presented the Vouch Protocol, an open standard for cryptographic identity and continuous state verifiability of autonomous AI agents. The protocol composes Verifiable Credentials, Decentralized Identifiers, Data Integrity proofs, and post-quantum cryptosuites with two novel layers: an Identity Sidecar pattern that isolates the agent's key from the LLM and bounds the agent's capabilities by an enforced allow-list, and a State Verifiability layer that renews trust continuously via heartbeat, decays trust exponentially in the interval, attests behaviour cryptographically, and detects silent failure through canary commit/reveal chains.

Three reference implementations (Python, TypeScript, Go) interoperate at the credential-byte level. The protocol is open under Apache 2.0; fifty-eight defensive disclosures keep the design space open under CC0.

The accountability gap in agent identity is solvable today. The cryptographic primitives are sound, the standards exist, and the implementation effort is bounded. Vouch is one realization of a path the open agent-identity ecosystem will increasingly need: from "the bearer has access" to "this specific agent issued this specific intent under this specific authorization chain, verifiable in seconds, with cryptographic rather than logbook evidence."

---

## Acknowledgements

The author thanks Manu Sporny and the W3C Verifiable Credentials Working Group for foundational work on Verifiable Credentials, Data Integrity, and the eddsa-jcs-2022 cryptosuite; the W3C Credentials Community Group for hosting and reviewing the incubation; the IETF JOSE working group for ongoing work on PQ/T composite signatures; the C2PA technical committee for content-provenance complementarity; and the open-source community of contributors and reviewers whose feedback shaped many of the choices documented here.

---

## References

[C2PA-1.4] Coalition for Content Provenance and Authenticity. *C2PA Technical Specification 1.4*. 2024.

[DID-CORE] World Wide Web Consortium. *Decentralized Identifiers (DIDs) v1.0.* W3C Recommendation, 19 July 2022.

[MCP-2025] Anthropic. *Model Context Protocol Specification.* 2025.

[NIST-FIPS-204] National Institute of Standards and Technology. *Module-Lattice-Based Digital Signature Standard.* FIPS 204, August 2024.

[RFC 6749] Hardt, D. *The OAuth 2.0 Authorization Framework.* IETF RFC 6749, 2012.

[RFC 6962] Laurie, B., Langley, A., and Kasper, E. *Certificate Transparency.* IETF RFC 6962, 2013.

[RFC 8785] Rundgren, A., Jordan, B., Erdtman, S. *JSON Canonicalization Scheme (JCS).* IETF RFC 8785, June 2020.

[RFC 9700] Lodderstedt, T., Bradley, J., Labunets, A., Fett, D. *OAuth 2.0 Security Best Current Practice.* IETF RFC 9700, 2025.

[Strong2018] Strong, J. *SPIFFE: Universal Workload Identity.* Linux Foundation, 2018.

[VC-BITSTRING-STATUS-LIST] World Wide Web Consortium. *Bitstring Status List v1.0.* W3C Candidate Recommendation, 2024.

[VC-DATA-INTEGRITY] World Wide Web Consortium. *Verifiable Credential Data Integrity 1.0.* W3C Candidate Recommendation, 2024.

[VC-DM-2.0] World Wide Web Consortium. *Verifiable Credentials Data Model v2.0.* W3C Candidate Recommendation, 2024.

[ZCAP-LD] World Wide Web Consortium Credentials Community Group. *Authorization Capabilities for Linked Data v0.3.* Draft Community Group Report.

### Defensive Disclosures Cited

[PAD-001] Cryptographic Agent Identity. Gaddam, December 2025.
[PAD-002] Chain of Custody Delegation. Gaddam, January 2026.
[PAD-003] Identity Sidecar Pattern. Gaddam, January 2026.
[PAD-008] Hybrid Identity Bootstrapping. Gaddam, January 2026.
[PAD-014] Vouch Sonic: Robust Acoustic Provenance. Gaddam, January 2026.
[PAD-016] Dynamic Credential Renewal / Heartbeat Protocol. Gaddam, February 2026.
[PAD-024] Temporal Video Fingerprinting. Gaddam, February 2026.
[PAD-031] Adversarial Provenance Honeypots. Gaddam, April 2026.
[PAD-032] Cryptographic Mortality Protocol. Gaddam, April 2026.
[PAD-039] JCS Deterministic Multi-Party Trust State. Gaddam, April 2026.
[PAD-040] Hybrid Composite Signature Bound to Same Canonical Bytes. Gaddam, April 2026.
[PAD-041] Multikey Algorithm-Agnostic Verification. Gaddam, April 2026.
[PAD-042] Standardized Metadata Schema. Gaddam, April 2026.
[PAD-045] Proof of Non-Hallucination via Cryptographic Retrieval Anchoring. Gaddam, April 2026.
[PAD-046] Algorithm Quorum Verification. Gaddam, April 2026.
[PAD-047] Verifiable Delay Functions for Rate-Limited Agent Actions. Gaddam, April 2026.
[PAD-053] Time-Bounded Ephemeral Rules. Gaddam, April 2026.
[PAD-056] Capability-Bounded AI Assistant Output via Intent Allow-List. Gaddam, May 2026.
[PAD-057] BYO-LLM Distribution of Protocol Capabilities. Gaddam, May 2026.
[PAD-058] Automated DID Rotation on Leak Detection. Gaddam, May 2026.

Full disclosure portfolio: https://github.com/vouch-protocol/vouch/tree/main/docs/disclosures/

---

## Appendix A: Reference Implementations

- **Python**: `pip install vouch-protocol`. Source: https://github.com/vouch-protocol/vouch/tree/main/vouch/
- **TypeScript**: `npm install vouch-protocol`. Source: https://github.com/vouch-protocol/vouch/tree/main/packages/sdk-ts/
- **Go**: `go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest`. Source: https://github.com/vouch-protocol/vouch/tree/main/go-sidecar/

## Appendix B: Test Vectors

All test vectors are at https://github.com/vouch-protocol/vouch/tree/main/test-vectors/. The set covers JCS canonicalization (`jcs/`), eddsa-jcs-2022 cryptosuite (`eddsa-jcs-2022/`), hybrid-eddsa-mldsa44-jcs-2026 cryptosuite (`hybrid-eddsa-mldsa44/`), BitstringStatusList encoding (`bitstring-status-list/`), and sidecar HTTP contract (`sidecar-contract/`).

## Appendix C: Specification Document

The full Vouch Protocol Specification, currently Spec v0.1-draft in W3C Credentials Community Group incubation, is at https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md.

---

*End of paper.*
