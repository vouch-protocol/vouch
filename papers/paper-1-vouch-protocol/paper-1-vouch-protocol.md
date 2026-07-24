---
abstract: |
  Autonomous AI agents now make decisions that matter: they move money,
  submit regulated filings, read clinical records, commit code. The
  credentials those agents use to do this (API keys, OAuth bearer
  tokens, shared service accounts) were designed for a human clicking
  through a session. They prove access. They do not prove who authorized
  that action, what the agent intends to do, or whether the agent is
  still trustworthy by the time it acts.

  We present the **Vouch Protocol**: an open specification with a
  byte-exact Rust core and software development kits in seven languages
  (Python, TypeScript, Go, C++, .NET, JVM, and Swift) for
  cryptographically identifying autonomous AI agents and binding every
  action they take to a signed Verifiable Credential. Each credential
  carries the agent's identity, the specific intent (action, target,
  resource), the delegation chain from the original human principal down
  to the agent, and a freshness window after which the credential stops
  being valid.

  Per-action signing is necessary but not sufficient. Once an agent has
  been admitted, the next question is whether it is still behaving
  correctly *right now*, after we let it through the door. The
  protocol's *State Verifiability layer* answers that with four
  mechanisms: (1) trust entropy decay, where credential trust falls
  exponentially over time and must be renewed before consequential
  actions; (2) behavioral attestation digests, lightweight per-interval
  summaries of the agent's API calls, resources accessed, and intent
  drift; (3) canary commit/reveal chains, providing cryptographic
  detection of silent agent failure or substitution; and (4) $M$-of-$N$
  validator quorum, distributing trust evaluation across
  role-specialized validators (policy, behavior, budget).

  A cluster of recent systems enforces *pre-action authorization*: they
  intercept an agent's tool call and evaluate it against a declarative
  policy before execution (Uchibeke 2026; Fatmi 2026; Errico 2026; Lavi
  2026; Palumbo et al. 2026). Vouch addresses the complementary and
  broader problem. Rather than checking an action against a finite
  authored allow-list, it verifies the action against the principal's
  cryptographically signed *intent*, traced through a delegation chain
  to the root human author, which covers the open-ended space of
  legitimate actions that a finite policy cannot enumerate. Because the
  credential format is standards-native (W3C Verifiable Credentials
  secured by Data Integrity, the `eddsa-jcs-2022` cryptosuite), any
  conforming verifier can consume it, and the protocol extends
  verification with a correctness layer (reasoning-faithfulness and
  retrieval-grounding) that policy enforcement alone does not provide.

  The protocol is built on W3C Verifiable Credentials Data Model 2.0
  with Data Integrity proofs: the `eddsa-jcs-2022` cryptosuite, which
  signs Ed25519 over RFC 8785 JCS-canonicalized payloads. For the
  post-quantum transition, the protocol defines a *dual-proof profile*
  in which a credential carries two independent Data Integrity proofs on
  the same JCS-canonicalized bytes: one `eddsa-jcs-2022` proof
  (classical Ed25519) and one `mldsa44-jcs-2026` proof (ML-DSA-44, FIPS
  204). Verifiers can downgrade gracefully, and the wire format requires
  no Vouch-specific composite cryptosuite identifier.

  This paper covers the credential format, the Identity Sidecar pattern
  that isolates an agent's signing key from the LLM process,
  delegation-chain construction with resource narrowing and
  depth-limited validation, the BitstringStatusList revocation
  mechanism, the Heartbeat Protocol's renewal cycle, the dual-proof
  post-quantum profile and its same-canonical-bytes property, and the
  State Verifiability runtime. We then work through the adversarial
  cases that motivated the design (prompt injection, key exfiltration,
  replay across resources, post-quantum cryptographic obsolescence) and
  what the protocol does about each. Because all seven language SDKs
  bind to a single Rust core, credentials produced through any SDK are
  byte-identical, and a published RFC 8785 JCS test-vector battery
  verifies this on every release.

  The implementation is open-source under Apache 2.0. Sixty defensive
  prior-art disclosures accompany the specification under CC0 to keep
  design innovations openly available.

  **Index Terms:** AI agent identity, Verifiable Credentials,
  decentralized identifiers, intent-bound authorization, pre-action
  authorization, reasoning faithfulness, retrieval grounding,
  post-quantum cryptography, dual-proof signatures, JCS
  canonicalization, prompt injection, delegation, continuous
  attestation, behavioral provenance.
author:
- Ramprasad Anandam Gaddam
bibliography: "C:/Users/rampy/AppData/Local/Temp/references.bib"
date: |
  Version v0.1 May 2026\
  *This paper is released under CC BY 4.0; the reference implementations
  under Apache 2.0; the defensive disclosures under CC0.*\
  Vouch-signed by Vouch Protocol: <https://vch.sh/arxiv-1>
title: " Vouch Protocol: Cryptographic Identity and Continuous State
  Verifiability for Autonomous AI Agents "
---

# Introduction

## The Accountability Gap

Modern AI agents (LangChain pipelines, CrewAI swarms, AutoGPT-style
autonomous workers, Model Context Protocol-driven assistants)
increasingly take actions that human-level credentials were never
designed to authorize. An LLM-driven agent submitting an insurance
claim, placing a stock order, querying a patient's electronic health
record, or auto-committing code to a production branch is performing a
real action with real consequences. When that action requires audit,
dispute resolution, or regulatory review, the only artefact available is
a log entry naming an API key. The key is shared, was rotated three
months ago, and gives no insight into which specific agent generation,
which orchestration layer, which prompt, or which user-level principal
authorized the action.

The accountability gap has three structural sources:

1.  **Identity opacity.** Bearer credentials (API keys, JWTs, OAuth
    access tokens) prove access by possession, not by signature over an
    intent. An entity in possession of the bearer can take any action
    the bearer permits; nothing in the credential reflects which
    specific entity, in which specific context, with which specific
    upstream authorization, did so.

2.  **Intent omission.** Even when an action is logged, the intent it
    represented is recorded in application-specific log formats with no
    cryptographic binding. A log entry
    "`agent-prod-2 called submit_claim`" can be forged by anyone with
    access to the log writer. The action's parameters, the resource it
    targeted, and the authorization chain are not cryptographically
    bound to the agent's identity.

3.  **Trust monotonicity.** Existing identity systems trust credentials
    until they are explicitly revoked. A compromised agent continues
    operating until a human detects misbehavior and pushes a revocation.
    For autonomous agents, which may operate in regulated,
    latency-sensitive, or sparsely-monitored contexts, the gap between
    compromise and revocation may span hours or days, during which the
    compromised agent has uninterrupted authority.

## The Vouch Protocol Approach

The Vouch Protocol addresses these failures with three composing layers:

1.  A **credential layer** in which every agent action is issued as a
    W3C Verifiable Credential signed by the agent's Decentralized
    Identifier (DID) via a Data Integrity proof. The credential's
    `credentialSubject.intent` field carries the action verb, the target
    identifier, and the resource URI bound together. The credential's
    `validUntil` is short (commonly 5 minutes). The proof is
    `eddsa-jcs-2022` over the JCS-canonicalized credential bytes,
    optionally paired with a second `mldsa44-jcs-2026` proof on the same
    credential for the dual-proof post-quantum profile.

2.  A **delegation layer** in which credentials chain together, each
    link cryptographically attesting to a principal-to-sub-principal
    authorization. Resource scope must narrow at each link; chain depth
    is bounded; the root principal is verifiable. Multi-agent systems
    gain end-to-end attribution: "the patient authorized the clinician,
    who authorized their EHR agent, who authorized the prior-auth
    sub-agent, who submitted this credential" is a single auditable
    chain.

3.  A **state verifiability layer** in which long-running agents renew
    their credentials on a heartbeat schedule. Trust decays
    exponentially over time; behavioral attestation digests are computed
    per interval; canary commit/reveal chains detect silent failures; an
    $M$-of-$N$ validator quorum distributes trust evaluation across
    role-specialized policy / behavior / budget validators. An agent
    that cannot heartbeat, because it crashed, is compromised, or has
    drifted out of policy, loses authority by entropy decay; a missed
    heartbeat is cryptographically detectable.

Together, the three layers move from "the agent had a key" to "the agent
issued a signed credential at time $T$, declaring action $A$ on resource
$R$, with the authorization of principals $P_1 \to P_2 \to P_n$,
verifiable against the agent's published DID Document and the issuer's
revocation registry, with a freshness window of 300 seconds and a
running behavioral attestation showing the agent is operating within its
declared scope."

The protocol's central claim is one of *intent verification* rather than
*policy authorization*. A recent and active line of work intercepts an
agent's tool call and checks it against an authored declarative policy
before execution (Uchibeke 2026; Fatmi 2026; Errico 2026; Lavi 2026;
Palumbo et al. 2026). A declarative policy is a finite allow-list and
can admit only the actions its author anticipated; the space of
legitimate actions an agent may need to take for a principal is
open-ended. Vouch instead verifies each action against the principal's
cryptographically signed intent, carried down a delegation chain to the
root human author (§[5](#sec:delegation){reference-type="ref"
reference="sec:delegation"}), and adds a correctness layer that checks
reasoning-faithfulness (Gaddam 2026d) and retrieval-grounding (Gaddam
2026e). The two approaches compose: a policy gate can bound capability
type while Vouch establishes identity, intent, and correctness for each
admitted action. §[2](#sec:related){reference-type="ref"
reference="sec:related"} develops this positioning against the specific
systems in that cluster.

## Design Goals

Six design goals shaped the protocol:

- **Standards alignment over invention.** Where existing open standards
  suffice (W3C VC 2.0, Data Integrity, DIDs, BitstringStatusList, RFC
  8785 JCS, NIST FIPS 204), the protocol composes with them and does not
  introduce new primitives.

- **LLM-isolated key material.** The agent's private signing key must
  never appear in the LLM's context window. The Identity Sidecar pattern
  isolates the key in a separate process that the LLM cannot reach.

- **Byte-identical canonicalization across languages.** All seven
  language SDKs bind to a single Rust core (`vouch-core`); a credential
  produced through any SDK verifies against any other. JCS (RFC 8785) is
  the canonical form (Gaddam 2026b).

- **Cryptographic agility.** The protocol must accommodate the
  post-quantum transition without changing the canonical payload format.
  The dual-proof profile attaches two independent Data Integrity proofs
  on the same JCS-canonicalized bytes; verifiers select the trust level
  they require.

- **Continuous verifiability, not point-in-time authentication.** Trust
  must be renewed under observation; an agent that goes silent must lose
  authority automatically.

- **Open prior art.** Every novel design pattern is published as a
  defensive disclosure (Apache 2.0 code, CC0 disclosure) to keep the
  design space open.

## Contribution Summary

This paper contributes:

1.  The Vouch Credential format and its Data Integrity proof
    construction (`eddsa-jcs-2022`).

2.  The Identity Sidecar pattern with intent allow-list enforcement at
    the sidecar layer, defended against prompt injection by
    construction.

3.  The delegation chain mechanism with resource narrowing, depth-limit,
    and trusted-principal anchoring.

4.  The BitstringStatusList integration for per-credential revocation,
    plus DID-level revocation for issuer-key compromise.

5.  The dual-proof post-quantum profile, in which a credential carries
    two independent Data Integrity proofs (`eddsa-jcs-2022` and
    `mldsa44-jcs-2026`) on the same JCS-canonicalized bytes.

6.  The State Verifiability runtime: trust entropy decay, behavioral
    attestation digests, canary commit/reveal chains, $M$-of-$N$
    validator quorum.

7.  A byte-exact Rust core (`vouch-core`) with SDKs in seven languages
    (Python, TypeScript, Go, C++, .NET, JVM, Swift) that produce
    byte-identical credentials, backed by a published cross-language JCS
    test-vector battery (Gaddam 2026b).

8.  A positioning of intent verification as distinct from, and broader
    than, policy-based pre-action authorization, extended with a
    correctness layer (reasoning-faithfulness (Gaddam 2026d),
    retrieval-grounding (Gaddam 2026e)) absent from that body of work.

## Paper Organization

Section [2](#sec:related){reference-type="ref" reference="sec:related"}
reviews related work and clarifies Vouch's position in the
agent-identity landscape.
Section [3](#sec:credential){reference-type="ref"
reference="sec:credential"} defines the credential format.
Section [4](#sec:sidecar){reference-type="ref" reference="sec:sidecar"}
presents the Identity Sidecar architecture.
Section [5](#sec:delegation){reference-type="ref"
reference="sec:delegation"} develops the delegation chain construction
and its verification. Section [6](#sec:revocation){reference-type="ref"
reference="sec:revocation"} details the revocation mechanisms.
Section [7](#sec:hybrid){reference-type="ref" reference="sec:hybrid"}
presents the dual-proof post-quantum profile.
Section [8](#sec:state){reference-type="ref" reference="sec:state"}
introduces the State Verifiability layer.
Section [9](#sec:security){reference-type="ref"
reference="sec:security"} analyses the protocol's security properties
against an adversarial threat model.
Section [10](#sec:interop){reference-type="ref" reference="sec:interop"}
reports cross-language interoperability results.
Section [11](#sec:discussion){reference-type="ref"
reference="sec:discussion"} discusses limitations and future work.
Section [12](#sec:conclusion){reference-type="ref"
reference="sec:conclusion"} concludes.

# Related Work and Positioning {#sec:related}

## Workload Identity Systems

SPIFFE and SPIRE (Strong and SPIFFE Project 2018) define workload
identity for service-to-service communication in cloud environments.
SPIFFE issues short-lived X.509 SVIDs or JWT-SVIDs to workloads via
attestation against the host platform. SPIFFE establishes *that* a
workload is who it claims to be (via attestation against the runtime),
but does not bind the workload's actions to the identity at the
per-action level. A SPIFFE-authenticated workload making an HTTP call to
a downstream service authenticates the call via mutual TLS; the call's
intent (target resource, requested action, authorization chain) is not
part of the authenticated payload.

Vouch composes with SPIFFE: a SPIFFE-attested workload may also be a
Vouch issuer, holding a Vouch DID whose verification methods are
bootstrapped from the SVID. The Vouch credential then provides the
per-action binding that SPIFFE does not.

## OAuth 2.0 / OAuth 2.1 and Token-Based Access

OAuth 2.x (Hardt 2012; Lodderstedt et al. 2025) is the dominant
access-grant protocol for HTTP APIs. Access tokens are bearer
credentials authorizing the client to call defined scopes on the
resource server. OAuth makes no claim about which specific agent within
a client used the token, what the agent intended, or whether the agent's
runtime state remains within policy.

Vouch is complementary to OAuth at the application layer. A Vouch
credential may accompany an OAuth-authorized HTTP request, providing the
agent-identity, intent, and delegation that OAuth's bearer model omits.
Resource servers may verify both (OAuth for coarse access authorization
and Vouch for action-specific identity and intent), or may use Vouch
alone for agent-to-agent communication where OAuth's session model does
not fit.

## Decentralized Identifiers and Verifiable Credentials

The W3C Decentralized Identifiers (DID) Core (World Wide Web Consortium
2022) and Verifiable Credentials Data Model 2.0 (World Wide Web
Consortium 2024b) specifications define the underlying identity and
credential primitives Vouch uses. Vouch issues VCs as defined by
VC-DM-2.0, with DIDs as the issuer identifier. Vouch does not introduce
a new identity primitive; it specifies a credential subtype
(`VouchCredential`) and a per-action issuance pattern.

Among the many credential subtypes the VC ecosystem has produced
(student transcripts, professional certifications, vaccination records,
employment letters), Vouch occupies a distinct niche: per-action,
short-validity, agent-issued credentials describing what the agent is
about to do, not what it has been authorized to be.

## ZCAP-LD and Capability-Based Authorization

ZCAP-LD (W3C Credentials Community Group 2024) is a JSON-LD capability
authorization format that supports attenuation through delegation. ZCAP
capabilities are attenuated at each delegation: a parent capability is
restricted as it is delegated downward. The result is similar in shape
to a Vouch delegation chain.

Vouch's delegation differs in three respects:

1.  **Canonicalization**: Vouch uses RFC 8785 JCS, not JSON-LD
    canonicalization. JCS is simpler, has no external context
    dependencies, and produces byte-identical output across
    implementations more reliably.

2.  **Resource binding**: Each Vouch delegation link explicitly binds a
    `resource` URI. The chain validator enforces that child resources be
    sub-paths of parent resources, preventing capability widening at any
    link.

3.  **Chain semantics**: Vouch delegations are credentials in their own
    right (each link is a VC); ZCAP capabilities are stand-alone
    documents with their own data model.

## C2PA Content Credentials

The Coalition for Content Provenance and Authenticity (C2PA) defines
content-binding credentials for media assets (Coalition for Content
Provenance and Authenticity 2024). C2PA Content Credentials embed signed
provenance into media files (images, audio, video). Vouch is
complementary: a content-creation agent may sign a Vouch credential
authorizing the act of generating an image, then bind the image's C2PA
manifest to the same agent identity.

## Post-Quantum Signature Migration Frameworks

NIST's selection of ML-DSA-44 (FIPS 204) and SLH-DSA (FIPS 205) as
standardized post-quantum digital signature algorithms (National
Institute of Standards and Technology 2024) creates the migration
pressure Vouch addresses. The IETF's *draft-ietf-jose-pq-composite-sigs*
defines composite signatures for JOSE; the W3C Data Integrity community
has parallel work in progress, including Digital Bazaar's
`mldsa44-rdfc-2024-cryptosuite` family (Digital Bazaar, Inc. 2026) and
an upcoming JCS variant. Vouch's *dual-proof profile* is a
Data-Integrity-native realization that avoids inventing a composite
cryptosuite identifier: a single Vouch credential carries two
independent Data Integrity proofs in its `proof` array, one
`eddsa-jcs-2022` proof and one `mldsa44-jcs-2026` proof, both computed
over the same JCS canonical credential bytes. Verifiers in
classical-only mode validate the `eddsa-jcs-2022` proof and ignore the
rest; verifiers in PQ-aware mode validate the `mldsa44-jcs-2026` proof;
verifiers in both-required mode iterate the proof array and accept only
when every proof verifies.

## Pre-Action Authorization Systems {#sec:related-preaction}

A cluster of systems published between January and April 2026
establishes *pre-action authorization* as a distinct primitive for agent
safety. Uchibeke's Open Agent Passport intercepts an agent's tool calls
and evaluates them against a declarative policy before execution,
emitting a signed audit record for each decision (Uchibeke 2026).
Faramesh places a mandatory, transport-independent authorization
checkpoint ahead of any action that changes external state,
standardizing actions into a canonical representation and returning
permit, defer, or deny artifacts that executors must honor (Fatmi 2026).
AARM specifies a runtime that intercepts actions, evaluates them against
policy and intent alignment, and maintains tamper-evident records, with
a threat taxonomy covering prompt injection and confused-deputy
attacks (Errico 2026). Right-to-Act formalizes a pre-execution
admissibility boundary in which any unmet required condition halts or
defers execution, separating compensatory from non-compensatory decision
regimes (Lavi 2026). FORGE compiles declarative policies, written in a
Datalog-derived language over abstract predicates, into a reference
monitor that enforces them at each agent decision point (Palumbo et al.
2026).

These systems share an architecture: an enforcement point admits or
denies an action against an authored policy. They differ from Vouch in
three respects that this paper treats as the central distinction. First,
they are *policy-bound*: the admission decision is made against a
finite, declaratively authored rule set, which can only cover the
actions an author anticipated. Vouch is *intent-bound*: the decision is
made against the principal's cryptographically signed intent, traced
through a delegation chain to the root human author
(§[5](#sec:delegation){reference-type="ref"
reference="sec:delegation"}), covering the open-ended space of
legitimate actions a finite policy cannot enumerate. Second, none of
these systems anchors its decision in a standards-defined credential;
their audit records and decision artifacts are system-specific, whereas
a Vouch credential is a W3C Verifiable Credential secured by Data
Integrity (§[3](#sec:credential){reference-type="ref"
reference="sec:credential"}) that any conforming verifier can consume.
Third, none adds a correctness layer: Vouch additionally verifies
whether the agent's reasoning was faithful to the stated intent (Gaddam
2026d) and whether its outputs were grounded in retrieved evidence
rather than confabulated (Gaddam 2026e).

The two approaches are complementary rather than competing. A deployment
can run a pre-action policy gate and Vouch together: the policy gate
bounds capability *type*, and Vouch establishes who acted, under whose
signed intent, with what delegated authority, and whether the action was
reasoned faithfully. As a matter of record, the foundational primitives
Vouch builds on were placed in the public domain as dated defensive
disclosures contemporaneously with this cluster: the cryptographic
binding of agent identity to signed intent in December 2025 (Gaddam
2025), and the recursive, intent-bound delegation chain anchored to a
root human author in January 2026 (Gaddam 2026c).

# The Vouch Credential {#sec:credential}

## Format

A Vouch Credential is a W3C Verifiable Credential 2.0 with a
`VouchCredential` type tag, a `credentialSubject` carrying the agent's
intent, and a Data Integrity proof over the JCS-canonicalized credential
bytes. The format is defined in Section 5 of the Vouch Protocol
specification.

``` {.json language="json"}
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
    "proofValue": "z77CAhFw1rKB1wLQ541oZ55WD1rVcmkiHFnF8EcVs2A4..."
  }
}
```

The required fields beyond the VC 2.0 baseline:

- `type` MUST include `VouchCredential`.

- `credentialSubject.vouchVersion` MUST be present and equal to the
  protocol version this credential conforms to.

- `credentialSubject.intent.action`, `intent.target`, `intent.resource`
  MUST all be non-empty strings. Empty strings are treated as missing.

- `validFrom` MUST be in RFC 3339 form with `Z` UTC indicator (not
  `+00:00`).

- `validUntil` SHOULD be set to a short window (default 300 seconds from
  `validFrom`).

## The eddsa-jcs-2022 Cryptosuite

The default cryptosuite is `eddsa-jcs-2022` (W3C Data Integrity
registered identifier). The signing procedure:

1.  Construct the credential dictionary with all required fields,
    including the `proof` object except `proofValue`.

2.  Canonicalize the entire credential using RFC 8785 JCS. JCS specifies
    a strict deterministic ordering, escaping, and number formatting;
    the output is byte-identical across conforming implementations.

3.  Compute the SHA-256 digest of the canonical bytes.

4.  Compute the Ed25519 signature over the digest using the issuer's
    private key.

5.  Encode the signature in multibase base58btc form (the `z` prefix),
    producing approximately 88 characters.

6.  Set `proof.proofValue` to the multibase-encoded signature.

Verification reverses the process:

1.  Extract `proof.proofValue`, decode from multibase base58btc.

2.  Reconstruct the credential dictionary excluding `proof.proofValue`
    (other proof fields are part of the signed payload).

3.  JCS-canonicalize.

4.  Compute the SHA-256 digest of the canonical bytes.

5.  Resolve the issuer's DID Document, locate the verification method
    indicated by `proof.verificationMethod`, extract the Ed25519 public
    key (encoded as Multikey in the DID Document).

6.  Verify the Ed25519 signature over the digest.

## JCS Determinism Across Languages

JSON Canonicalization Scheme (RFC 8785) fixes the serialization that
Ed25519 signs. Rather than maintaining several independent
implementations in sync, the protocol exposes a single Rust core
(`vouch-core`) to seven languages (Python, TypeScript, Go, C++, .NET,
JVM, Swift) through WebAssembly and UniFFI bindings, so byte-identical
JCS output is a property of the shared core rather than of
cross-implementation discipline. A published JCS test-vector
battery (Gaddam 2026b) pins the canonical form, and any conforming
binding must reproduce it.

The byte-identity property is foundational: without it, a credential
produced through one SDK and a credential with the same logical content
produced through another would have different signatures, breaking
interoperability and federation across languages.

## Intent Replay Resistance

Each credential carries a unique `id` (typically a UUID URN). Verifiers
maintain a nonce store keyed on `id`. A credential whose `id` has
previously been seen is rejected (`nonce_replay`). The nonce store's TTL
must be at least the longest plausible credential `validUntil` to
prevent a credential from being replayed after the nonce store has
forgotten it.

Replay resistance is also enforced at the intent level: `intent.target`
and `intent.resource` are part of the signed payload. A credential
authorizing `submit_claim` on `claim:HC-001` cannot be replayed against
`claim:HC-002` without re-signing; the JCS canonical bytes differ.

# The Identity Sidecar Pattern {#sec:sidecar}

## Motivation

Modern AI agents are typically built around a Large Language Model. The
LLM is stochastic, non-deterministic, and vulnerable to prompt
injection. Exposing the agent's private signing key to the LLM's context
window creates three failure modes:

- **Key leak via prompt injection.** Adversarial content in retrieved
  documents, tool outputs, or user input can instruct the LLM to print
  the key as part of its output.

- **Unauthorized signing via jailbreak.** A jailbroken LLM may use the
  key to sign arbitrary intents, including intents not authorized by the
  principal.

- **Persistence in training data and logs.** Key material that passed
  through the LLM may end up in logged conversation transcripts,
  fine-tuning corpora, or vendor-side analytics.

Direct key exposure to the LLM is incompatible with the protocol's
security model.

## Architecture

The Identity Sidecar pattern separates the agent into two processes:

1.  **The Brain (stochastic).** The LLM. Holds zero cryptographic
    secrets. Reasons about which action to take and proposes intents to
    the Sidecar.

2.  **The Passport (deterministic).** A small, auditable process holding
    the private signing keys in its address space. Receives intent
    proposals from the Brain, applies a deterministic policy check, and
    issues credentials only when policy passes.

The Brain and the Passport communicate over a local IPC channel:
typically localhost HTTP, a UNIX domain socket, or an MCP transport. The
IPC boundary is the trust boundary.

## Just-In-Time Signing Flow

A signing operation proceeds:

1.  The Brain decides an action is appropriate. It constructs a proposed
    intent.

2.  The Brain submits the intent to the Sidecar over IPC.

3.  The Sidecar applies its policy: structural validation (required
    fields present), allow-list check (action type is in the deployed
    allow-list), and rate-limit check.

4.  If policy passes, the Sidecar constructs the full credential, signs
    it with the held private key, and returns the credential to the
    Brain.

5.  If policy fails, the Sidecar returns a structured error. No
    credential is produced.

The Sidecar's policy check is the *last line of defence* against a
compromised Brain. A prompt-injected LLM may propose any intent it
likes; the Sidecar refuses to sign anything outside the allow-list. The
capability bound on a compromised Brain is therefore structural, not
behavioural.

## Reference Implementations and Tier Hierarchy

Three reference Sidecar implementations accompany the protocol:

- **Go** (`go-sidecar/`): production-tier, KMS/HSM-backed, dual-proof PQ
  supported, sensitive-mode JWE wrapping, multi-tenant.

- **Python** (`vouch.sidecar.*`): lightweight tier for self-hosted
  Python stacks. File or environment keys. Intentionally omits KMS,
  dual-proof PQ, JWE, and multi-tenancy.

- **TypeScript** (`packages/sdk-ts/sidecar/`): lightweight tier for Node
  stacks. Same omissions as Python.

The HTTP wire contract is identical across all three. A shared contract
test suite verifies that all three implementations accept and reject the
same inputs and emit semantically equivalent credentials. The tier
hierarchy is informative guidance: deployers requiring KMS, FIPS,
dual-proof PQ, or multi-tenancy run the Go sidecar; deployers with
simpler requirements may run Python or TypeScript.

# Delegation Chains {#sec:delegation}

## Motivation

Multi-agent systems present an attribution problem: an action taken by a
leaf agent may have been authorized by a chain of principals: a user
authorized an assistant, which authorized a research agent, which
authorized a web-scraping sub-agent. When the action requires audit, the
leaf-only signing model loses the chain.

Vouch delegations are themselves Verifiable Credentials. Each link in a
chain is a credential signed by the delegating principal and identifying
the delegate. A leaf-action credential includes the full chain (or a
reference to it) so a verifier can reconstruct the authorization path
from root principal to leaf agent.

## Delegation Link Structure

A delegation link is a Vouch credential whose `credentialSubject` is
shaped:

``` {.json language="json"}
{
  "issuer": "did:web:assistant.example.com",
  "subject": "did:web:research-agent.example.com",
  "intent": {
    "action": "web_search",
    "target": "topic:climate-2026",
    "resource": "https://research-agent.example.com/agents/research-agent/scope/2026"
  },
  "validFrom": "2026-05-14T06:00:00Z",
  "validUntil": "2026-05-14T08:00:00Z",
  "proof": { "...DataIntegrityProof..." }
}
```

The link's `issuer` is the delegating principal; `subject` is the
delegate. The `intent` object (`action`, `target`, `resource`) describes
the authorized action and the resource URI under which it must fall;
`validFrom` and `validUntil` bound the delegation in time. Each link is
itself signed by its `issuer`.

## Chain Construction and the Resource Narrowing Rule

A chain is a list of delegation-link credentials, ordered from root
principal to leaf agent. At each link, the child's `intent.resource`
MUST be a sub-URI of, or equal to, the parent's `intent.resource`. The
narrowing rule prevents capability widening at any link: a delegate
cannot grant a sub-delegate more authority than it itself holds.

## Depth Limit

Chain depth is bounded to **five links maximum**. This limit prevents
pathological chains from inflating verification cost and from obscuring
the actual authorization path.

## Chain Validation

A verifier validating a leaf credential with an attached chain:

1.  Verifies the leaf credential's signature.

2.  Verifies the root link's `issuer` is in the verifier's set of
    trusted principals for the leaf action.

3.  For each adjacent pair (parent, child), verifies the parent link's
    `subject` equals the child link's `issuer`.

4.  For each link, verifies its `intent.resource` is a sub-URI of, or
    equal to, the parent link's `intent.resource`.

5.  For each link, verifies its `validFrom` and `validUntil` fall within
    the parent link's temporal bounds.

6.  Verifies each link's Data Integrity proof.

7.  Verifies the leaf credential's `intent.resource` is a sub-URI of the
    deepest link's `intent.resource`.

Any failure produces a structured rejection reason:
`untrusted_principal`, `chain_depth_exceeded`, `resource_not_narrowed`,
`temporal_bounds_exceeded`, `subject_issuer_mismatch`, or
`link_signature_invalid`.

# Revocation {#sec:revocation}

## Two Mechanisms

Vouch supports two complementary revocation mechanisms:

- **DID-level revocation**: revoke an entire DID, invalidating all
  credentials it has issued or ever will issue.

- **Credential-level revocation**: revoke a specific credential without
  affecting other credentials from the same issuer.

Most production deployments run both. DID-level revocation is
appropriate for blanket kill switches (key compromise, agent
decommissioning); credential-level revocation is appropriate for
surgical retraction (regulatory hold on a specific transaction,
suspension pending review).

## DID-Level Revocation Registry

The protocol defines a revocation registry interface
(`RevocationStoreInterface`). A revoked DID is recorded as a
`RevocationRecord` with `did`, `revoked_at`, `reason`, and `revoked_by`.
Reference implementations include in-memory, file, and Redis backends.

Verifiers consult the registry on every credential verification. If the
issuing DID is in the registry, the credential is rejected with
`issuer_revoked`. The registry's cache TTL is operator-configurable; a
typical default is 60 seconds.

## BitstringStatusList for Per-Credential Revocation

For per-credential revocation, Vouch uses W3C BitstringStatusList (World
Wide Web Consortium 2024a). The issuer maintains a published
`BitstringStatusListCredential` whose `credentialSubject.encodedList` is
a gzip-compressed, base64url-encoded bitstring. Each Vouch credential
includes a `credentialStatus` property pointing at its index. A verifier
fetches the status list, decompresses, reads the indicated bit; if the
bit is set, the credential is revoked.

The protocol's `StatusListFetcher` caches the status list with a
configurable TTL and supports conditional GETs (`If-None-Match`,
`If-Modified-Since`) for efficient re-validation.

# Dual-Proof Post-Quantum Profile {#sec:hybrid}

## Motivation

NIST's selection of ML-DSA-44 (FIPS 204) as a standardized post-quantum
digital signature (National Institute of Standards and Technology 2024)
places a known cryptographic transition on the protocol's horizon.
Ed25519 will not survive a sufficiently large fault-tolerant quantum
computer. The transition window is uncertain but real, and credentials
with multi-year audit retention requirements (regulated healthcare,
financial settlement) cannot afford to be signed with an algorithm that
will be broken before the retention window expires.

The protocol's response is the *dual-proof profile*: a credential
carries two independent W3C Data Integrity proofs on the same
JCS-canonicalized credential bytes, one `eddsa-jcs-2022` proof
(classical Ed25519) and one `mldsa44-jcs-2026` proof (ML-DSA-44). The
Data Integrity specification already defines the `proof` field as an
array, so the dual-proof construction is a natural use of existing
primitives and requires no Vouch-specific composite cryptosuite
identifier.

## Construction

The credential's `proof` field is an array of two Data Integrity proof
objects:

    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "...#key-ed25519",
        "proofPurpose": "assertionMethod",
        "proofValue": "z<base58btc(ed25519_sig)>"
      },
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "mldsa44-jcs-2026",
        "verificationMethod": "...#key-mldsa44",
        "proofPurpose": "assertionMethod",
        "proofValue": "z<base58btc(mldsa44_sig)>"
      }
    ]

Both proofs are computed over the same JCS-canonical credential bytes
(the credential minus the `proofValue` field of each proof,
JCS-canonicalized). The same-canonical-bytes property is preserved by
construction: both cryptosuites use JCS canonicalization on the same
credential body. Each proof's `proofValue` is independently multibase
base58btc-encoded.

The Ed25519 signature is exactly 64 bytes; the ML-DSA-44 signature is
exactly 2,420 bytes. Each appears in its own proof object's `proofValue`
rather than being concatenated into a single field.

## Verifier Modes

A verifier iterates the credential's `proof` array and applies one of
three local policies:

1.  **Classical-only**: validate the `eddsa-jcs-2022` proof; ignore the
    rest. Useful when ML-DSA-44 libraries are unavailable or
    computationally expensive.

2.  **Post-quantum-only**: validate the `mldsa44-jcs-2026` proof. Useful
    when classical signatures are no longer trusted under the verifier's
    compliance regime.

3.  **Both-required**: validate every proof in the array; reject if any
    one fails. The cautious mode, recommended for long-retention
    credentials.

The verifier's mode is policy, not part of the credential. The same
credential is verifiable under any verifier mode without re-signing.

## DID Document Representation

A signing DID supporting the dual-proof profile publishes two
verification methods in its DID Document: one Ed25519 Multikey, one
ML-DSA-44 Multikey. The Multikey multicodec prefix distinguishes the two
algorithms, and each proof's `verificationMethod` field points at its
own key.

## Migration Path

A deployment migrates from classical to dual-proof in three steps:

1.  **Adopt dual-proof signing**: the signer issues credentials with two
    proofs in the array. Existing classical-only verifiers continue
    working (they see a familiar `eddsa-jcs-2022` proof and ignore the
    second one they don't recognize).

2.  **Update verifiers**: deploy a verifier release that supports
    ML-DSA-44. Configure the verifier's mode (classical-only, PQ-only,
    or both-required) based on the deployment's risk tolerance.

3.  **Retire classical signing**: once all verifiers are PQ-aware,
    switch the signer to issue only the `mldsa44-jcs-2026` proof. The
    dual-proof profile is the migration vehicle, not the destination.

## Performance and Size

Per-credential signing cost (Apple M3 Max, reference Python
implementation):

- Ed25519 alone: $\sim$`<!-- -->`{=html}50 $\mu$s

- ML-DSA-44 alone: $\sim$`<!-- -->`{=html}3 ms

- Dual-proof (both): $\sim$`<!-- -->`{=html}3 ms (dominated by
  ML-DSA-44)

Per-credential credential size (multibase-encoded proofs):

- Classical only: $\sim$`<!-- -->`{=html}700 bytes total

- Dual-proof: $\sim$`<!-- -->`{=html}3,200 bytes total

The size delta matters for HTTP-header-conveyed credentials and for
credentials embedded in QR codes. For application-body conveyance the
overhead is negligible.

## Relationship to Concurrent Work

The dual-proof construction converges with Digital Bazaar's
`mldsa44-rdfc-2024-cryptosuite` family (Digital Bazaar, Inc. 2026),
which defines an ML-DSA-44 Data Integrity cryptosuite using RDFC
canonicalization, and with that family's forthcoming JCS variant. The
cryptosuite identifier `mldsa44-jcs-2026` used in this paper is
provisional and is being aligned with that upstream registration.
Earlier Vouch reference implementations (v1.6.x) emit a single composite
cryptosuite (`hybrid-eddsa-mldsa44-jcs-2026`) with a concatenated
`proofValue`; this composite identifier is retained as a transitional
alias for backward compatibility only, and new implementations emit the
dual-proof form described above.

# The State Verifiability Layer {#sec:state}

## Motivation: From Point-in-Time to Continuous

The credential layer addresses "did the agent claim authorization at
time $T$." The State Verifiability layer addresses operational questions
arising *after* that: is the agent still behaving correctly *now*? Has
it drifted out of policy? Has it been substituted? Has it crashed
silently and been replayed by an adversary?

A long-running agent without continuous attestation accumulates risk.
The longer it runs, the wider the window during which a compromise or
substitution may go undetected. Heartbeat-style renewal makes that
window bounded.

## The Heartbeat Protocol

The Heartbeat Protocol defines a periodic renewal cycle:

1.  The agent's `HeartbeatSession` records actions and behavioural
    signals during each interval.

2.  At the heartbeat boundary (default 60 seconds), the session
    constructs a `HeartbeatRequest`: it includes a behavioural digest,
    the running Merkle root of actions performed since the last
    heartbeat, the canary commit/reveal pair, and an interval index.

3.  The agent submits the request to a validator (or quorum of
    validators).

4.  The validator(s) check schema, behavioural digest structure, canary
    chain integrity, interval-index monotonicity, and trust policy.

5.  On success, the validator returns a fresh `SessionVoucher`
    credential with the agent's renewed trust parameters.

6.  On failure (broken canary, stale interval index, behavioural drift),
    no voucher is issued; the agent's existing voucher expires; the
    agent loses authority.

The Heartbeat Protocol inverts the traditional PKI trust model from
"trusted until revoked" to *"untrusted until renewed"* (Gaddam 2026a).

## Trust Entropy Decay

Each SessionVoucher carries `initialTrust` and `decayLambda`. The
effective trust at time $t$ after the voucher's `issuedAt`:

$$\textsf{trust}(t) = \textsf{initialTrust} \cdot e^{-\lambda (t - t_0)}$$

Sensitive actions are gated by current trust. The specification defines
five reference thresholds by operation category:

- Financial transaction: $\theta = 0.95$ (transfers, settlement,
  regulated submissions).

- API write: $\theta = 0.80$ (state-changing calls, code deployment).

- API read: $\theta = 0.50$ (PHI read, customer-data access, status
  queries).

- Health check: $\theta = 0.20$ (liveness, idle activity).

- Logging: $\theta = 0.05$ (telemetry, audit emission).

Heartbeat interval should be set to less than half the half-life so
renewal stays ahead of decay. For $\lambda = 0.01$, half-life is
approximately 69 seconds; a 30-second heartbeat is appropriate.

## Behavioural Attestation

Per-interval, the `BehavioralCollector` records:

- API calls made by the agent (URL, token count, optional intent-drift
  score)

- Resources accessed

- Any policy-defined custom signals

At each heartbeat, the collector produces a `behavioralDigest`. Three
reference intent-drift scorers ship with the SDK: arithmetic mean,
maximum-of-samples, and exponential-weighted moving average. The drift
score quantifies the divergence of the agent's recent activity from a
baseline; a sharp rise across consecutive intervals signals a potential
prompt-injection or policy-drift event.

## Canary Commitments

The canary commit/reveal chain provides cryptographic detection of
silent agent failure. Each heartbeat commits to a fresh 256-bit secret
hash; the next heartbeat reveals the prior secret. A missed heartbeat
means the prior secret is never revealed; no subsequent heartbeat can
resume the chain because the validator expects the missing reveal.

The validator state per agent is one string (the last commitment). The
state is cheap to persist and survives validator restarts.

## Action Merkle Roots

A `HeartbeatRequest` includes the Merkle root of actions performed since
the last heartbeat, computed over RFC 6962-domain-separated Merkle
trees (Laurie et al. 2013). Each action is hashed with `0x00` prefix
(leaf); internal nodes are hashed with `0x01` prefix. This prevents the
classical second-preimage attack on Merkle trees.

## Validator Quorum

Single validators are single points of failure. The `HeartbeatQuorum`
distributes trust evaluation across multiple validators with different
responsibilities:

``` {.python language="Python"}
quorum = HeartbeatQuorum(
    validators=[
        QuorumValidator(validator=policy_validator,     role=ROLE_POLICY),
        QuorumValidator(validator=behavioral_validator, role=ROLE_BEHAVIORAL),
        QuorumValidator(validator=budget_validator,     role=ROLE_BUDGET),
    ],
    threshold=2,
)
```

Roles are reference tags; deployments choose their own role taxonomy.
The quorum threshold is $M$-of-$N$. Trust parameter aggregation across
approving validators is configurable; the defaults bias toward caution.

# Security Analysis {#sec:security}

## Threat Model

The protocol assumes:

- The cryptographic primitives (Ed25519, ML-DSA-44, SHA-256) are sound
  under their respective security assumptions.

- The verifier can resolve the issuer's DID Document via the agent's
  chosen DID method (`did:web` via HTTPS, `did:key` via decoding).

- The verifier has access to the revocation registry and to
  BitstringStatusList endpoints.

- The Identity Sidecar's process boundary is enforced by the host
  operating system: a malicious LLM process cannot read the Sidecar's
  memory.

The protocol does *not* assume:

- The LLM is trustworthy. Prompt injection, jailbreak, and model
  substitution attacks are within the threat model.

- The transport layer is confidential. Credentials are designed to be
  exposed in transit (the signature establishes authenticity even when
  an adversary observes the credential).

- The agent's host platform is uncompromised. Root-level compromise of
  the host defeats any application-level defence, including this one.

## Defended Threats

**Bearer-credential theft.** Vouch credentials are bound to the issuer's
DID by signature; an adversary who copies a credential cannot reuse it
to issue new credentials. The original credential is bound to its
`intent.target` and `intent.resource`; it cannot be replayed against a
different resource.

**Prompt injection causing key exfiltration.** The Identity Sidecar
makes this attack class structurally impossible: the LLM process has no
access to the private key.

**Prompt injection causing unauthorized credential issuance.** The
Sidecar's intent allow-list makes this attack class capability-bounded:
the LLM may propose any intent it likes, but the Sidecar refuses to sign
intents outside the deployment's allow-list.

**Injected or untrustworthy intent.** A natural objection is that
verifying an action against "signed intent" only relocates the trust
problem upstream: what if the captured intent is itself a product of
prompt injection? Vouch closes this in two places. First, intent is
signed at the human-principal boundary before any agent processing. The
root of every delegation chain is a credential signed by the human
principal's key (§[5](#sec:delegation){reference-type="ref"
reference="sec:delegation"}), establishing a chain of custody from the
original authorization down to the acting agent (Gaddam 2026c); an
intent fabricated inside a compromised agent carries no valid root
signature and fails chain validation. Second, the faithfulness of the
agent's reasoning relative to that signed intent is itself verifiable:
the reasoning trace is evidence-anchored and checked for causal
consistency with the chosen action (Gaddam 2026d), and outputs can be
bound to retrieved evidence rather than confabulated (Gaddam 2026e).
Intent an agent invents for itself is therefore neither rooted in a
principal's signature nor reconcilable with a faithful reasoning trace.

**Replay across resources.** Each credential's `intent.resource` is part
of the signed payload. Replaying against a different resource
invalidates the signature.

**Delegation chain forgery.** Each link is a signed credential; forging
a link requires possessing the delegating principal's key.
Trusted-principal anchoring ensures the chain root is known to the
verifier independently.

**Resource widening at delegation.** The chain validator's
resource-narrowing rule rejects chains where any link grants access
beyond its parent's scope.

**Long-running agent silent failure.** The Heartbeat Protocol's canary
chain detects missed heartbeats: the next heartbeat cannot produce the
expected reveal, the chain breaks, and the validator refuses to renew.

**Key compromise.** DID-level revocation invalidates all credentials
issued by the compromised key. The auto-rotation pipeline automates
rotation when leak detection fires.

**Post-quantum cryptanalysis.** The dual-proof profile carries an
ML-DSA-44 Data Integrity proof in addition to the Ed25519 proof,
allowing the credential to be re-verified against the PQ proof once
Ed25519 is broken. Verifiers in both-required mode are immune to
single-algorithm cryptanalysis.

## Residual Threats

**Within-allow-list abuse.** The Sidecar's allow-list bounds capability
*type*, not *abuse within type*. Mitigations: pattern strictness, rate
limits, downstream verifier policy, and human-in-the-loop confirmation
for ambiguous cases.

**DID resolution failures.** If the issuer's DID Document is
unreachable, the credential cannot be verified. Verifiers MUST fail
closed rather than accept unverified credentials.

**Trusted-principal anchor compromise.** If a trusted-principal DID is
compromised, the adversary can construct delegation chains rooted at
that DID that authorize arbitrary leaf actions within the principal's
scope. Defence: rotate trusted-principal keys regularly; require
multi-key signing at the root for high-stakes deployments.

# Cross-Language Interoperability {#sec:interop}

## Test Vectors

The protocol ships cross-language test vectors verifying that every
language SDK, each bound to the shared Rust core, produces
byte-identical credentials given identical inputs:

- `test-vectors/jcs/`: JSON Canonicalization Scheme reference outputs.

- `test-vectors/eddsa-jcs-2022/`: full credential signing test vectors
  for the classical cryptosuite.

- `test-vectors/hybrid-eddsa-mldsa44/`: full credential signing test
  vectors for the dual-proof post-quantum profile (and, for v1.6.x
  interop, the transitional composite cryptosuite).

- `test-vectors/bitstring-status-list/`: BitstringStatusList encoding
  test vectors.

- `test-vectors/sidecar-contract/`: HTTP wire-contract test suite for
  the three sidecar implementations.

## Reference Implementation Properties

  Component       Language / runtime
  --------------- ---------------------
  `vouch-core`    Rust (shared core)
  `sdk-py`        Python 3.10+
  `sdk-ts`        TypeScript 5+
  `go-sidecar`    Go 1.21+
  `sdks/cpp`      C++
  `sdks/dotnet`   .NET
  `sdks/jvm`      Java / Kotlin (JVM)
  `sdks/swift`    Swift

  : The Vouch reference architecture: one Rust core (`vouch-core`)
  exposed to seven language SDKs through WebAssembly and UniFFI
  bindings, so every SDK produces byte-identical credentials by
  construction.

All SDKs pass the cross-language test vectors. CI runs the vectors on
every commit and rejects merges that introduce divergence.

## Known Implementation Divergences

The one documented divergence is in BitstringStatusList byte-encoding:
different DEFLATE encoders across language runtimes produce valid but
non-identical compressed streams for the same bitstring. The
specification requires equivalence of the *decompressed* bitstring,
which every implementation satisfies; revocation status is therefore
identical across all SDKs, and verifiers and issuers interoperate.

# Discussion {#sec:discussion}

## Limitations

**State Verifiability is Python-only at the runtime level.** The data
formats (SessionVoucher, behavioural digest, canary commitment,
heartbeat request) are cross-language and verifiable in any of the three
implementations. The runtime orchestration (`HeartbeatSession`,
`HeartbeatScheduler`, `HeartbeatValidator`, `HeartbeatQuorum`) is
implemented in Python only. TypeScript and Go ports are work in progress
at the time of publication.

**Trusted-principal anchoring is deployment-specific.** The protocol
does not standardize how a verifier discovers its trusted principals.
Each deployment configures this independently.

**Confidentiality of sensitive intents is not addressed in v0.1-draft.**
Vouch credentials are non-confidential. For deployments handling
regulated content, the next minor revision will add an optional
confidentiality profile using post-quantum key encapsulation.

**The Identity Sidecar's allow-list is static configuration.** Dynamic
capability adjustment is achievable through the protocol's normal
credential validity windows but requires care to compose with the
Sidecar's static allow-list.

## Adoption Path

The protocol has been validated against three reference implementations
and a cross-language test-vector battery. Adoption requirements for a
new deployment:

1.  Generate an issuer DID and publish its DID Document.

2.  Choose a Sidecar tier (Go for production, Python or TypeScript for
    lighter deployments).

3.  Configure the Sidecar's allow-list with the deployment's action
    vocabulary.

4.  Wire the agent's tool-call layer to call the Sidecar's `/sign`
    endpoint instead of directly calling external APIs.

5.  Deploy a verifier (either as a library at the API boundary, or as a
    separate service) for the deployment's external services.

6.  For long-running agents, deploy at least one Heartbeat validator (or
    a quorum of three for regulated deployments).

End-to-end onboarding effort is on the order of one to two engineering
days for the credential layer alone, and another two to four days for
state verifiability and quorum.

## Future Work

Four directions are actively under development:

1.  **TypeScript and Go ports of the State Verifiability runtime.**

2.  **Confidentiality profile for sensitive intents** using ML-KEM-768
    key encapsulation.

3.  **Hosted continuous leak monitor** that closes the loop from
    automated detection to DID rotation with dual-signed migration
    credentials and verifier broadcast.

4.  **AI-assisted developer tooling** distributed as Claude Skills /
    Custom GPTs / Gemini Gems, allowing developers to receive Vouch
    integration guidance through their own AI tool subscriptions with
    zero protocol-vendor inference cost.

5.  **Embodied and robotics extension**: applying per-action intent
    credentials and the State Verifiability layer to physical actuation,
    where an action is a movement or a manipulation rather than an API
    call.

The protocol's State Verifiability runtime, the dual-proof post-quantum
profile, and the migration story from classical to dual-proof to pure-PQ
each merit follow-up papers; outlines are in preparation.

# Conclusion {#sec:conclusion}

We have presented the Vouch Protocol, an open standard for cryptographic
identity and continuous state verifiability of autonomous AI agents. The
protocol composes Verifiable Credentials, Decentralized Identifiers,
Data Integrity proofs, and post-quantum cryptosuites with two novel
layers: an Identity Sidecar pattern that isolates the agent's key from
the LLM and bounds the agent's capabilities by an enforced allow-list,
and a State Verifiability layer that renews trust continuously via
heartbeat, decays trust exponentially in the interval, attests behaviour
cryptographically, and detects silent failure through canary
commit/reveal chains.

A single Rust core (`vouch-core`), exposed to seven language SDKs
through WebAssembly and UniFFI bindings, makes credentials
byte-identical across languages by construction. The protocol is open
under Apache 2.0; sixty defensive disclosures keep the design space open
under CC0.

The accountability gap in agent identity is solvable today. The
cryptographic primitives are sound, the standards exist, and the
implementation effort is bounded. Vouch is one realization of a path the
open agent-identity ecosystem will increasingly need: from "the bearer
has access" to "this specific agent issued this specific intent under
this specific authorization chain, verifiable in seconds, with
cryptography rather than logbook evidence."

# Acknowledgements {#acknowledgements .unnumbered}

The author thanks Manu Sporny and the W3C Verifiable Credentials Working
Group for foundational work on Verifiable Credentials, Data Integrity,
and the eddsa-jcs-2022 cryptosuite; the W3C Credentials Community Group
for hosting and reviewing the incubation; the IETF JOSE working group
for ongoing work on PQ/T composite signatures; the C2PA technical
committee for content-provenance complementarity; and the open-source
community of contributors and reviewers whose feedback shaped many of
the choices documented here.

# Reference Implementations

- **Python**: `pip install vouch-protocol`. Source:
  <https://github.com/vouch-protocol/vouch/tree/main/vouch/>

- **TypeScript**: `npm install @vouch-protocol/core`. Source:
  <https://github.com/vouch-protocol/vouch/tree/main/packages/sdk-ts/>

- **Go**: install with `go install` from
  [github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar](github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar){.uri}.
  Source:
  <https://github.com/vouch-protocol/vouch/tree/main/go-sidecar/>

- **Rust core and further SDKs**: the `vouch-core` crate is under
  <https://github.com/vouch-protocol/vouch/tree/main/core/>; SDKs for
  C++, .NET, JVM, and Swift are under
  <https://github.com/vouch-protocol/vouch/tree/main/sdks/>.

# Test Vectors

All test vectors are at
<https://github.com/vouch-protocol/vouch/tree/main/test-vectors/>.

# Specification Document

The full Vouch Protocol Specification, currently Spec v0.1-draft in W3C
Credentials Community Group incubation, is at
<https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md>.

::::::::::::::::::::::::: {#refs .references .csl-bib-body .hanging-indent}
::: {#ref-c2pa14 .csl-entry}
Coalition for Content Provenance and Authenticity. 2024. *C2PA Technical
Specification 1.4*.
<https://c2pa.org/specifications/specifications/1.4/index.html>.
:::

::: {#ref-db-mldsa44 .csl-entry}
Digital Bazaar, Inc. 2026. *Mldsa44-Rdfc-2024-Cryptosuite: ML-DSA-44
Data Integrity Cryptosuite (RDFC Canonicalization)*.
<https://github.com/digitalbazaar/mldsa44-rdfc-2024-cryptosuite>.
:::

::: {#ref-aarm2026 .csl-entry}
Errico, Herman. 2026. *Autonomous Action Runtime Management (AARM): A
System Specification for Securing AI-Driven Actions at Runtime*.
<https://arxiv.org/abs/2602.09433>.
:::

::: {#ref-faramesh2026 .csl-entry}
Fatmi, Amjad. 2026. *Faramesh: A Protocol-Agnostic Execution Control
Plane for Autonomous Agent Systems*. <https://arxiv.org/abs/2601.17744>.
:::

::: {#ref-pad001 .csl-entry}
Gaddam, Ramprasad Anandam. 2025. *Cryptographic Binding of AI Agent
Identity*.
<https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-001-cryptographic-agent-identity.md>.
:::

::: {#ref-pad016 .csl-entry}
Gaddam, Ramprasad Anandam. 2026a. *Continuous Trust Maintenance via
Dynamic Credential Renewal (the Heartbeat Protocol)*.
<https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-016-dynamic-credential-renewal.md>.
:::

::: {#ref-pad039 .csl-entry}
Gaddam, Ramprasad Anandam. 2026b. *Cross-Implementation Deterministic
Multi-Party Trust State via JCS-Canonicalized Verifiable Credentials*.
<https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-039-jcs-deterministic-multi-party-trust-state.md>.
:::

::: {#ref-pad002 .csl-entry}
Gaddam, Ramprasad Anandam. 2026c. *Cryptographic Binding of AI Agent
Intent via Recursive Delegation (Chain of Custody)*.
<https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-002-chain-of-custody.md>.
:::

::: {#ref-pad017 .csl-entry}
Gaddam, Ramprasad Anandam. 2026d. *Cryptographic Proof of Reasoning with
Adaptive Commitment Depth*.
<https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-017-cryptographic-proof-of-reasoning.md>.
:::

::: {#ref-pad045 .csl-entry}
Gaddam, Ramprasad Anandam. 2026e. *Proof of Non-Hallucination via
Cryptographic Retrieval Anchoring*.
<https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-045-proof-of-non-hallucination-retrieval-anchoring.md>.
:::

::: {#ref-rfc6749 .csl-entry}
Hardt, D. 2012. *The OAuth 2.0 Authorization Framework*. RFC 6749.
Internet Engineering Task Force.
<https://datatracker.ietf.org/doc/html/rfc6749>.
:::

::: {#ref-rfc6962 .csl-entry}
Laurie, B., A. Langley, and E. Kasper. 2013. *Certificate Transparency*.
RFC 6962. Internet Engineering Task Force.
<https://datatracker.ietf.org/doc/html/rfc6962>.
:::

::: {#ref-righttoact2026 .csl-entry}
Lavi, Gadi. 2026. *Right-to-Act: A Pre-Execution Non-Compensatory
Decision Protocol for AI Systems*. <https://arxiv.org/abs/2604.24153>.
:::

::: {#ref-rfc9700 .csl-entry}
Lodderstedt, T., J. Bradley, A. Labunets, and D. Fett. 2025. *OAuth 2.0
Security Best Current Practice*. RFC 9700. Internet Engineering Task
Force. <https://datatracker.ietf.org/doc/html/rfc9700>.
:::

::: {#ref-nistfips204 .csl-entry}
National Institute of Standards and Technology. 2024.
*Module-Lattice-Based Digital Signature Standard*. FIPS 204. U.S.
Department of Commerce. <https://csrc.nist.gov/pubs/fips/204/final>.
:::

::: {#ref-forge2026 .csl-entry}
Palumbo, Nils, Sarthak Choudhary, Jihye Choi, Guy Amir, Prasad
Chalasani, and Somesh Jha. 2026. *Formal Policy Enforcement for
Real-World Agentic Systems*. <https://arxiv.org/abs/2602.16708>.
:::

::: {#ref-strong2018spiffe .csl-entry}
Strong, J., and SPIFFE Project. 2018. *SPIFFE: Universal Workload
Identity*. Linux Foundation. <https://spiffe.io/>.
:::

::: {#ref-oap2026 .csl-entry}
Uchibeke, Uchi. 2026. *Before the Tool Call: Deterministic Pre-Action
Authorization for Autonomous AI Agents*.
<https://arxiv.org/abs/2603.20953>.
:::

::: {#ref-zcapld .csl-entry}
W3C Credentials Community Group. 2024. *Authorization Capabilities for
Linked Data V0.3 (ZCAP-LD)*. <https://w3c-ccg.github.io/zcap-spec/>.
:::

::: {#ref-w3cdidcore .csl-entry}
World Wide Web Consortium. 2022. *Decentralized Identifiers (DIDs)
V1.0*. W3C Recommendation. <https://www.w3.org/TR/did-core/>.
:::

::: {#ref-w3cbsl .csl-entry}
World Wide Web Consortium. 2024a. *Bitstring Status List V1.0*. W3C
Candidate Recommendation.
<https://www.w3.org/TR/vc-bitstring-status-list/>.
:::

::: {#ref-w3cvcdm2 .csl-entry}
World Wide Web Consortium. 2024b. *Verifiable Credentials Data Model
V2.0*. W3C Candidate Recommendation.
<https://www.w3.org/TR/vc-data-model-2.0/>.
:::
:::::::::::::::::::::::::
