# 1.1 System Topology

The high-level component map of a Vouch deployment. Shows the agent host
(LLM + orchestration + sidecar + optional Shield), the validator quorum
that issues SessionVouchers, the verifier fleet that consumes
credentials, and the public artifacts (DID Document, BitstringStatusList
credential) that anchor verification.

Trust boundaries are highlighted: keys never leave the sidecar process,
the LLM never sees them, and verifiers compose multiple checks
(DID resolution, nonce store, revocation registry, status list) in
parallel.

```mermaid
flowchart LR
    subgraph AgentHost["Agent Host"]
        direction TB
        LLM["LLM<br/>(no key access)"]
        Orch["Orchestration<br/>(LangChain, CrewAI, MCP, ...)"]
        Sidecar["Identity Sidecar<br/>holds Ed25519 + ML-DSA-44 keys"]
        Shield["Vouch Shield (optional)<br/>tool-call interception"]
        LLM -- tool call --> Orch
        Orch -- "POST /sign" --> Sidecar
        Sidecar -- "signed VC" --> Orch
        Orch -- "credential + tool call" --> Shield
    end

    subgraph ValidatorQuorum["Validator Quorum (M-of-N)"]
        direction TB
        V1["Policy Validator"]
        V2["Behavioral Validator"]
        V3["Budget Validator"]
    end

    subgraph VerifierFleet["Verifier Fleet"]
        direction TB
        Ver["Verifier"]
        Cache["DID Doc Cache"]
        Nonce["Nonce Store"]
        Rev["Revocation Registry<br/>(DID-level)"]
        Stat["StatusListFetcher<br/>(credential-level)"]
        Ver --> Cache
        Ver --> Nonce
        Ver --> Rev
        Ver --> Stat
    end

    DIDDoc[("DID Document<br/>HTTPS /.well-known/did.json")]
    StatusVC[("BitstringStatusListCredential<br/>stable HTTPS URL")]

    Shield -- "heartbeat request" --> ValidatorQuorum
    ValidatorQuorum -- "aggregate SessionVoucher" --> Shield
    Shield -- "action credential" --> Ver
    Cache -- "resolves" --> DIDDoc
    Stat -- "fetches (cached, conditional GET)" --> StatusVC

    classDef boundary fill:#fef9e7,stroke:#b8860b,stroke-width:2px,color:#000
    classDef artifact fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#000
    class AgentHost,ValidatorQuorum,VerifierFleet boundary
    class DIDDoc,StatusVC artifact
```

## What it answers

- Where do keys live? In the sidecar, in its own process.
- What can the LLM see? Tool calls and their results, never keys.
- Who issues SessionVouchers? The validator quorum, M-of-N.
- What does a verifier consult? DID resolution, nonce store, revocation
  registry (DID-level), status list fetcher (credential-level), in parallel.
- What's public? Only the DID Document and the BitstringStatusListCredential.
