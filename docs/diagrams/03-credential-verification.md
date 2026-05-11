# 2.6 Credential Verification Flow

Decision tree a verifier walks when a credential arrives. Each step is
an independent check; the credential is accepted only if every check
passes. Failures emit a structured reason code so callers can react
specifically (refresh DID Doc, force-refresh status list, etc.).

```mermaid
flowchart TD
    Start([Credential arrives]) --> Parse{Valid JSON?<br/>VC shape?}
    Parse -- No --> RShape[reject: schema_invalid]
    Parse -- Yes --> Resolve{Resolve issuer DID}
    Resolve -- did:web HTTPS fails --> RDID[reject: did_unresolvable]
    Resolve -- ok --> FindVM{Find verificationMethod<br/>matching proof.verificationMethod}
    FindVM -- not found --> RVM[reject: verification_method_unknown]
    FindVM -- found --> Canon["JCS canonicalize<br/>vc minus proofValue"]
    Canon --> Sig{"Verify signature<br/>Ed25519 or hybrid<br/>per cryptosuite"}
    Sig -- invalid --> RSig[reject: signature_invalid]
    Sig -- valid --> TimeWindow{validFrom <= now<br/>and now <= validUntil}
    TimeWindow -- no --> RTime[reject: expired<br/>or not_yet_valid]
    TimeWindow -- yes --> NonceCheck{Nonce in nonce store?}
    NonceCheck -- yes --> RReplay[reject: nonce_replay]
    NonceCheck -- no --> RecordNonce[insert nonce<br/>with TTL]
    RecordNonce --> DIDRev{"Issuer DID revoked?<br/>revocation registry"}
    DIDRev -- yes --> RDIDRev[reject: issuer_revoked]
    DIDRev -- no --> HasStatus{credentialStatus<br/>field present?}
    HasStatus -- no --> Chain{delegationChain<br/>present?}
    HasStatus -- yes --> FetchStat["StatusListFetcher.get url<br/>cached + conditional GET"]
    FetchStat --> Bit{Bit at statusListIndex set?}
    Bit -- yes --> RStatus[reject: credential_revoked<br/>force_refresh and retry]
    Bit -- no --> Chain
    Chain -- yes --> WalkChain[verify each delegation link<br/>signature plus resource subset<br/>plus depth <= 5]
    WalkChain -- chain valid --> Pass([accept])
    WalkChain -- chain invalid --> RChain[reject: delegation_chain_invalid]
    Chain -- no --> Pass

    classDef reject fill:#fdecea,stroke:#c62828,stroke-width:1px,color:#000
    classDef accept fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#000
    class RShape,RDID,RVM,RSig,RTime,RReplay,RDIDRev,RStatus,RChain reject
    class Pass accept
```

## What it answers

- What order do checks happen in? Cheap, local checks first (schema,
  signature math), then network-dependent checks (DID resolution, status
  list fetch). Verifiers SHOULD short-circuit on the cheapest failures.
- What's the difference between issuer_revoked and credential_revoked?
  `issuer_revoked` means the entire DID has been revoked (DID-level
  registry, blanket effect). `credential_revoked` means just this
  specific credential has its bit set in a BitstringStatusList.
- When does force_refresh fire? When `credential_revoked` is returned
  from a cached status list. The verifier re-fetches with a conditional
  GET to confirm the bit really is set (and isn't a stale-cache artifact).
- What if there's a delegation chain? Each link is verified the same way
  (signature, validity window, resource subset, depth check). The whole
  chain must validate for the action credential to be accepted.
