# 4.1 Delegation Chain Construction and Verification

How authority flows from a human principal down to the agent that
actually executes an action, with cryptographic proof at every link.

The example: a human principal authorizes an agent to manage orders,
who then sub-delegates to a sub-agent for one specific order. Each link
narrows the resource scope; the verifier walks the chain backward to
the principal.

```mermaid
sequenceDiagram
    autonumber
    actor H as Human Principal<br/>did:web:cfo.example
    participant A as Agent<br/>did:web:agent.example
    participant S as Sub-Agent<br/>did:web:sub.example
    participant V as Verifier

    Note over H: scope: orders/*
    H->>A: signed VC link #1<br/>{ issuer: H, subject: A,<br/>  resource: "orders/*",<br/>  validFrom, validUntil }

    Note over A: receives broader scope<br/>narrows to specific order
    A->>S: signed VC link #2<br/>{ issuer: A, subject: S,<br/>  resource: "orders/HC-001",<br/>  parent: link #1,<br/>  validFrom, validUntil }

    Note over S: must operate within<br/>orders/HC-001 only

    S->>V: action credential<br/>{ issuer: S,<br/>  intent: { action: "submit_claim",<br/>            target: "claim/HC-001",<br/>            resource: "orders/HC-001" },<br/>  delegationChain: [link #1, link #2] }

    rect rgb(245, 245, 250)
        Note right of V: Verifier walks chain backward
        V->>V: verify action credential signature (S)
        V->>V: verify action.resource ⊆ link#2.resource<br/>(orders/HC-001 ⊆ orders/HC-001) ✓
        V->>V: verify link #2 signature (A)
        V->>V: verify link#2.resource ⊆ link#1.resource<br/>(orders/HC-001 ⊆ orders/*) ✓
        V->>V: verify link #1 signature (H)
        V->>V: verify H is a trusted principal
        V->>V: verify chain depth (3) ≤ 5
    end

    V-->>S: accept (chain valid)
```

## Resource narrowing visualized

```mermaid
flowchart LR
    P["Principal H<br/>scope: orders/*"] --> A["Agent A<br/>scope: orders/HC-001"]
    A --> S["Sub-Agent S<br/>scope: orders/HC-001"]
    S --> Action["Action<br/>resource: orders/HC-001"]

    Pset(("orders/*"))
    Aset(("orders/HC-001"))

    Pset -.->|⊇| Aset

    classDef widest fill:#e3f2fd,stroke:#1565c0
    classDef narrower fill:#bbdefb,stroke:#1565c0
    classDef narrowest fill:#90caf9,stroke:#1565c0
    class P widest
    class A,S narrower
    class Action narrowest
```

## What it answers

- Who is ultimately responsible? The human principal at the top of the
  chain (`did:web:cfo.example` here). The chain proves that everything
  downstream was authorized by them.
- Can a sub-agent grant itself more authority than it was given? No. The
  resource-narrowing rule is enforced at verification: each link's
  resource scope MUST be a subset of the previous link's scope.
- What's the depth limit? 5 links maximum (W3C CG Report §9.4). Prevents
  unbounded chain growth and limits the verifier's walk cost.
- What does the verifier check at each link? Signature math (the
  issuer's public key in their DID Document verifies the signature) and
  the resource-subset condition.
- What happens if a middle link is revoked? If any link's issuer DID is
  in the revocation registry, OR any link's `credentialStatus` is set,
  the whole chain fails. The action credential cannot stand on a
  compromised parent.
