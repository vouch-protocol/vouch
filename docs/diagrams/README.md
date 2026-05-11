# Vouch Protocol Diagrams

Process flow and architecture diagrams for the Vouch Protocol, authored
as Mermaid markdown. GitHub renders these inline; in any other viewer,
paste the ` ```mermaid ` block into [mermaid.live](https://mermaid.live)
for an instant preview.

## Wave 1 (this batch)

| # | File | What it shows |
|---|---|---|
| 1.1 | [01-system-topology.md](01-system-topology.md) | Component map: agent host, sidecar, validator quorum, verifier fleet, public artifacts. Trust boundaries highlighted. |
| 2.5 | [02-credential-issuance.md](02-credential-issuance.md) | Application → SDK → JCS → Signer → signed VC. Default and hybrid PQ paths. |
| 2.6 | [03-credential-verification.md](03-credential-verification.md) | Verifier decision tree with structured reject reasons. |
| 4.1 | [04-delegation-chain.md](04-delegation-chain.md) | Principal → Agent → Sub-Agent chain construction plus verifier walk plus resource narrowing. |

## Roadmap (waves 2 and 3)

See the parent issue / planning notes for the catalog of ~70 diagrams
across the protocol. Wave 2 covers cryptographic moves (CanaryChain,
trust decay curve, hybrid signing, Merkle inclusion proof). Wave 3
fills in revocation, sidecar variants, integrations, and standards
composition.

## Authoring

- Source format: Mermaid `flowchart`, `sequenceDiagram`, and friends.
  See [mermaid.js.org](https://mermaid.js.org) for syntax.
- Style conventions: subgraphs label trust boundaries; `classDef`
  highlights reject/accept paths in red/green; arrows go left-to-right
  in topology diagrams and top-to-bottom in sequence diagrams.
- Every diagram file has a one-paragraph header explaining what the
  diagram shows and a "What it answers" section underneath listing the
  reader questions the diagram is designed to settle.
