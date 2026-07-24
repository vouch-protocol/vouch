# Sidecar tiers: Go, Python, TypeScript

The Vouch sidecar is the separate process that holds an agent's signing
key. The LLM-running process calls it over HTTP for signatures. Because
the key lives in a different process from the LLM, prompt injection
cannot exfiltrate what is not there.

Three implementations ship today. They are **not interchangeable in
production**. Pick by use case, not language preference.

## Tier table

| Tier | Language | Use case | Key storage | When to pick |
|---|---|---|---|---|
| Production | **Go** | Real deployments | KMS / HSM / file | You will be audited. Small static binary. FIPS 140-3 ready in Pro tier. |
| Lightweight | **Python** | Self-hosted, non-regulated | File or env | Stack is already Python; ops simplicity matters more than minimal attack surface. |
| Lightweight | **TypeScript** | Self-hosted, non-regulated | File or env | Stack is already Node. |
| Dev | **Python `dev_sidecar`** | Local development only | Ephemeral, in-memory | Local iteration. Never production. |

**Rule of thumb**: if your auditor will ask about the sidecar, run the
Go one.

## Why the tiering

The sidecar is security-critical. The smaller and more auditable its
code surface, the better it does its job. The Go binary is a few
thousand lines of audited code with no runtime dependencies. The
Python and TypeScript sidecars necessarily bring in their language
runtimes and a web framework. That is a real difference.

We ship Python and TypeScript sidecars anyway because:
- Local development should not require installing a Go toolchain.
- Operationally simpler one-language stacks are valuable for teams who
  cannot adopt Go for sidecar deployment.
- Reference implementations in three languages prove the protocol is
  not tied to one runtime.

## What stays out of the lightweight sidecars

To keep them minimal, the Python and TypeScript sidecars intentionally
omit:
- Post-quantum signing (the `eddsa-jcs-2022` plus `mldsa44-jcs-2024` proof set)
- KMS / HSM key integration
- Sensitive-mode JWE wrapping (ML-KEM 768)
- Heartbeat session validation
- Multi-tenancy (one DID per sidecar process)

If you need any of those, switch to the Go sidecar. That switch is the
design intent, not a workaround.

## Cross-language equivalence

All three sidecars expose the same HTTP API:
- `GET  /health` — liveness probe
- `GET  /did` — the sidecar's DID
- `GET  /.well-known/did.json` — DID Document (optional, dev-friendly)
- `POST /sign` — sign an intent, return a Verifiable Credential

A contract test suite verifies that each implementation accepts and
rejects the same inputs and emits semantically equivalent credentials.

## Switching tiers

The HTTP API is identical. An agent that talks to the Python sidecar
can talk to the Go sidecar with one env-var change:

**macOS / Linux**

```bash
export VOUCH_SIDECAR_URL=http://localhost:8877
```

**Windows (PowerShell)**

```powershell
$env:VOUCH_SIDECAR_URL = "http://localhost:8877"
```

The agent code does not change. The DID changes (production agents
use a real did:web rooted on your domain), and the key material
changes (production loads from KMS).
