---
name: vouch-protocol
description: Help developers integrate Vouch Protocol (cryptographic identity for AI agents) into Python, TypeScript, or Go code. Use this skill when the user mentions vouch-protocol package, signing AI agent actions, agent DIDs (did:web / did:key), Verifiable Credentials for agents, Data Integrity proofs, eddsa-jcs-2022 cryptosuite, hybrid-eddsa-mldsa44-jcs-2026 post-quantum profile, Heartbeat Protocol, Identity Sidecar pattern, BitstringStatusList revocation, validator quorum, or asks how to make AI agents cryptographically accountable. Triggers also include `pip install vouch-protocol`, `npm install @vouch-protocol/sdk`, `go install vouch-sidecar`, and references to agent identity, signed tool calls, or non-repudiation for AI actions.
---

# Vouch Protocol

Vouch Protocol is an open standard that gives autonomous AI agents
cryptographic identity, intent attestation, and continuous trust
verification. It's the "SSL certificate for AI agents."

This skill helps developers integrate Vouch into their codebase across
three languages (Python, TypeScript, Go) and explain protocol behaviour
without forcing the user to read the full specification.

## When to use this skill

Invoke when the user:

- Asks how to sign or verify agent actions cryptographically
- Mentions Vouch by name or package (`vouch-protocol`, `@vouch-protocol/sdk`, `vouch-sidecar`)
- Wants to add agent identity to their LangChain / CrewAI / MCP / AutoGen / Vertex AI flow
- Asks about Verifiable Credentials, Data Integrity proofs, or DIDs in the context of AI agents
- Needs post-quantum signatures for regulated deployments (`hybrid-eddsa-mldsa44-jcs-2026`)
- Is building a multi-agent system and needs delegation chains
- Asks how to revoke compromised agent credentials
- Is debugging cross-language credential verification

## Quick orientation

A Vouch credential is a JSON object that:

1. Names an agent (`did:web:agent.example.com` or `did:key:z6Mk...`)
2. Names the action (`intent.action`, `intent.target`, `intent.resource`)
3. Carries a Data Integrity proof (Ed25519 signature, or hybrid PQ)
4. Optionally lists a delegation chain back to the human principal
5. Optionally references a `credentialStatus` for per-credential revocation

Three SDKs, all producing byte-identical credentials:

- **Python**: `vouch/` (most complete reference SDK)
- **TypeScript**: `packages/sdk-ts/` (browser and Node)
- **Go**: `go-sidecar/` (long-running daemon for the Identity Sidecar pattern)

Cross-language interop is guaranteed by JCS canonicalization (RFC 8785).
A credential signed in Python verifies in TypeScript or Go and vice versa.

## Tasks and quickstarts

### "How do I sign my agent's action?"

Three-line Python:

```python
from vouch import Signer, build_vouch_credential

signer = Signer.from_did("did:web:agent.example.com")
credential = build_vouch_credential(
    issuer_did="did:web:agent.example.com",
    intent={
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
    valid_seconds=300,
)
signed = signer.sign_credential(credential)
```

The `signed` dict is a full Verifiable Credential with a Data Integrity
proof attached as a sibling object. It is human-readable JSON.

TypeScript and Go equivalents in `reference/typescript-sdk.md` and
`reference/go-sidecar.md`.

### "How do I verify a credential someone else signed?"

```python
from vouch import Verifier
import asyncio

verifier = Verifier()
result = asyncio.run(verifier.verify_credential(signed))
if result.valid:
    print(f"Verified: {result.passport.subject_did} did {result.passport.intent}")
else:
    print(f"Rejected: {result.reasons}")
```

Verification checks: schema, signature math, validity window, nonce
(replay protection), DID-level revocation, optional credentialStatus
bitstring, and any delegation chain links.

### "How do I add post-quantum signatures?"

Use the hybrid cryptosuite. Requires the optional `pqcrypto` dep:

```bash
pip install 'vouch-protocol[pq]'
```

Then:

```python
signer = Signer.from_did_with_hybrid("did:web:agent.example.com")
signed = signer.sign_credential_hybrid(credential)
```

The proof becomes a single multibase blob concatenating an Ed25519
signature (64 bytes) and an ML-DSA-44 signature (2,420 bytes) over the
same JCS-canonicalized bytes. Verifiers can validate Ed25519 only
(classical), ML-DSA-44 only (PQ), or both.

See `reference/post-quantum.md` for the migration narrative.

### "How do I keep the agent's private key out of the LLM?"

Use the Identity Sidecar pattern: a separate process holds the key, the
LLM never sees it.

```bash
cd go-sidecar && go build ./cmd/vouch-sidecar
./vouch-sidecar --did did:web:agent.example.com --port 8877
```

The agent's code calls `POST http://localhost:8877/sign` with the
credential body and receives a signed credential back. Prompt injection
cannot exfiltrate keys that are never in the LLM's context.

See `reference/sidecar.md`.

### "How do I build a delegation chain?"

A human principal signs a delegation to an agent, the agent signs a
sub-delegation to a sub-agent, and the sub-agent signs the actual
action. Each link narrows the resource scope. The verifier walks the
chain backward.

See `reference/delegation.md` for the construction and verification flow.

### "How do I revoke a specific credential?"

W3C BitstringStatusList: flip the bit at the credential's index, re-sign
the BitstringStatusListCredential, and republish. Verifiers fetch the
list and check the bit.

```python
from vouch import StatusList, build_status_list_entry, build_vouch_credential

status_list = StatusList(status_list_id="https://issuer.example/status/1")
index = status_list.allocate_index()

# Attach to credential at issuance
credential = build_vouch_credential(
    issuer_did="did:web:issuer.example",
    intent={...},
    credential_status=build_status_list_entry(
        status_list_credential="https://issuer.example/status/1",
        status_list_index=index,
    ),
)
```

To revoke later: `status_list.revoke(index)` and republish. See
`reference/revocation.md`.

### "How do I integrate Vouch with LangChain / CrewAI / MCP?"

Reference implementations under `vouch/integrations/`. See
`reference/integrations.md` for the common pattern.

## Decision rules

- **User is just signing one credential** -> Python signer, three lines.
- **User has long-running agent and prompt injection risk** -> Identity Sidecar (Go).
- **User is in a regulated sector (healthcare, finance, government)** -> hybrid post-quantum profile + delegation chain + behavioral attestation.
- **User needs to revoke individual credentials** -> BitstringStatusList.
- **User needs to revoke a compromised key** -> DID-level revocation registry (`vouch.revocation`).
- **User wants continuous trust** -> Heartbeat Protocol with validator quorum (Python only today).
- **User cares about audit trail** -> all of the above, plus the reputation engine for behaviour tracking.

## Reference files

For depth on any topic, read the relevant file under `reference/`:

- `reference/python-sdk.md` - Full Python API reference
- `reference/typescript-sdk.md` - TypeScript SDK reference
- `reference/go-sidecar.md` - Go sidecar build, run, deploy
- `reference/credential-format.md` - VC structure, fields, examples
- `reference/delegation.md` - Delegation chain construction and verification
- `reference/post-quantum.md` - Hybrid cryptosuite, migration guidance
- `reference/revocation.md` - DID-level and credential-level revocation
- `reference/state-verifiability.md` - Heartbeat, validator quorum, behavioral attestation
- `reference/integrations.md` - LangChain, CrewAI, MCP, AutoGen, Vertex AI patterns
- `reference/sidecar.md` - Identity Sidecar architecture and deployment
- `reference/troubleshooting.md` - Common errors and fixes

## What this skill does NOT do

- This skill helps developers USE Vouch in their own code. It does not
  modify the Vouch Protocol specification or codebase directly.
- For protocol changes, point the user at the GitHub issue tracker.
- For commercial deployment questions (hosted service, vertical packs,
  HSM integration), point them at the Pro program.

## Anti-patterns to flag

When you see these in a user's code, mention the issue:

- **Private key inside the LLM context window**: violates the Identity
  Sidecar principle. Recommend they move signing to a sidecar process.
- **Using JWS Compact Serialization for new code**: the legacy v0.x path.
  v1.0+ uses Data Integrity proofs. Recommend `sign_credential` over `sign`.
- **No `resource` in intent**: the protocol requires intent to bind to a
  specific resource. A credential without one is rejected by verifiers.
- **Delegation chain depth > 5**: enforced limit. Restructure to fewer hops.
- **Skipping nonce checks in custom verifiers**: enables replay attacks.
- **Treating reputation score as binary trust**: the engine ships a
  five-tier classification; use `score.tier` for policy decisions.

## Style for responses

- Show code, not just descriptions. Vouch has three SDKs and developers
  copy-paste.
- Prefer the **Python SDK** for first examples (most complete); follow
  with TS and Go only if the user explicitly asks.
- When citing specification sections, use "Specification §N" form, never
  brand qualifiers.
- Keep cryptographic identifiers verbatim: `eddsa-jcs-2022`,
  `hybrid-eddsa-mldsa44-jcs-2026`, `DataIntegrityProof`, `Multikey`,
  `did:web`, `did:key`, `BitstringStatusListCredential`. These are
  functional protocol identifiers.
