/**
 * Vouch Protocol Help Guides
 *
 * Long-form articles organized into sections. Each article is structured
 * so a returning user can skim section headings, jump to the part they
 * need, and recover working context after time away.
 *
 * Every article is grounded in shipped code, no aspirational steps.
 */

export interface HelpArticle {
    /** URL anchor */
    id: string;
    /** Short title shown in sidebar nav and article header */
    title: string;
    /** One-line summary for the section index */
    summary: string;
    /** Markdown-ish content body (see renderer for supported syntax) */
    body: string;
}

export interface HelpSection {
    id: string;
    title: string;
    description: string;
    articles: HelpArticle[];
}

export const HELP_SECTIONS: HelpSection[] = [
    {
        id: 'getting-started',
        title: 'Getting Started',
        description: 'Install an SDK, sign your first credential, and verify it.',
        articles: [
            {
                id: 'quickstart-python',
                title: 'Python Quickstart',
                summary: 'Five-minute path from pip install to a verified Vouch credential.',
                body: `
## Install

\`\`\`bash
pip install vouch-protocol
\`\`\`

For the optional hybrid post-quantum profile, also install the pqcrypto extra:

\`\`\`bash
pip install 'vouch-protocol[pq]'
\`\`\`

## Generate an identity

\`\`\`bash
vouch init --domain agent.example.com
\`\`\`

This creates an Ed25519 keypair, derives a did:web DID, and stores the private key in your platform's secure key store. The public key is published in a DID Document you can serve at \`https://agent.example.com/.well-known/did.json\`.

## Sign a credential

\`\`\`python
from vouch import Signer, build_vouch_credential

signer = Signer.from_did("did:web:agent.example.com")

credential = build_vouch_credential(
    subject_did="did:web:agent.example.com",
    intent={
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
    valid_seconds=300,
)

signed = signer.sign_credential(credential)
print(signed["proof"]["proofValue"])
\`\`\`

The \`signed\` dict is the full W3C Verifiable Credential with a Data Integrity proof attached.

## Verify it

\`\`\`python
from vouch import Verifier
import asyncio

verifier = Verifier()
result = asyncio.run(verifier.verify_credential(signed))
print(result.valid, result.reasons)
\`\`\`

## What you have now

- A DID controlled by your local key
- A signed VC binding an action to a specific resource
- Verification that runs anywhere with internet access to your DID Document

Next: try [signing with the hybrid post-quantum profile](#hybrid-pq) or [adding a delegation chain](#delegation-chains).
`,
            },
            {
                id: 'quickstart-typescript',
                title: 'TypeScript Quickstart',
                summary: 'Same flow in Node or browser. Cross-verifies with Python-signed credentials.',
                body: `
## Install

\`\`\`bash
npm install @vouch-protocol/core
\`\`\`

## Sign a credential

\`\`\`ts
import { Signer, buildVouchCredential } from '@vouch-protocol/core';

const signer = await Signer.fromDid('did:web:agent.example.com');

const credential = buildVouchCredential({
    subjectDid: 'did:web:agent.example.com',
    intent: {
        action: 'submit_claim',
        target: 'claim:HC-001',
        resource: 'https://insurance.example.com/claims/HC-001',
    },
    validSeconds: 300,
});

const signed = await signer.signCredential(credential);
console.log(signed.proof.proofValue);
\`\`\`

## Verify

\`\`\`ts
import { Verifier } from '@vouch-protocol/core';

const verifier = new Verifier();
const result = await verifier.verifyCredential(signed);
console.log(result.valid, result.reasons);
\`\`\`

## Cross-language interop

A credential signed in Python verifies byte-identically in TypeScript and vice versa, thanks to RFC 8785 JCS canonicalization. The test vectors at [test-vectors/hybrid-eddsa-mldsa44/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors/hybrid-eddsa-mldsa44) exercise this.

## Browser vs Node

The TypeScript SDK works in both. In the browser, key storage falls back to IndexedDB (with optional WebAuthn-gated unlock) rather than the platform key store. In Node, you can pass a custom KMS provider.
`,
            },
            {
                id: 'quickstart-go',
                title: 'Go Sidecar Quickstart',
                summary: 'Run the long-running signing daemon. Sign credentials from any language over HTTP.',
                body: `
## Build the binary

\`\`\`bash
git clone https://github.com/vouch-protocol/vouch
cd vouch/go-sidecar
go build ./cmd/vouch-sidecar
\`\`\`

Or via go install:

\`\`\`bash
go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest
\`\`\`

## Run

\`\`\`bash
./vouch-sidecar --did did:web:agent.example.com --port 8877
\`\`\`

Optional flags:

- \`--sensitive\` or \`-s\` - wrap the response in a JWE so the credential is encrypted in flight
- \`--hybrid\` - use the hybrid post-quantum cryptosuite
- \`--verbose\` - detailed startup logs

## Sign a credential

Any language can sign by POSTing to the sidecar:

\`\`\`bash
curl -X POST http://localhost:8877/sign \\
    -H 'Content-Type: application/json' \\
    -d '{
        "subjectDid": "did:web:agent.example.com",
        "intent": {
            "action": "submit_claim",
            "target": "claim:HC-001",
            "resource": "https://insurance.example.com/claims/HC-001"
        },
        "validSeconds": 300
    }'
\`\`\`

The response is the full signed W3C VC.

## Why a sidecar?

The Identity Sidecar pattern keeps the private signing key out of the LLM's process. The LLM emits a tool-call object; the orchestration layer (your Python or TypeScript code) asks the sidecar to sign on the agent's behalf; the sidecar returns a credential bound to the action.

This makes prompt-injection key-exfiltration impossible: even if the LLM is jailbroken to leak its context, the key is not in that context.
`,
            },
        ],
    },

    {
        id: 'identity-and-signing',
        title: 'Identity & Signing',
        description: 'Working with DIDs, keypairs, delegation chains, and the hybrid PQ profile.',
        articles: [
            {
                id: 'did-management',
                title: 'Managing DIDs and Keys',
                summary: 'did:web vs did:key, where keys live, how to rotate.',
                body: `
## did:web vs did:key

**did:web** resolves over HTTPS to a DID Document at \`https://{domain}/.well-known/did.json\` (or a path-based variant). Good for production agents owned by an organization; the domain anchors trust.

**did:key** contains the public key inside the identifier itself. Self-resolving, no infrastructure. Good for ephemeral or fully decentralized agents.

Both are W3C Core DID methods. Vouch supports both natively.

## Key storage

The Python SDK uses your platform's secure key store by default (Keychain on macOS, DPAPI on Windows, secretstore on Linux). For server deployments, use the KMS abstraction at \`vouch/kms.py\`:

- AWS KMS (via boto3)
- GCP KMS (via google-cloud-kms)
- Azure Key Vault
- Local encrypted file with optional passphrase

## Key rotation

\`vouch/kms.py\` exposes \`RotatingKeyProvider\`. Configure the rotation window:

\`\`\`python
from vouch.kms import RotatingKeyProvider, KeyConfig
from datetime import timedelta

provider = RotatingKeyProvider(
    backend="aws-kms",
    key_id="alias/vouch-agent",
    rotation_period=timedelta(days=90),
)
\`\`\`

The DID Document publishes both the current and the previous keys during the overlap window, so in-flight credentials remain verifiable.
`,
            },
            {
                id: 'hybrid-pq',
                title: 'Using the Hybrid Post-Quantum Profile',
                summary: 'Ed25519 + ML-DSA-44 in one cryptosuite, three verifier modes, all three SDKs.',
                body: `
## Install dependencies

Python:

\`\`\`bash
pip install 'vouch-protocol[pq]'
\`\`\`

TypeScript:

\`\`\`bash
npm install @noble/post-quantum
\`\`\`

Go:

The Cloudflare circl dependency is already transitive in the sidecar.

## Sign

Python:

\`\`\`python
from vouch import Signer

signer = Signer.from_did_with_hybrid("did:web:agent.example.com")
signed = signer.sign_credential_hybrid(credential)
\`\`\`

TypeScript:

\`\`\`ts
import { Signer } from '@vouch-protocol/core';

const signer = await Signer.fromDidWithHybrid('did:web:agent.example.com');
const signed = await signer.signCredentialHybrid(credential);
\`\`\`

Go sidecar: pass \`--hybrid\` when starting the daemon.

## What the wire format looks like

\`\`\`
proof.cryptosuite = "hybrid-eddsa-mldsa44-jcs-2026"
proof.proofValue  = "z" + base58btc(ed25519_sig[64] || mldsa44_sig[2420])
\`\`\`

Both signatures cover the **same** JCS-canonicalized credential bytes (PAD-040 same-bytes property).

## Verifier modes

A verifier can be configured for three modes:

- **Mode A (classical-only)** - validates only the Ed25519 part
- **Mode B (PQ-only)** - validates only the ML-DSA-44 part
- **Mode C (both required)** - validates both, fails if either fails

Mode C is the strictest. Mode A is useful for verifiers that have not yet been upgraded to support ML-DSA-44 (graceful downgrade during migration).

## DID Document layout

A hybrid agent publishes both keys in its DID Document:

\`\`\`json
{
    "id": "did:web:agent.example.com",
    "verificationMethod": [
        { "id": "...#key-ed25519", "type": "Multikey", "publicKeyMultibase": "z6Mk..." },
        { "id": "...#key-mldsa44", "type": "Multikey", "publicKeyMultibase": "z87..." }
    ]
}
\`\`\`

The verifier picks the appropriate verification method based on the credential's cryptosuite.

## Size and performance

| Property | Ed25519 only | Hybrid |
|---|---|---|
| Signature size | 64 bytes | 2,484 bytes |
| Credential size (typical) | ~700 B | ~3.2 KB |
| Sign time (M2) | ~50µs | ~3ms |
| Verify time (M2) | ~150µs | ~3ms |

Hybrid credentials exceed typical HTTP header size limits, so transmit them in the request body (CG Report §13.4).
`,
            },
            {
                id: 'delegation-chains',
                title: 'Building Delegation Chains',
                summary: 'Verifiable principal → agent → sub-agent chains with resource narrowing.',
                body: `
## Why chains

When a human principal delegates to an agent that delegates to a sub-agent, you need a verifiable audit trail. The delegation chain answers: who authorized this action, and what was the scope at each step?

## Three rules

1. Each link is a signed Vouch credential where the **issuer** is the **subject** of the previous link.
2. Each link's \`resource\` MUST be a subset of the previous link's. You cannot delegate authority you do not have.
3. The chain must terminate at a principal (typically a human, or a system root).

## Build a chain in Python

\`\`\`python
from vouch import Signer, build_vouch_credential

principal = Signer.from_did("did:web:principal.example.com")
agent = Signer.from_did("did:web:agent.example.com")
sub_agent = Signer.from_did("did:web:sub-agent.example.com")

# Principal delegates to agent
principal_link = principal.sign_credential(build_vouch_credential(
    subject_did=agent.did,
    intent={"action": "*", "target": "*", "resource": "https://insurance.example.com/claims/*"},
    valid_seconds=3600,
))

# Agent narrows and delegates to sub-agent
agent_link = agent.sign_credential(build_vouch_credential(
    subject_did=sub_agent.did,
    intent={"action": "read", "target": "claim:HC-001", "resource": "https://insurance.example.com/claims/HC-001"},
    valid_seconds=300,
    delegated_from=[principal_link],
))

# Sub-agent signs its actual action
action = sub_agent.sign_credential(build_vouch_credential(
    subject_did=sub_agent.did,
    intent={"action": "read", "target": "claim:HC-001", "resource": "https://insurance.example.com/claims/HC-001"},
    valid_seconds=60,
    delegated_from=[principal_link, agent_link],
))
\`\`\`

## Verify

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify_delegation_chain([principal_link, agent_link, action])
\`\`\`

The verifier walks every link, validates each signature, and confirms resource narrowing.
`,
            },
        ],
    },

    {
        id: 'deployment',
        title: 'Production Deployment',
        description: 'Sidecar, KMS, storage backends, metrics, rate limiting.',
        articles: [
            {
                id: 'sidecar-deployment',
                title: 'Deploying the Go Sidecar',
                summary: 'Containerizing, key provisioning, health checks, observability.',
                body: `
## Build container

The Go binary is statically linked; you can put it in a scratch image.

\`\`\`dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /vouch-sidecar ./go-sidecar/cmd/vouch-sidecar

FROM scratch
COPY --from=build /vouch-sidecar /vouch-sidecar
ENTRYPOINT ["/vouch-sidecar"]
\`\`\`

## Key provisioning

Three options in order of recommendation:

1. **Cloud KMS** - mount KMS credentials, configure the sidecar with the key alias
2. **Init container** - provision keys via Vault or AWS Secrets Manager, write to a tmpfs volume
3. **Direct env var** - acceptable for development only

## Health check

\`GET /health\` returns 200 OK with a JSON body indicating ready state and last successful signature.

## Observability

The sidecar emits structured JSON logs on stdout. For metrics, run it alongside the Python verifier's Prometheus exporter, or use the OpenTelemetry exporter (\`--otel-endpoint\`) for distributed tracing.

## Scaling

The sidecar is stateless. Horizontally scale by running multiple instances behind a load balancer. Each instance needs access to the same KMS key (or its own replica of the agent's key for hot-standby).
`,
            },
            {
                id: 'kms-integration',
                title: 'KMS Integration',
                summary: 'AWS, GCP, Azure, Local file. How to configure each.',
                body: `
## AWS KMS

\`\`\`python
from vouch.kms import RotatingKeyProvider

provider = RotatingKeyProvider(
    backend="aws-kms",
    key_id="alias/vouch-agent-prod",
    region="us-east-1",
)
\`\`\`

Requires \`boto3\` and IAM permissions \`kms:Sign\` and \`kms:GetPublicKey\` on the key.

## GCP KMS

\`\`\`python
provider = RotatingKeyProvider(
    backend="gcp-kms",
    key_id="projects/my-proj/locations/global/keyRings/vouch/cryptoKeys/agent",
)
\`\`\`

Requires \`google-cloud-kms\` and the \`roles/cloudkms.signer\` IAM role.

## Azure Key Vault

\`\`\`python
provider = RotatingKeyProvider(
    backend="azure-kv",
    key_id="https://vouch-kv.vault.azure.net/keys/agent/abc123",
)
\`\`\`

Requires \`azure-keyvault-keys\` and the Key Vault Crypto Officer role.

## Local file (development only)

\`\`\`python
provider = RotatingKeyProvider(
    backend="local-file",
    key_id="/etc/vouch/agent.jwk",
    passphrase=os.environ["VOUCH_KEY_PASSPHRASE"],
)
\`\`\`
`,
            },
            {
                id: 'reputation',
                title: 'Deploying the Reputation Engine',
                summary: 'Memory, Redis, Kafka, HTTP backends. Decay model and tiers.',
                body: `
## What the engine does

\`vouch/reputation.py\` (711 lines) tracks an integer reputation score per DID. The score is shaped by:

- Action deltas: success \`+1\`, failure \`-2\`, slash and boost configurable
- Exponential decay toward baseline (default \`base=50\`, rate \`0.1/day\`, kicks in after 7 days of inactivity)
- Tier classification:
    - \`exceptional\` for score ≥ 90
    - \`trusted\` for ≥ 75
    - \`neutral\` for ≥ 50
    - \`cautionary\` for ≥ 25
    - \`untrusted\` otherwise

## Memory backend (dev)

\`\`\`python
from vouch.reputation import ReputationEngine, MemoryReputationStore

engine = ReputationEngine(store=MemoryReputationStore())
\`\`\`

## Redis backend (single-region production)

\`\`\`python
from vouch.reputation import RedisReputationStore
engine = ReputationEngine(store=RedisReputationStore(url="redis://prod:6379/0"))
\`\`\`

## Kafka backend (event-sourced)

\`\`\`python
from vouch.reputation import KafkaReputationStore
engine = ReputationEngine(store=KafkaReputationStore(
    bootstrap_servers="kafka:9092",
    topic="vouch-reputation-events",
))
\`\`\`

Reputation events are appended to the topic. Downstream services can replay the topic to reconstruct state, derive analytics, or feed into a downstream auditor.

## HTTP backend (cross-org)

\`\`\`python
from vouch.reputation import HTTPReputationStore
engine = ReputationEngine(store=HTTPReputationStore(
    base_url="https://reputation.consortium.example/v1",
    api_key=os.environ["REPUTATION_API_KEY"],
))
\`\`\`

For consortium deployments where reputation is shared across organizations.

## Scope note

The W3C CG Report says specific reputation scoring **algorithms** are non-normative; the shipped engine is a reference implementation. Implementers MAY swap in their own algorithm by implementing the \`ReputationStoreInterface\`.
`,
            },
            {
                id: 'revocation',
                title: 'Deploying the Revocation Registry',
                summary: 'DID-level revocation vs credential-level BitstringStatusList.',
                body: `
## Two kinds of revocation

**DID-level**: revoke an entire agent identity. All credentials issued by that DID become invalid. Useful when a key is compromised or an agent is decommissioned. \`vouch/revocation.py\` (449 lines) ships this.

**Credential-level**: revoke a single credential by index in a BitstringStatusList. Useful when a specific action needs to be retracted without affecting the rest of the agent's history. Referenced in the spec; an integration runtime is on the roadmap.

## Backends

Memory and Redis ship today. The \`RevocationStoreInterface\` is abstract so custom backends (HTTP remote registries, distributed key-value stores) are straightforward.

\`\`\`python
from vouch.revocation import RevocationRegistry, RedisRevocationStore

registry = RevocationRegistry(store=RedisRevocationStore(url="redis://prod:6379/1"))

# Revoke a DID
await registry.revoke(
    did="did:web:compromised-agent.example.com",
    reason="key_compromise",
    revoked_by="did:web:security-team.example.com",
)

# Check status
is_revoked = await registry.is_revoked("did:web:compromised-agent.example.com")
\`\`\`

## How the verifier uses it

The verifier consults the revocation registry on every verification. If the issuing DID is revoked, the credential fails with reason \`issuer_revoked\`. Cache TTL is configurable (default 60 seconds) to balance freshness with verifier throughput.
`,
            },
            {
                id: 'metrics-and-observability',
                title: 'Metrics and Observability',
                summary: 'Prometheus and OpenTelemetry, what to alert on.',
                body: `
## Prometheus metrics

\`vouch/metrics.py\` exposes:

\`\`\`
vouch_signatures_total            counter
vouch_verifications_total         counter
vouch_verification_success_rate   gauge
vouch_verification_latency_seconds  histogram
vouch_cache_hits                  counter
vouch_cache_misses                counter
vouch_credential_issuances        counter
vouch_reputation_lookups          counter
vouch_revocation_checks           counter
\`\`\`

Mount the exporter on \`/metrics\` of your verifier service.

## OpenTelemetry

Install the OTel extra:

\`\`\`bash
pip install 'vouch-protocol[otel]'
\`\`\`

Then point at your collector via \`OTEL_EXPORTER_OTLP_ENDPOINT\`. Verifier spans include credential ID, DID, and outcome.

## What to alert on

- \`vouch_verification_success_rate\` dropping below 0.99 over a 5-minute window
- \`vouch_verification_latency_seconds\` p99 exceeding your SLO (typical: 50ms with caching)
- \`vouch_revocation_checks\` increasing without a corresponding rise in \`vouch_verifications_total\` (suggests a verifier loop is consulting the registry inefficiently)
`,
            },
        ],
    },

    {
        id: 'integrations',
        title: 'Framework Integrations',
        description: 'LangChain, CrewAI, AutoGPT, AutoGen, MCP, Vouch Shield, GitHub App.',
        articles: [
            {
                id: 'integrations',
                title: 'Framework Integration Overview',
                summary: 'Which frameworks have shipped integrations and where they live.',
                body: `
## Python integrations

All under \`vouch/integrations/\`:

| Framework | File | What it does |
|---|---|---|
| LangChain | \`langchain/tool.py\` | Wraps a LangChain Tool so its inputs are signed before execution |
| CrewAI | \`crewai/tool.py\` | Same pattern for crew-style multi-agent flows |
| AutoGPT | \`autogpt/commands.py\` | Command integration for AutoGPT plugins |
| AutoGen | \`autogen/tool.py\` | Tool wrapper for AutoGen conversational agents |
| Streamlit | \`streamlit/seal.py\` | Media-sealing UI helper for Streamlit apps |
| Vertex AI | \`vertex_ai/tool.py\` | Google Vertex AI tool integration |
| Google ADK | \`adk.py\` | Agent Development Kit integration |
| Google APIs | \`google.py\` | Generic Sheets/Docs/Drive integration |
| n8n | \`n8n.py\` | n8n workflow automation node |
| Hasura | \`hasura/webhook.py\` | GraphQL webhook handler |
| MCP | \`mcp/server.py\` | Reference Model Context Protocol server |

End-to-end examples are at [examples/05_integrations/](https://github.com/vouch-protocol/vouch/tree/main/examples/05_integrations).

## TypeScript integrations

Currently one: \`packages/sdk-ts/src/integrations/amnesia.ts\` for the Amnesia egress-decision bridge.

## Vouch Shield (sibling repo)

[vouch-protocol/vouch-shield](https://github.com/vouch-protocol/vouch-shield) is a TypeScript runtime middleware that intercepts tool calls and enforces signature verification, allowlist, capability permissions, and audit logging. Treat it as the enforcement layer that consumes Vouch credentials at execution time.
`,
            },
            {
                id: 'github-app',
                title: 'Vouch Gatekeeper GitHub App',
                summary: 'Enforce signed commits and organizational policy on every PR.',
                body: `
## What it does

Vouch Gatekeeper listens for \`pull_request.opened\` and \`pull_request.synchronize\` events. For each PR, it verifies commit signatures with GitHub's SSH/GPG infrastructure first, and falls back to the Vouch Registry if a commit is not signed via those mechanisms.

## Zero-config policy

Org member with a signed commit = allow. That is the default; no configuration needed.

## Custom policy

Add \`.github/vouch-policy.yml\` to your repo:

\`\`\`yaml
allowlist:
    - did:web:alice.example.com
    - did:key:z6Mk...
blocklist: []
require_signed_commits: true
require_co_authored_with_did: false
\`\`\`

## Install

GitHub App URL: [github.com/apps/vouch-gatekeeper](https://github.com/apps/vouch-gatekeeper) (see the live install in the repo's \`github-app/app-manifest.json\`).

The app auto-opens a PR on installation to add the protection badge to your README:

\`\`\`md
![Vouch Protected](https://api.vouch-protocol.com/api/badge/{owner}/{repo})
\`\`\`

## Architecture

FastAPI service (\`github-app/main.py\`, ~1000 lines). Webhook endpoint at \`/webhook\`, badge endpoint at \`/api/badge/{owner}/{repo}\`. Setup flow at \`/setup\` redirects through GitHub OAuth and back to \`/setup/callback\`.
`,
            },
            {
                id: 'vouch-shield',
                title: 'Wiring Up Vouch Shield',
                summary: 'Drop the middleware in front of your agent\'s tool layer.',
                body: `
## Install

\`\`\`bash
npm install @vouch-protocol/shield
\`\`\`

## Basic usage

\`\`\`ts
import { VouchShield, generateKeypair, signPayload } from '@vouch-protocol/shield';

const shield = new VouchShield({ strictMode: true });

// Trust a specific identity
const identity = generateKeypair();
shield.registerPublicKey(identity.did, identity.publicKey);
shield.trustDid(identity.did);
shield.setCapabilities(identity.did, {
    filesystem: 'read',
    network: 'outbound',
    shell: 'none',
});

// Before executing a tool call, intercept
const signedRequest = signPayload(
    { file: '/data/input.txt' },
    identity.secretKey,
    identity.did,
);

const result = shield.interceptToolCall({
    tool: 'read_file',
    args: { file: '/data/input.txt' },
    signedPayload: signedRequest,
});

if (result.allowed) {
    // Execute the tool
} else {
    console.error('Blocked:', result.reason);
}
\`\`\`

## Where Shield sits

Between your framework's tool-call event and the actual tool function. If you use LangChain in TypeScript, intercept in the \`AgentExecutor\` callback. If you use a custom orchestrator, intercept in your tool-dispatch loop.

## Audit trail

The \`FlightRecorder\` logs every allowed and blocked call. Pipe it to your SIEM or store it locally for after-the-fact audit.
`,
            },
        ],
    },

    {
        id: 'cli',
        title: 'CLI Reference',
        description: 'The full vouch command and what each subcommand does.',
        articles: [
            {
                id: 'cli-reference',
                title: 'Complete vouch CLI Reference',
                summary: 'Every subcommand, its flags, and a copy-pasteable example.',
                body: `
## init

Generate a new Ed25519 keypair, derive a DID, and store the key securely.

\`\`\`bash
vouch init [--domain DOMAIN] [--env]
\`\`\`

- \`--domain DOMAIN\` - generates a did:web DID for the given domain
- Without \`--domain\` - generates a did:key DID
- \`--env\` - exports the DID and key path as shell env vars

## credential sign

Sign a W3C Verifiable Credential.

\`\`\`bash
vouch credential sign credential.json
vouch credential sign credential.json --hybrid    # use hybrid PQ profile
\`\`\`

## credential verify

Verify a W3C credential file.

\`\`\`bash
vouch credential verify signed.json
\`\`\`

## git init

One-command setup of the Vouch git workflow: configures SSH signing, installs commit hooks, and (optionally) injects a CI badge into the README.

\`\`\`bash
cd my-repo
vouch git init
\`\`\`

## git status

Show the current Vouch git configuration for this repo.

\`\`\`bash
vouch git status
\`\`\`

## reputation get

Fetch a DID's reputation score from the configured backend.

\`\`\`bash
vouch reputation get --did did:web:agent.example.com
\`\`\`

## revocation check

Check whether a DID is in the revocation registry.

\`\`\`bash
vouch revocation check --did did:web:agent.example.com
\`\`\`

## Output formats

All subcommands support \`--json\` for machine-readable output. The default is human-readable. Use \`--env\` to format output as shell exports for scripting.
`,
            },
        ],
    },
];
