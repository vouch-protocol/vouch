/**
 * Vouch Protocol FAQ content
 *
 * Single-page FAQ organized by audience. Each section has audience tag,
 * title, and an array of Q&A entries. Answers may include inline links
 * [text](url) which the renderer parses.
 *
 * Goal: document what is *actually shipped* in the repo so the editor
 * (or any reader) can use this to recollect / onboard after time away.
 *
 * Every claim here is cross-checked against:
 *   vouch-protocol/CHANGELOG.md (current: v1.6.0)
 *   vouch-protocol/vouch/ (Python SDK)
 *   vouch-protocol/packages/sdk-ts/ (TypeScript SDK)
 *   vouch-protocol/go-sidecar/ (Go sidecar)
 *   vouch-protocol/vouch-shield (sibling repo)
 *   vouch-protocol/docs/specs/w3c-cg-report.md
 */

export interface FAQItem {
    q: string;
    a: string;
    /** Optional cross-link to a Help/Guides anchor for deeper reading. */
    helpLinks?: { label: string; href: string }[];
    /** Optional metadata footnote: spec section, PAD reference, shipped-in version. */
    meta?: string;
}

export interface FAQSection {
    /** Section slug (URL anchor) */
    id: string;
    /** Mono uppercase audience tag, e.g., "For Developers" */
    audience: string;
    /** Serif section title, e.g., "Getting Vouch into your codebase" */
    title: string;
    items: FAQItem[];
}

export const FAQ_SECTIONS: FAQSection[] = [
    // =====================================================================
    // ABOUT VOUCH
    // =====================================================================
    {
        id: 'about',
        audience: 'About Vouch',
        title: 'What the protocol is and why it exists',
        items: [
            {
                q: 'What is Vouch Protocol?',
                a: `Vouch is a digital signature layer for AI agents. When your agent does something on your behalf (sends an email, transfers money, files a claim, queries a database), Vouch lets it cryptographically sign that action so anyone, anywhere, can later prove who did what and with whose permission.

Think of it as a tamper-proof receipt for every move an autonomous AI makes. The receipt is human-readable, cryptographically signed, and works across whatever framework you use to build agents (LangChain, CrewAI, MCP, anything).`,
            },
            {
                q: 'What problem does it solve?',
                a: `AI agents are doing real work now: they submit insurance claims, place trades, file regulatory reports, access patient records. When something goes wrong (and eventually something will), you need to know exactly which agent took which action, who authorized it, and whether the agent had permission.

The tools we built for humans (API keys, login sessions, OAuth tokens) were not designed for this. They prove someone has access. They don't prove what the agent intended to do, who delegated the action down to it, or whether the agent is still behaving correctly.

Vouch fixes this by turning every agent action into a signed receipt. Identity, intent, target, and the chain of permissions are all cryptographically bound together. If your CFO asks "did our agent really wire that money?", you can prove it in seconds, with math, not log files.`,
            },
            {
                q: 'How is this different from OAuth, API keys, or JWTs?',
                a: `Three big differences:

**1. The agent owns its identity.** With API keys, someone hands the agent a string. With Vouch, the agent generates its own cryptographic identity. Nobody, including the issuer, can impersonate it or take it away from afar.

**2. Every action carries its intent.** An API key just says "I'm allowed in." A Vouch credential says "I am Agent A, I want to submit *this specific claim* to *this specific URL*, at *this specific time*, and here is the chain of humans who approved it." Replaying the credential against any other resource literally cannot work.

**3. Trust expires fast and renews continuously.** A bearer token is good until someone remembers to revoke it. Vouch flips this: agents are untrusted by default and must renew their credentials on a heartbeat. If an agent goes silent (crashed, compromised, network split), its permissions expire on their own. No manual cleanup.`,
            },
            {
                q: 'Can I use Vouch in production today?',
                a: `**Yes, for what most teams need.** Signing your agent's actions, verifying them anywhere, building permission chains between multiple agents, revoking compromised credentials, and being post-quantum ready: all shipped, all tested across Python, TypeScript, and Go, all have published test vectors. Build on it today.

**The "continuous trust scoring" layer now ships in the Python SDK.** That's the part where the credential's trust value decays over time, multiple validators can agree on whether your agent is behaving correctly while it's running, and a missed heartbeat is cryptographically detectable. The six new modules (trust entropy decay, behavioral attestation digest, canary commit/reveal chain, Merkle trees, heartbeat orchestration, validator quorum) animate the SessionVoucher format end-to-end. TypeScript and Go ports of these runtime pieces are not yet shipped; the data formats are already cross-language.

**Vouch Shield**, our optional runtime middleware that checks every tool call against your permission rules, is also production-ready (TypeScript library).`,
            },
            {
                q: 'Who is behind Vouch?',
                a: `Vouch is a personal open-source project from [Ramprasad Gaddam](https://github.com/vouch-protocol), an AI engineering director with 20+ years in regulated industries (healthcare, banking, manufacturing), 20 patents in cryptography and AI, and active membership in W3C, The Linux Foundation, C2PA, the Content Authenticity Initiative, DIF, and IEEE.

It is not affiliated with or endorsed by any employer.`,
            },
            {
                q: 'Where does the name come from?',
                a: `To vouch for someone is to publicly stand behind them and take responsibility if they let you down. A Vouch credential does the same thing in code: an agent stands behind its own action, and the chain of people who delegated to it stands behind the agent.`,
            },
            {
                q: 'Is Vouch free? What is the license?',
                a: `Yes, fully free and open-source. **Apache 2.0** for all code and the specification. **CC0** (public domain) for the 55 design disclosures we've published. Use it in commercial products, fork it, sell things built on top of it. We just ask that you don't try to patent the ideas back at us.`,
            },
            {
                q: 'Where can I read the formal specification?',
                a: `Most people never need to. The FAQ and [Guides](/help/) cover everything you'll use day to day. But if you want the formal version, it's at [docs/specs/w3c-cg-report.md](https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md), with an executive summary [here](https://github.com/vouch-protocol/vouch/blob/main/docs/specs/cg-report-executive-summary.md). Vouch is on the W3C standards track via the Credentials Community Group.`,
            },
        ],
    },

    // =====================================================================
    // CORE CONCEPTS
    // =====================================================================
    {
        id: 'concepts',
        audience: 'How It Works',
        title: 'The pieces, explained simply',
        items: [
            {
                q: 'What is a DID, in plain English?',
                a: `A DID (Decentralized Identifier) is a username your agent gives itself, backed by a cryptographic key only your agent holds. No registrar, no central authority can take it away.

Think of it like a passport you issue to yourself, where the passport's authenticity is proven by math, not by a government stamp. Vouch uses two flavours:

- **did:web** looks like \`did:web:agent.example.com\` and points to a small JSON file on your domain. Use this when you own a domain.
- **did:key** looks like \`did:key:z6Mk...\` and the public key is baked into the identifier itself. Use this for quick experiments or self-contained agents that don't need a website.`,
            },
            {
                q: 'What is a Verifiable Credential?',
                a: `A Verifiable Credential is a small piece of signed JSON that says "the holder of this DID claims X." For Vouch, X is something like "I, Agent A, am about to submit claim HC-001 to the insurance system at this URL."

The credential is signed by whoever issues it (the agent itself, a human delegator, or a validator). Anyone with the issuer's public key can verify the signature later. Tamper with even one character and the signature breaks.

A Vouch credential is just a Verifiable Credential with an \`intent\` field that pins down what the agent is doing and to what.`,
            },
            {
                q: 'What is a Data Integrity proof?',
                a: `It is the cryptographic signature glued to the side of a Verifiable Credential. Vouch uses a W3C standard called Data Integrity, which keeps the credential as plain readable JSON and attaches the proof as a separate object next to it. You can open a Vouch credential in any text editor and read it.

By default Vouch uses Ed25519 (fast, well-known elliptic-curve signatures). If you need post-quantum protection, switch to the hybrid cryptosuite that signs with both Ed25519 *and* ML-DSA-44 (a NIST-approved post-quantum algorithm).`,
            },
            {
                q: 'Why do you talk about "JCS canonicalization"?',
                a: `It is a fancy name for "write this JSON the exact same way every time." JCS (RFC 8785) gives every implementation the same recipe: sort keys alphabetically, format numbers the same way, no random whitespace. Same JSON in, same bytes out.

This matters because signatures are over bytes, not over abstract JSON. If your Python signs the credential but the bytes look different when TypeScript serializes the same data, the signature breaks. JCS makes that impossible. It is the reason a Vouch credential signed in Python can be verified in TypeScript or Go without any conversion.`,
            },
            {
                q: 'What is the Identity Sidecar pattern, and why should I care?',
                a: `It is a deployment trick that keeps your agent's private signing key away from the language model.

Here is the problem: your LLM-driven agent has tools, and a prompt-injection attack could trick it into leaking anything in its context window. If the private key is in that context, the attacker now controls your agent's identity.

The fix: run a small separate process (the "sidecar") that owns the key. When the agent wants to sign something, it asks the sidecar over a local connection. The sidecar signs, returns the credential, and never exposes the key to the LLM. Vouch ships a small Go binary you can run as the sidecar.`,
            },
            {
                q: 'What is the Heartbeat Protocol?',
                a: `It is a dead-man's-switch for long-running agents. Every few minutes (you pick the interval) the agent has to actively renew its credentials. If it crashes, gets disconnected, or is taken over, the renewals stop and its permissions expire on their own. No human has to remember to revoke anything.

The credential format for these renewals ships today (it is called SessionVoucher). The runtime that actually drives the heartbeats and coordinates with multiple validators is on the roadmap, not built yet.`,
            },
            {
                q: 'What is a delegation chain?',
                a: `A chain of permission slips that tracks "who let whom do what." Imagine you tell your assistant "please book my flight." Your assistant tells an AI travel agent "please find flights." The travel agent tells a payment agent "please charge this card." Three steps, three permission grants.

A Vouch delegation chain captures all three steps cryptographically. Each step narrows the permission (the travel agent can find flights but not, say, sell your house). At the end, anyone looking at the action can walk the chain backward to the human who started it. "The AI did it" becomes "Person X delegated to assistant Y who delegated to agent Z, and here is each signed step." Real accountability.`,
            },
        ],
    },

    // =====================================================================
    // FOR DEVELOPERS
    // =====================================================================
    {
        id: 'developers',
        audience: 'Building with Vouch',
        title: 'Adding Vouch to your code',
        items: [
            {
                q: 'Which languages have Vouch SDKs?',
                a: `Three reference SDKs that produce byte-identical credentials thanks to JCS canonicalization:

- **Python**: \`pip install vouch-protocol\` (most complete: signer, verifier, async verifier, KMS, reputation, revocation, cache, rate-limit, metrics, CLI)
- **TypeScript**: \`npm install @vouch-protocol/core\` (browser and Node: signer, verifier, JCS, hybrid PQ, vouch-client for sidecar RPC)
- **Go**: \`go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar\` (long-running daemon for the Identity Sidecar pattern)

Cross-language test vectors are published at [test-vectors/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors).`,
                helpLinks: [
                    { label: 'Python quickstart', href: '/help/#quickstart-python' },
                    { label: 'TypeScript quickstart', href: '/help/#quickstart-typescript' },
                    { label: 'Go sidecar quickstart', href: '/help/#quickstart-go' },
                ],
                meta: 'Shipped v1.6.0',
            },
            {
                q: 'How do I sign a credential in Python?',
                a: `Three lines after imports:

\`\`\`python
from vouch import Signer, build_vouch_credential

signer = Signer.from_did("did:web:agent.example.com")
credential = build_vouch_credential(
    subject_did="did:web:agent.example.com",
    intent={"action": "submit_claim", "target": "claim:HC-001",
            "resource": "https://insurance.example.com/claims/HC-001"},
    valid_seconds=300,
)
signed = signer.sign_credential(credential)
\`\`\`

The \`signed\` dict has a \`proof\` object with a \`proofValue\` (z-base58 encoded Ed25519 signature) and verification metadata.`,
                helpLinks: [{ label: 'Full Python quickstart', href: '/help/#quickstart-python' }],
            },
            {
                q: 'How do I sign with the hybrid post-quantum profile?',
                a: `Use \`sign_credential_hybrid()\` instead of \`sign_credential()\`. You need the optional \`pqcrypto\` dependency:

\`\`\`bash
pip install 'vouch-protocol[pq]'
\`\`\`

Then:

\`\`\`python
from vouch import Signer, build_vouch_credential

signer = Signer.from_did_with_hybrid("did:web:agent.example.com")
signed = signer.sign_credential_hybrid(credential)
\`\`\`

The resulting credential has \`proof.cryptosuite == "hybrid-eddsa-mldsa44-jcs-2026"\` and the \`proofValue\` is the concatenation of the Ed25519 signature (64 bytes) and the ML-DSA-44 signature (2,420 bytes), base58-encoded.`,
                helpLinks: [{ label: 'Hybrid PQ implementation guide', href: '/help/#hybrid-pq' }],
                meta: 'Shipped v1.6.0 - CG Report §13.2',
            },
            {
                q: 'How do I verify a credential signed in a different language?',
                a: `You don't need to do anything special. JCS canonicalization guarantees byte-identical signed payloads across languages, so a credential signed in Python verifies correctly in TypeScript or Go (and vice versa).

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify_credential(signed)  # accepts credentials from any SDK
\`\`\`

The published test vectors at [test-vectors/hybrid-eddsa-mldsa44/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors/hybrid-eddsa-mldsa44) include a Python-generated signature that is exercised by both the TypeScript and Go test suites.`,
                meta: 'PAD-039 JCS Deterministic Multi-Party Trust State',
            },
            {
                q: 'Do I need to run the Go sidecar?',
                a: `Only if you want the Identity Sidecar pattern, which is the recommended deployment for LLM-driven agents because it keeps the private key out of the LLM context window. If your code never exposes the key to the model (for example, a Python service signing on behalf of an agent), you can sign directly from the Python or TypeScript SDK.

The Go sidecar is also useful for polyglot stacks: it exposes \`POST /sign\` over HTTP, so any language can ask it to sign without having a Vouch SDK installed.`,
                helpLinks: [{ label: 'Sidecar deployment guide', href: '/help/#sidecar-deployment' }],
                meta: 'CG Report §10 - PAD-003',
            },
            {
                q: 'How do I verify a delegation chain?',
                a: `Pass the chain (list of credentials, principal first, agent last) to the verifier:

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify_delegation_chain([principal_vc, agent_vc, sub_agent_vc])
\`\`\`

The verifier walks every link, validates signatures, and confirms resource subset narrowing. If any link fails, the whole chain fails with a structured reason.`,
                meta: 'CG Report §9 Delegation Chains',
            },
            {
                q: 'How do I attach a credentialStatus (BitstringStatusList) to an issued credential?',
                a: `Two steps. First, allocate an index from your status list. Second, build a status entry and pass it to \`build_vouch_credential\`:

\`\`\`python
from vouch import (
    StatusList, build_status_list_entry, build_vouch_credential, Signer,
)

# Issuer maintains a single StatusList per status purpose (revocation or suspension).
status_list = StatusList(status_list_id="https://issuer.example/status/1")
index = status_list.allocate_index()

# Attach the status entry at issuance time.
status_entry = build_status_list_entry(
    status_list_credential="https://issuer.example/status/1",
    status_list_index=index,
)

credential = build_vouch_credential(
    issuer_did="did:web:issuer.example",
    intent={"action": "submit_claim", "target": "claim:HC-001",
            "resource": "https://insurance.example/claims/HC-001"},
    credential_status=status_entry,
)

signed = Signer.from_did("did:web:issuer.example").sign_credential(credential)
\`\`\`

The TypeScript and Go SDKs expose the same API (\`buildStatusListEntry\` / \`BuildStatusListEntry\`) and accept \`credentialStatus\` / \`CredentialStatus\` on their credential builders.`,
                helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
                meta: 'Shipped on main, in next release - CG Report §11.2',
            },
            {
                q: 'How do I revoke a credential I previously issued?',
                a: `Flip the bit at that credential's index in your status list, re-sign the BitstringStatusListCredential, and republish it:

\`\`\`python
status_list.revoke(index)  # set the bit

status_credential = build_status_list_credential(
    issuer_did="did:web:issuer.example",
    status_list=status_list,
)
signed_status_credential = signer.sign_credential(status_credential)

# Publish signed_status_credential at the URL referenced by issued credentials.
\`\`\`

Verifiers fetch the updated status credential, decode the bitstring, and observe that the bit is now set. The credential itself doesn't change; only the status list does.`,
                helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
                meta: 'Shipped on main, in next release',
            },
            {
                q: 'How does a verifier check credential status?',
                a: `Fetch the status list credential, then call \`verify_status\` with the credential's \`credentialStatus\` entry and the fetched list:

\`\`\`python
from vouch import StatusListFetcher, verify_status

fetcher = StatusListFetcher()  # in-memory TTL cache, conditional GETs

status_credential = fetcher.get(
    signed["credentialStatus"]["statusListCredential"]
)

is_revoked = verify_status(
    credential_status=signed["credentialStatus"],
    status_list_credential=status_credential,
)
\`\`\`

The fetcher caches by URL with a 5-minute default TTL and issues conditional GETs (\`If-None-Match\`, \`If-Modified-Since\`) so re-validation is cheap when the issuer hasn't updated the list. Set \`force_refresh=True\` on verification failure to handle stale-cache scenarios. TypeScript and Go callers can compose the equivalent with \`fetch()\` and \`net/http.Get()\` respectively.`,
                helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
                meta: 'Shipped on main, in next release',
            },
            {
                q: 'How does the issuer survive a restart without re-allocating indices?',
                a: `Use the persistence API. \`to_state_dict()\` returns a JSON-serializable dict containing the encoded bitstring **and** the allocation cursor (\`next_index\`), which is NOT recoverable from the encoded list alone:

\`\`\`python
from vouch import FilesystemStatusListStore

store = FilesystemStatusListStore("/var/lib/vouch/status-1.json")

# After every allocate / revoke, persist.
store.save(status_list)

# On startup:
status_list = store.load()
\`\`\`

\`FilesystemStatusListStore\` is a reference implementation with atomic temp-file + rename writes. Production deployments substitute Redis, Postgres, or S3 using the same state-dict API. Without persistence of \`next_index\`, an issuer restart would re-allocate already-used indices, silently overwriting prior revocations.`,
                helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
                meta: 'Shipped on main, in next release',
            },
            {
                q: 'What framework integrations exist?',
                a: `Python integrations live under \`vouch/integrations/\`:

- **LangChain** - tool wrapper that signs tool inputs before execution
- **CrewAI** - tool wrapper for crew-style multi-agent flows
- **AutoGPT** - command integration
- **AutoGen** - tool wrapper
- **Streamlit** - media-sealing UI helper
- **Vertex AI** - Google Vertex AI tool
- **Google ADK** - Agent Development Kit integration
- **Google APIs** - generic Sheets/Docs/Drive integration
- **n8n** - workflow automation node
- **Hasura** - GraphQL webhook
- **MCP** - Model Context Protocol server

Examples for each are in [examples/05_integrations/](https://github.com/vouch-protocol/vouch/tree/main/examples/05_integrations).

TypeScript currently has the Amnesia bridge in \`packages/sdk-ts/src/integrations/\`.`,
                helpLinks: [{ label: 'Framework integration guides', href: '/help/#integrations' }],
            },
            {
                q: 'Is there a CLI?',
                a: `Yes. \`pip install vouch-protocol\` installs the \`vouch\` command:

\`\`\`
vouch init [--domain DOMAIN] [--env]    Generate keypair + DID, store securely
vouch credential sign [--hybrid]        Sign a W3C Verifiable Credential
vouch credential verify                 Verify a W3C Verifiable Credential
vouch git init                          One-command Git workflow setup
vouch git status                        Show current Git config
vouch reputation get [--did DID]        Fetch reputation score
vouch revocation check [--did DID]      Check revocation status
\`\`\`

The CLI source is at \`vouch/cli.py\`.`,
                helpLinks: [{ label: 'CLI reference', href: '/help/#cli-reference' }],
            },
            {
                q: 'Where is the browser extension?',
                a: `Source at [browser-extension/](https://github.com/vouch-protocol/vouch/tree/main/browser-extension). Manifest v3, Chrome / Edge / Brave compatible. Adds a "Sign with Vouch" context menu on selected text, a popup for identity selection and verification, and shortlink resolution via vch.sh.

Build artifacts (.crx, .zip) are produced by the GitHub Actions workflow at [.github/workflows/build-extensions.yml](https://github.com/vouch-protocol/vouch/blob/main/.github/workflows/build-extensions.yml).`,
            },
            {
                q: 'Is there a mobile SDK?',
                a: `Yes. [mobile/expo-app/](https://github.com/vouch-protocol/vouch/tree/main/mobile/expo-app) is a React Native + Expo app supporting iOS and Android. It uses device-level Secure Enclave (iOS) and Android Keystore. Capture-time photo signing with EXIF preservation and a chain of trust linking to organizational credentials.`,
            },
        ],
    },

    // =====================================================================
    // FOR OPERATORS
    // =====================================================================
    {
        id: 'operators',
        audience: 'Running in Production',
        title: 'Deployment, keys, storage, observability',
        items: [
            {
                q: 'Which KMS backends are supported?',
                a: `\`vouch/kms.py\` (16 KB) supports:

- **Memory** - in-process key storage (development only)
- **AWS KMS** - via boto3
- **GCP KMS** - via google-cloud-kms
- **Azure Key Vault** - via azure-keyvault
- **Local File** - encrypted file storage with optional passphrase

The \`RotatingKeyProvider\` class handles automatic rotation by time or by validity period. \`KeyConfig\` is the dataclass that holds JWK, DID, key ID, and validity window.`,
                helpLinks: [{ label: 'KMS integration guide', href: '/help/#kms-integration' }],
                meta: 'Shipped v1.2.0 - vouch/kms.py',
            },
            {
                q: 'What storage backends does the revocation registry support?',
                a: `\`vouch/revocation.py\` (449 lines) supports Memory and Redis backends out of the box, with an abstract \`RevocationStoreInterface\` for custom backends (HTTP remote registries, distributed key-value stores, etc.).

This is **DID-level revocation** (revoke a DID, all credentials under it become invalid). For **credential-level revocation** (revoke a single credential by index in a status bitstring), Vouch ships a W3C BitstringStatusList implementation across all three SDKs (\`vouch.status_list\` in Python, \`packages/sdk-ts/src/status-list.ts\` in TypeScript, \`go-sidecar/signer/status_list.go\` in Go). The two mechanisms compose: BitstringStatusList for granular per-credential status, DID-level registry for "revoke everything from this compromised identity" scenarios.`,
                helpLinks: [
                    { label: 'Revocation deployment', href: '/help/#revocation' },
                    { label: 'Credential status (BitstringStatusList)', href: '/help/#credential-status' },
                ],
                meta: 'Shipped v1.2.0 (registry) + Unreleased (BitstringStatusList) - CG Report §11.2',
            },
            {
                q: 'What storage backends does the reputation engine support?',
                a: `\`vouch/reputation.py\` (711 lines) supports four backends:

- **MemoryReputationStore** - in-process dict
- **RedisReputationStore** - via redis-py
- **KafkaReputationStore** - event-sourced via Kafka topics
- **HTTP** - remote reputation API

The engine implements exponential decay toward a baseline (default rate 0.1/day, kicks in after 7 days of inactivity), action deltas (success +1, failure -2, slash/boost configurable), and five-tier classification (untrusted < cautionary < neutral < trusted < exceptional).

Note: the W3C CG Report scope statement says reputation *algorithms* are not normative; the shipped engine is a reference implementation.`,
                helpLinks: [{ label: 'Reputation deployment', href: '/help/#reputation' }],
                meta: 'Shipped v1.2.0 (engine), v1.3.1 (Signer integration)',
            },
            {
                q: 'What caching is built in?',
                a: `\`vouch/cache.py\` (9.4 KB) ships three cache backends: Memory (LRU), Redis (distributed), and Tiered (Memory + Redis fallback). The caches are used by the verifier to cache DID Document resolutions, public key lookups, and credential-status responses.`,
                meta: 'Shipped v1.1.3 - vouch/cache.py',
            },
            {
                q: 'How does rate limiting work?',
                a: `\`vouch/ratelimit.py\` (9.5 KB) implements token-bucket rate limiting backed by Redis (distributed) or Memory (local). Per-DID, per-IP, or per-tool buckets. Configurable burst capacity and refill rate.

For more aggressive primitives, [PAD-047](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-047-vdf-rate-limited-agent-actions.md) describes a Verifiable Delay Function (VDF) approach where minimum elapsed wall-clock time is cryptographically self-evident without trust in any clock authority.`,
                meta: 'Shipped v1.1.3 - PAD-047',
            },
            {
                q: 'How is replay attack prevention handled?',
                a: `\`vouch/nonce.py\` (7 KB) tracks recently-seen credential nonces and rejects duplicates. Memory or Redis backed, with configurable TTL (default 300 seconds). The verifier consults the nonce store on every verification.`,
                meta: 'Shipped v1.1.3',
            },
            {
                q: 'What metrics does Vouch expose?',
                a: `\`vouch/metrics.py\` (8.8 KB) emits Prometheus-compatible metrics:

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

OpenTelemetry exporters are optional via the \`[otel]\` extra.`,
                meta: 'Shipped v1.1.0',
            },
            {
                q: 'What throughput can the Python SDK handle?',
                a: `The reputation engine's three-tier storage architecture is sized for 10K-50K RPS deployments per the CHANGELOG. Signing and verification throughput depends on the chosen cryptosuite (ed25519 is fast, hybrid PQ adds ML-DSA-44's ~3ms sign cost per operation on M-series hardware). For high-throughput verifier paths, use \`async_verifier\` (\`vouch/async_verifier.py\`, 16 KB) which supports concurrent verification with caching.`,
                meta: 'Shipped v1.1.3 (async_verifier), v1.2.0 (reputation scale claims)',
            },
            {
                q: 'How do I deploy the Go sidecar?',
                a: `Build and run:

\`\`\`bash
cd go-sidecar
go build ./cmd/vouch-sidecar
./vouch-sidecar --did did:web:agent.example.com --port 8877
\`\`\`

The \`-s\` / \`--sensitive\` flag wraps the response in a JWE so the credential is encrypted in flight. The endpoint is \`POST /sign\` accepting a credential JSON body and returning the signed credential.

For containerized deployment, the [Dockerfile](https://github.com/vouch-protocol/vouch/tree/main/go-sidecar) is straightforward Go static binary in a scratch image.`,
                helpLinks: [{ label: 'Sidecar deployment guide', href: '/help/#sidecar-deployment' }],
            },
            {
                q: 'Is there a GitHub App?',
                a: `Yes. **Vouch Gatekeeper** ([github-app/](https://github.com/vouch-protocol/vouch/tree/main/github-app), FastAPI, ~1000 lines) enforces cryptographic identity and organizational policy on every PR. Listens for \`pull_request.opened\` and \`pull_request.synchronize\`. Verifies commit signatures with GitHub SSH/GPG first, falls back to the Vouch Registry. Zero-config policy is "org member with signed commit = allow." Custom policy via \`.github/vouch-policy.yml\`. Shields.io badge endpoint at \`/api/badge/{owner}/{repo}\`. Auto-opens a PR to add the protection badge on installation.`,
                helpLinks: [{ label: 'GitHub App setup guide', href: '/help/#github-app' }],
                meta: 'Shipped v1.4.0',
            },
            {
                q: 'Is there a Cloudflare Worker?',
                a: `Yes. [cloudflare-worker/](https://github.com/vouch-protocol/vouch/tree/main/cloudflare-worker) provides signature storage and shortlink redirection. Shortlinks at \`vch.sh/{id}\` redirect to \`vouch-protocol.com/v/{id}\`. Free tier (1-year expiry) and Pro tier (no expiry). Cloudflare KV bindings for storage.`,
            },
            {
                q: 'What about media provenance?',
                a: `Vouch leaves media provenance to [C2PA](https://c2pa.org) and works alongside it rather than reimplementing it. The \`c2pa-ca/\` directory contains an active Certificate Authority that issues Ed25519-signed C2PA certificates and embeds CBOR manifests in image metadata. The audio path (\`vouch/audio.py\`, 38 KB) implements multi-layer Hamming(7,4) watermarks with psychoacoustic masking for audio signing.`,
                meta: 'Shipped v1.5.0',
            },
            {
                q: 'How should I deploy the BitstringStatusList in production?',
                a: `Three operational pieces:

1. **Issuer-side storage**: Replace \`FilesystemStatusListStore\` (development) with a shared store so multiple issuer instances can coordinate. The state-dict API is backend-agnostic; common choices are Redis (\`SET status:1 <state-json>\`), Postgres (single row with \`UPDATE\` under SELECT FOR UPDATE), or S3 (with optimistic concurrency via ETags).

2. **Status list publishing**: Sign the \`BitstringStatusListCredential\` and serve it at a stable HTTPS URL, ideally with \`Cache-Control: max-age=...\` and \`ETag\` headers. The \`StatusListFetcher\` honors both. CDN-cacheable; the credential is public.

3. **Verifier-side caching**: The reference \`StatusListFetcher\` uses an in-memory cache, fine for single-process verifiers. For multi-instance verifier fleets, wrap it with a shared cache (Redis) so a revocation is visible across the fleet within one TTL window. On verification failure, set \`force_refresh=True\` to bypass the cache and pick up the latest list.`,
                helpLinks: [{ label: 'BitstringStatusList how-to', href: '/help/#credential-status' }],
                meta: 'Shipped on main, in next release',
            },
            {
                q: 'How big can a BitstringStatusList grow?',
                a: `The W3C minimum is 131,072 bits (16 KiB uncompressed; ~50 bytes compressed when empty). That's enough for 131,072 credentials per status list. For larger issuers, allocate a new status list when you approach exhaustion; each credential's \`credentialStatus.statusListCredential\` URL identifies which list it belongs to.

Practical operational sizing: 131,072 credentials at a 5-minute validity (typical short-lived agent credentials) means a single list covers roughly one year at 0.4 credentials/minute, or one day at ~91/minute. Plan list rotation accordingly.`,
                meta: 'W3C BitstringStatusList §4.2',
            },
        ],
    },

    // =====================================================================
    // FOR COMPLIANCE / REGULATORY
    // =====================================================================
    {
        id: 'compliance',
        audience: 'Compliance & Regulations',
        title: 'HIPAA, SR 11-7, EU AI Act, NIST and friends',
        items: [
            {
                q: 'Does Vouch satisfy HIPAA / HITECH?',
                a: `Vouch is not a HIPAA control by itself, no specification is. But Vouch provides the cryptographic primitives that map directly onto multiple HIPAA Technical Safeguards (45 CFR 164.312):

- **Audit Controls** (§164.312(b)) - every agent action is a non-repudiable signed credential
- **Integrity** (§164.312(c)) - Data Integrity proofs detect any post-hoc modification
- **Person or Entity Authentication** (§164.312(d)) - DIDs prove agent identity cryptographically
- **Transmission Security** (§164.312(e)) - delegation chains plus optional JWE wrapping in the sidecar

For 21 CFR Part 11 (electronic records / electronic signatures), the same proofs satisfy the integrity and authenticity requirements.`,
                meta: 'CG Report §1.1 - Healthcare framing',
            },
            {
                q: 'Does Vouch satisfy SR 11-7 / FFIEC AI guidance?',
                a: `SR 11-7 (Federal Reserve guidance on model risk management) and FFIEC AI guidance require a verifiable audit trail of model-driven decisions, the ability to attribute actions to specific model versions, and continuous monitoring of model behavior post-deployment.

Vouch addresses these through (a) intent-bound credentials with model-version metadata in the credential subject, (b) the Heartbeat Protocol for continuous post-deployment monitoring, and (c) reputation tracking and slashing for misbehavior detection. The [docs/THREAT_MODEL.md](https://github.com/vouch-protocol/vouch/blob/main/docs/THREAT_MODEL.md) maps Vouch primitives to SR 11-7 categories.`,
            },
            {
                q: 'Does Vouch satisfy the EU AI Act?',
                a: `The EU AI Act (applicable from 2025) imposes auditability and human-oversight obligations on high-risk AI systems. Vouch's delegation chains provide a verifiable principal-to-agent-to-sub-agent audit trail. The intent attestation in every credential satisfies the "human-interpretable record of the model's decision" requirement for high-risk systems. The Heartbeat Protocol provides the continuous monitoring required under Article 14.`,
                meta: 'CG Report §1.1 EU framing',
            },
            {
                q: 'Does Vouch satisfy NIST CNSA 2.0 / NSM-10 for post-quantum migration?',
                a: `Yes, in two phases. The current revision ships an **optional** hybrid Ed25519 + ML-DSA-44 profile (\`hybrid-eddsa-mldsa44-jcs-2026\`), aligning with the NIST CNSA 2.0 phase-in. As CNSA 2.0 advances and regulator guidance matures, the hybrid profile is expected to become RECOMMENDED for regulated sectors, then REQUIRED. Implementers operating in regulated sectors can adopt the hybrid profile today by passing \`--hybrid\` to the signer.`,
                helpLinks: [{ label: 'Hybrid PQ implementation guide', href: '/help/#hybrid-pq' }],
                meta: 'Shipped v1.6.0 - NIST FIPS 204',
            },
            {
                q: 'Where is the threat model?',
                a: `[docs/THREAT_MODEL.md](https://github.com/vouch-protocol/vouch/blob/main/docs/THREAT_MODEL.md). It covers the trust boundaries (LLM context, sidecar, validator quorum, verifier), the attacker model (network adversary, compromised agent, compromised LLM, compromised key holder), and the mitigation each Vouch primitive provides.`,
            },
            {
                q: 'How does Vouch handle non-repudiation?',
                a: `Every action is a cryptographically signed credential whose signature can be verified by any third party with access to the agent's DID Document. The credential is human-readable JSON, so an auditor can inspect it directly without specialized tooling. Delegation chains preserve the audit trail from the human principal down to the executing agent.

If a dispute arises, the credential and its proof can be presented as evidence; the signature is independently verifiable without needing the issuer to cooperate.`,
            },
            {
                q: 'Is there a defensive disclosure portfolio?',
                a: `Yes. 55 Prior Art Disclosures (PADs) published under CC0 1.0 Universal at [docs/disclosures/](https://github.com/vouch-protocol/vouch/tree/main/docs/disclosures). Each PAD documents an architectural pattern, threat model, or cryptographic primitive used in or adjacent to Vouch. The portfolio exists to establish prior art and prevent broad patents on Vouch's design decisions.`,
            },
        ],
    },

    // =====================================================================
    // FOR STANDARDS REVIEWERS
    // =====================================================================
    {
        id: 'standards',
        audience: 'Standards & Interoperability',
        title: 'How Vouch fits with W3C, IETF, and C2PA',
        items: [
            {
                q: 'What standards does Vouch build on?',
                a: `Vouch sits on top of well-known W3C and IETF standards rather than inventing new cryptography:

- **W3C Verifiable Credentials 2.0** — the JSON shape of a Vouch credential
- **W3C Data Integrity** — how the cryptographic signature is attached
- **W3C Decentralized Identifiers (DIDs)** — how agents identify themselves
- **W3C Controlled Identifiers / Multikey** — how public keys are encoded
- **W3C BitstringStatusList** — how individual credentials get revoked
- **RFC 8785 (JCS)** — the rule for serializing JSON the same way every time
- **NIST FIPS 204 (ML-DSA)** — the post-quantum signature algorithm
- **C2PA** — Vouch acts as the identity layer for media provenance

The full mapping is documented in Appendix A of the [specification](https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md).`,
            },
            {
                q: 'Does Vouch work with MCP, LangChain, CrewAI, etc.?',
                a: `Yes. Vouch is framework-agnostic. A Vouch credential is just signed JSON, so any framework that can pass a JSON blob alongside a tool call can carry it. We ship ready-made integrations for LangChain, CrewAI, AutoGPT, AutoGen, Google Vertex AI, Google ADK, n8n, Hasura, Streamlit, and the Model Context Protocol (MCP). Drop-in for the major frameworks; small adapter for anything else.`,
            },
            {
                q: 'Does Vouch work alongside C2PA for media provenance?',
                a: `Yes, and intentionally so. C2PA is the right standard for "where did this photo/video/audio come from." Vouch is the right layer for "which AI agent signed it, with whose permission." The repo ships a small Certificate Authority that issues Vouch-rooted C2PA certificates so the two stitch together cleanly. The editor is a member of C2PA and the Content Authenticity Initiative.`,
            },
            {
                q: 'Where is this in the standards pipeline?',
                a: `Vouch is a W3C Community Group Report being incubated in the [Credentials Community Group](https://www.w3.org/community/credentials/). The goal is to gather feedback from teams actually building agents, then propose it for the formal standards track via the W3C Verifiable Credentials Working Group and the Data Integrity Working Group.

If you want to follow along or contribute, the [public-credentials mailing list](https://lists.w3.org/Archives/Public/public-credentials/) is the right venue.`,
            },
            {
                q: 'Are test vectors published for interop?',
                a: `Yes. [Cross-language test vectors](https://github.com/vouch-protocol/vouch/tree/main/test-vectors) cover the hybrid post-quantum profile and W3C BitstringStatusList. Each vector includes a deterministic generator script so you can reproduce and audit it. Python, TypeScript, and Go all verify the same vectors byte-identically.`,
            },
        ],
    },

    // =====================================================================
    // POST-QUANTUM / HYBRID
    // =====================================================================
    {
        id: 'post-quantum',
        audience: 'Post-Quantum Security',
        title: 'Why hybrid signatures, and how they work',
        items: [
            {
                q: 'Why does Vouch care about post-quantum?',
                a: `Eventually, a sufficiently powerful quantum computer will be able to break today's elliptic-curve signatures (Ed25519 included). We don't know when, but governments are already publishing migration deadlines (NIST CNSA 2.0, U.S. NSM-10). Even more importantly, an attacker can harvest signed credentials now and decrypt them later. So even before quantum computers exist, the smart move is to start signing things with both an old and a new algorithm so old signatures stay valid forever.`,
            },
            {
                q: 'How does the hybrid signature work?',
                a: `Each credential is signed twice: once with Ed25519 (today's algorithm, fast) and once with ML-DSA-44 (the NIST-approved post-quantum algorithm). Both signatures cover the exact same JSON bytes, and they ride together inside the credential.

A verifier can choose what to check:

- **Old verifier?** Just check the Ed25519 part. Works today.
- **Forward-looking verifier?** Check the ML-DSA-44 part.
- **Belt-and-suspenders verifier?** Check both, fail if either is wrong.

This means you can issue hybrid-signed credentials right now, and they remain valid whether your verifier is upgraded yet or not. No flag day, no mass migration.`,
            },
            {
                q: 'Is post-quantum signing slower?',
                a: `Yes, but barely. On a modern laptop, signing with Ed25519 takes about 50 microseconds; the hybrid path adds the ML-DSA-44 signature for a total around 3 milliseconds. Verification is similar. The bigger trade-off is size: a classical credential is ~700 bytes; a hybrid one is ~3.2 KB. You'll want to send credentials in HTTP bodies rather than headers.`,
            },
            {
                q: 'How do I turn on the hybrid profile?',
                a: `In Python, install the post-quantum extra and call the hybrid signer:

\`\`\`bash
pip install 'vouch-protocol[pq]'
\`\`\`

\`\`\`python
signer = Signer.from_did_with_hybrid("did:web:agent.example.com")
signed = signer.sign_credential_hybrid(credential)
\`\`\`

TypeScript and Go work the same way. There's a full how-to in the [Guides](/help/#hybrid-pq) with code in all three languages.`,
                helpLinks: [{ label: 'Hybrid PQ how-to', href: '/help/#hybrid-pq' }],
            },
            {
                q: 'Which post-quantum algorithm does Vouch use?',
                a: `ML-DSA-44, the smallest parameter set of NIST FIPS 204 (the standard published in 2024). It gives roughly the same security level as Ed25519 but against quantum attacks. Larger ML-DSA parameter sets (ML-DSA-65, ML-DSA-87) aren't wired in yet but the format leaves room for them.`,
            },
        ],
    },

    // =====================================================================
    // VOUCH SHIELD
    // =====================================================================
    {
        id: 'shield',
        audience: 'Vouch Shield',
        title: 'Permission checks on every tool call',
        items: [
            {
                q: 'What is Vouch Shield?',
                a: `Vouch Shield is a small TypeScript library that sits between your AI agent and the tools it tries to call. Before any tool runs, Shield checks: is this call signed? Is the signer on my trust list? Does this DID have permission to call this specific tool? If anything is off, the call is blocked and logged. If everything checks out, the call runs.

\`npm install @vouch-protocol/shield\`. Source: [vouch-protocol/vouch-shield](https://github.com/vouch-protocol/vouch-shield).`,
                helpLinks: [{ label: 'Vouch Shield setup', href: '/help/#vouch-shield' }],
            },
            {
                q: 'How is Vouch Shield different from the Vouch Protocol itself?',
                a: `Think of Vouch Protocol as the passport: it defines how an agent proves who it is and what it intends to do. Vouch Shield is the customs officer: it inspects passports at the door and decides who gets through.

You can use Vouch Protocol without Shield (just sign and verify credentials in your own code). Shield is a convenience layer for teams who want the gatekeeping done for them.`,
            },
            {
                q: 'Where does Shield fit in my agent stack?',
                a: `Right before any tool actually executes. If your agent uses LangChain, CrewAI, AutoGen, MCP, or anything similar, Shield slots between "the LLM decided to call tool X" and "tool X actually runs." If the call doesn't pass Shield's checks, the tool never fires.`,
            },
        ],
    },

    // =====================================================================
    // TROUBLESHOOTING
    // =====================================================================
    {
        id: 'troubleshooting',
        audience: 'Troubleshooting',
        title: 'When things go wrong',
        items: [
            {
                q: 'My verifier rejects a credential signed in a different language. What is wrong?',
                a: `Most likely cause: the JCS canonicalization is not byte-identical. Check:

1. Are both ends on the same VC \`@context\` version? Mixing VC 1.1 and VC 2.0 contexts changes the canonical bytes.
2. Are timestamps in the canonical RFC 3339 form? Some implementations append \`+00:00\` instead of \`Z\` for UTC.
3. Are numbers serialized as JCS specifies? Trailing zeros, scientific notation, or non-canonical fractions break JCS.

Run the credential through the JCS reference test vectors at [test-vectors/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors) to isolate the issue.`,
            },
            {
                q: 'My hybrid PQ signature is rejected by a verifier that accepts ed25519. What is wrong?',
                a: `Verifier mode mismatch. The hybrid \`proofValue\` is a concatenation of ed25519 + ML-DSA-44 signatures. A classical-only verifier needs to know to take the first 64 bytes (the ed25519 part); a naive verifier might try to validate the whole concatenated blob as ed25519 and fail. Make sure your verifier supports the hybrid cryptosuite (\`hybrid-eddsa-mldsa44-jcs-2026\`) or strip the credential to the classical proof before sending.`,
                meta: 'CG Report §13.2',
            },
            {
                q: 'pip install vouch-protocol[pq] fails. What do I do?',
                a: `The \`pqcrypto\` dependency (\`pip install pqcrypto\` separately) requires a C compiler and the liboqs headers on some platforms. On macOS with Homebrew: \`brew install liboqs\` then retry. On Ubuntu: \`apt install build-essential libssl-dev\` then retry. If you only need verification and not signing of hybrid credentials, you can skip the \`[pq]\` extra; verification can be done with a pure-Python ML-DSA-44 implementation in a follow-up version.`,
            },
            {
                q: 'The Go sidecar refuses to start. What should I check?',
                a: `1. Is port 8877 (or your configured port) free? \`netstat -an | grep 8877\`
2. Is your DID resolvable? \`curl https://agent.example.com/.well-known/did.json\` should return your DID Document.
3. Is your private key correctly placed (env var, KMS config, or file)?

Run with \`--verbose\` for detailed startup logs.`,
            },
            {
                q: 'My credential has the right signature but verification still fails. Why?',
                a: `Common causes:

1. **DID resolution failed** - the verifier could not fetch the DID Document. Check network, TLS, and the \`.well-known/did.json\` URL.
2. **Key not in DID Document** - the signing key's verification-method ID is not in the DID Document's \`verificationMethod\` array.
3. **Credential expired** - \`validUntil\` is in the past.
4. **Nonce already seen** - the nonce store has a record of this credential's nonce.
5. **Revoked at the DID level** - the issuing DID is in the revocation registry.
6. **Revoked at the credential level** - the credential's \`credentialStatus\` bit is set in the fetched BitstringStatusListCredential.

The verifier returns structured reasons, not just "invalid"; check the error code.`,
            },
            {
                q: 'My verifier sees a credential as valid after I revoked it. What is going on?',
                a: `Almost always cache TTL. The \`StatusListFetcher\` caches the status list credential by URL for 5 minutes by default. A revocation made at the issuer becomes visible to verifiers only after the cache expires (or sooner if the verifier sets \`force_refresh=True\`).

Two operational adjustments:

1. **Shorten the TTL** if your latency-to-revocation requirement is tighter than 5 minutes (\`StatusListFetcher(cache_ttl_seconds=60)\`).
2. **Set \`force_refresh=True\` on verification failure** so a credential that suddenly fails for any reason triggers a fresh fetch of its status list. This is the recommended way to handle stale caches.

For coordinated revocations across a verifier fleet, share the cache (Redis) so an invalidation in one verifier becomes visible to all of them immediately.`,
                meta: 'CG Report §11.2',
            },
            {
                q: 'How do I report a security issue?',
                a: `Privately via the process documented in [SECURITY.md](https://github.com/vouch-protocol/vouch/blob/main/SECURITY.md). Do not open public GitHub issues for vulnerabilities.`,
            },
            {
                q: 'Where can I ask questions?',
                a: `Three channels:

- [W3C CCG mailing list](https://lists.w3.org/Archives/Public/public-credentials/) for specification-level questions
- [GitHub issues](https://github.com/vouch-protocol/vouch/issues) for implementation bugs
- [Discord](https://discord.gg/mMqx5cG9Y) for community discussion and quick questions`,
            },
        ],
    },
];
