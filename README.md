# Vouch Protocol™

<p align="center">
 <img src="docs/assets/vouch-wordmark.png" alt="Vouch Protocol" width="400">
</p>

<sub><em>Vouch Protocol™ — common-law trademark.</em></sub>

<p align="center">The Open Standard for Identity & Provenance of AI Agents</strong>
</p>

<p align="center">
 <a href="https://c2pa.org"><img src="https://img.shields.io/badge/C2PA-Member-0891b2?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyek0xMCAMTdsLTUtNSAxLjQxLTEuNDFMMTAgMTQuMTdsNy41OS03LjU5TDE5IDhsLTkgOXoiLz48L3N2Zz4=" alt="C2PA Member"></a>
 <a href="https://contentauthenticity.org"><img src="https://img.shields.io/badge/CAI-Member-f97316?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAxTDMgNXY2YzAgNS41NSAzLjg0IDEwLjc0IDkgMTIgNS4xNi0xLjI2IDktNi40NSA5LTEyVjVsLTktNHptMCAyLjE4bDcgMy4xMnY1LjdjMCA0LjgzLTMuMjMgOS4zNi03IDEwLjU4VjMuMTh6Ii8+PC9zdmc+" alt="CAI Member"></a>
 <a href="https://identity.foundation"><img src="https://img.shields.io/badge/DIF-Member-6F2DA8?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0tMiAxNWwtNS01IDEuNDEtMS40MUwxMCAxNC4xN2w3LjU5LTcuNTlMMTkgOGwtOSA5eiIvPjwvc3ZnPg==" alt="DIF Member"></a>
 <a href="https://lfaidata.foundation"><img src="https://img.shields.io/badge/Linux_Foundation-Member-333333?style=for-the-badge&logo=linux-foundation&logoColor=white" alt="Linux Foundation Member"></a>
</p>

<p align="center">
 <a href="https://github.com/vouch-protocol/vouch"><img src="https://img.shields.io/badge/Protected_by-Vouch_Protocol-00C853?style=flat&labelColor=333&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0Ij48cGF0aCBmaWxsPSIjMDBDODUzIiBkPSJNMTIgMjBMMiA0aDRsNiAxMC41TDE4IDRoNEwxMiAyMHoiLz48L3N2Zz4=" alt="Protected by Vouch"></a>
 <a href="https://www.bestpractices.dev/projects/11688"><img src="https://www.bestpractices.dev/projects/11688/badge" alt="OpenSSF Silver"></a>
 <a href="https://codecov.io/gh/vouch-protocol/vouch"><img src="https://codecov.io/gh/vouch-protocol/vouch/branch/main/graph/badge.svg" alt="Code Coverage"></a>
 <a href="https://discord.gg/mMqx5cG9Y"><img src="https://img.shields.io/badge/Discord-Join_Community-7289da?logo=discord&logoColor=white" alt="Discord"></a>
</p>

<p align="center">
 <a href="https://codespaces.new/vouch-protocol/vouch"><img src="https://github.com/codespaces/badge.svg" alt="Open in GitHub Codespaces" height="28"></a>
</p>

<p align="center">
 <a href="https://github.com/vouch-protocol/vouch/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="Apache 2.0 License"></a>
</p>

---

## Quick Start

```bash
# Install (Linux and macOS). On Windows, use: pip install vouch-protocol
curl -fsSL https://vouch-protocol.com/install.sh | sh

# Run vouch with no arguments and pick what you want to do
vouch
```

Prefer to do it by hand? It is three commands:

```bash
pip install vouch-protocol

# One command to configure SSH signing + Vouch branding
vouch git init

# All future commits are now signed and show ✅ Verified on GitHub
git commit -m "Secure commit"
```

Setting up an agent instead of git signing? `vouch onboard --quick` generates a working identity, allow-list, verifier, and heartbeat config in one command.

---

## What's New in v1.0

Vouch Protocol v1.0 aligns directly with the open standard:

- **Verifiable Credentials** as the credential format (replacing v0.x JWS tokens).
- **Data Integrity proofs** with the `eddsa-jcs-2022` cryptosuite (no JOSE, no Base64-wrapped payload, the credential remains human-readable JSON).
- **Multikey verification methods** in DID Documents (algorithm-agnostic, ML-DSA-44 ready).
- **Hybrid post-quantum profile** (`hybrid-eddsa-mldsa44-jcs-2026`) as an optional add-on for regulated deployments aligning with NIST CNSA 2.0 / NSM-10 timelines.
- **Three-way cross-implementation interop** verified across Python, TypeScript, and Go.

The legacy v0.x JWS API (`Signer.sign()`, `Verifier.verify()`) continues to work unchanged for a deprecation window. New code should prefer `Signer.sign_credential()` and `Verifier.verify_credential()`. See the Specification at [vouch-protocol.com/specs/SPEC/](https://vouch-protocol.com/specs/SPEC/) for the full specification.

---

> **The Open Standard for AI Agent Identity & Accountability**
> 
> When Anthropic launched MCP, they solved "how agents call tools." 
> They didn't solve "how we TRUST those agents."
> 
> **Vouch Protocol is the SSL certificate for AI agents.**

Vouch is not one tool, it is a set of them. Here is the whole map.

### On the command line
- **`vouch init`** generate an agent identity (a DID and keypair).
- **`vouch sign` / `vouch verify`** sign a payload and verify it.
- **`vouch git`** sign every git commit cryptographically, set up in one command, with a verified badge for your README.
- **`vouch scan`** find leaked Vouch key material in your code before it ships (a private key in a file, a seed in an env var, a DID document that accidentally carries a private key).
- **`vouch attribute`** separate who wrote which line. When an AI assistant and a human both edit a file, this records the AI's lines under the AI's own key and your lines under yours, so when a line causes an incident you can prove which of you wrote it. See [the Claude Code integration](vouch/integrations/claude-code/README.md).
- **`vouch media`** sign images, with C2PA support.

### For your agents
- **MCP server (`vouch-mcp`)** a standalone Model Context Protocol server so any MCP client (Claude Desktop, Cursor, any agent) can create an identity, sign and verify credentials, scan for leaked keys, and decode DIDs, out of the box.
- **Identity Sidecar** keeps signing keys out of the model's context, so a prompt injection cannot read them.
- **Vouch Shield** a runtime check that inspects every tool call against your rules, like a customs officer at the door.
- **Continuous trust** heartbeats and session vouchers, so trust is a live signal that has to be renewed, not a badge that is issued once and trusted forever.

### Framework integrations (new in v1.6.2)
Standalone packages that drop Vouch into the agent framework you already use. Each one issues a verifiable credential for a tool call, with optional delegation back to a human principal.
- **`vouch-langchain`** a LangChain tool that signs each tool call before it leaves the agent.
- **`vouch-crewai`** a CrewAI tool, with supervisor-to-worker delegation that can only narrow authority, never widen it.
- **`vouch-a2a`** binds an A2A (Agent2Agent) Agent Card to a Vouch identity, so two agents can verify each other before they collaborate.
- **`vouch-mlflow`** signs an MLflow model artifact at registration time, bound to a content digest so any change to the weights breaks the signature.
- **`vouch-safetensors`** embeds a credential in a `.safetensors` header, complementary to OpenSSF Model Signing, so a model carries who produced it.

The standalone **`vouch-mcp`** package above ships alongside these in v1.6.2.

### SDKs, in the language you use
Python, TypeScript, and Go are the full reference implementations. A Rust core with idiomatic Swift, JVM (Java and Kotlin), .NET, and C wrappers shares one codebase, so every language produces byte-identical output, verified against shared test vectors. A WebAssembly build is included for the browser and the edge. See the table further down for status per language.

### Robots and embodied agents
A robot is an agent with a body, so identity and accountability matter even more once it can cause physical harm. The `vouch.robotics` module ships six capabilities on the same `eddsa-jcs-2022` credentials as the rest of Vouch: hardware-rooted identity (bound to a TPM or secure element, so it cannot be cloned to other hardware), model and config provenance (re-signable on every OTA update), physical capability scope (force, speed, a tighter cap near humans, allowed zones, and shift windows, checked before each actuation, with narrow-only delegation), a robot-to-robot trust handshake, an encrypted tamper-evident black box with a verifiable kill switch, and a scannable offline passport. All six are implemented in Python, TypeScript, Go, and the Rust core, which flows to the Swift, Kotlin/JVM, .NET, C/C++, and WebAssembly wrappers, so a robotics credential signed in one language verifies in every other. Ten further capabilities round out the set: a living-trust heartbeat (a signed per-interval motion summary whose trust decays unless it is renewed in-envelope), two-level credential revocation (per-credential status lists and whole-DID kill), an accountable safety record (a tamper-evident incident ledger summarized into a portable signed record), signed perception provenance (each captured sensor frame's hash bound to the robot's key and hash-linked, so a robot can prove what its sensors saw and a substituted frame is detectable), an offline delegation lease (a short-lived, scope-bounded grant a disconnected robot verifies and acts on with no network call, nesting across vendors), a physical quorum (a cryptographic two-person rule requiring M of N attested approvers for a high-consequence action), lifecycle credentials (ownership transfer that chains into a verifiable chain of custody, key rotation that forms a key history, and a signed decommission that retires the robot), a regulatory conformance profile (a machine-checkable mapping from a robot's credentials to the clauses of ISO 10218 and 15066, the EU Machinery Regulation, the EU AI Act, and UL 3300, with a deterministic checker and a signed conformance attestation), post-quantum signing by default (robot credentials sign with the hybrid classical-plus-ML-DSA-44 cryptosuite, with backward-compatible verification, so a robot stays unforgeable across its decade-long life), and cross-embodiment identity continuity (an agent identity that moves between robot bodies, with an embodiment credential re-binding to each body's hardware root and a continuity chain that proves the same accountable agent persisted, plus a fork check), implemented across the same languages and pinned by the shared interop vector. See [docs/robotics.md](docs/robotics.md) and the defensive disclosures PAD-064 through PAD-070 and PAD-076 through PAD-082.

### Inside your AI tools
- **Claude Skill**, **OpenAI Custom GPT**, and **Gemini Gem** packages that teach your AI assistant how to add Vouch to your code, running on your own AI subscription.

### Media and the web
- **C2PA Content Credentials** for images.
- **Vouch Sonic** an audio watermark that carries provenance through sound.
- **Browser extension** for Chrome and Edge that signs and verifies content on the page.

### For your repositories
- **Gatekeeper GitHub App** verifies commit signatures on every pull request and blocks leaked Vouch keys before they merge.

### For the ecosystem
- **Agent Trust Index** an open benchmark that scans agents in the wild and measures how many can actually prove who they are. (Spoiler: today, almost none.)

[Read the spec →](https://github.com/vouch-protocol/vouch/blob/main/docs/vouch_guide.md) | [Join Discord →](https://discord.gg/mMqx5cG9Y)

---

## The Problem

AI agents are making real-world API calls with **ZERO cryptographic proof** of:
- **WHO** they are
- **WHAT** they intended to do 
- **WHEN** they did it

**Examples of the risk:**
- Healthcare AI accesses patient data → HIPAA violation risk
- Financial AI makes unauthorized trades → Liability nightmare
- Customer service AI leaks data → Compliance failure

**Current solutions:**
- **DIY JWT signing** → No agent-specific features, security mistakes easy
- **Nothing** → Most people just YOLO it and hope for the best

---

## The Solution

**Vouch Protocol** provides cryptographic identity for AI agents, modeled after SSL/TLS:

- **Verifiable Credentials** (VC Data Model 2.0)
- **Data Integrity proofs** (`eddsa-jcs-2022` cryptosuite, no JOSE/JWS dependency)
- **Decentralized Identifiers** (`did:web`, `did:key`)
- **Multikey verification methods** (algorithm-agnostic, post-quantum ready)
- **Hybrid post-quantum profile** (optional Ed25519 + ML-DSA-44 composite, `hybrid-eddsa-mldsa44-jcs-2026`)
- **Human-readable JSON** (proof attaches as a sibling object, no Base64-wrapped opaque payload)
- **Framework-agnostic** (works with MCP, LangChain, CrewAI, AutoGPT, AutoGen, Vertex AI)
- **Cross-language interop** (Python, TypeScript, Go, byte-identical canonical form)
- **Backward-compatible** (legacy v0.x JWS API still supported during deprecation window)
- **Open source** (Apache 2.0 license, CC0 prior-art portfolio)

**Think of it as:**
- SSL certificate = Proves website identity
- **Vouch Protocol = Proves AI agent identity**

---

## How It Works

### The Workflow

```mermaid
flowchart LR
  P["👤 Principal<br/>did:web:user.example.com"]
  A["🤖 AI Agent<br/>did:web:agent.example.com<br/>+ Identity Sidecar"]
  C["📄 Vouch Credential<br/>VC + Data Integrity<br/>(eddsa-jcs-2022)"]
  API["🔐 API Endpoint"]
  V{"✅ Verified"}

  P -->|"Delegation VC"| A
  A -->|"sign_credential(intent)"| C
  C -->|"HTTP body<br/>application/vc+vouch"| API
  API -->|"verify_credential()"| V
```

**4 Simple Steps:**
1. **Generate Identity**: Create an Ed25519 keypair and a DID, publish a DID Document with a Multikey verification method.
2. **Sign Action**: Agent's sidecar issues a Verifiable Credential carrying `action`, `target`, and `resource`, secured by an `eddsa-jcs-2022` Data Integrity proof.
3. **Send to API**: Transmit the credential as the HTTP request body with `Content-Type: application/vc+vouch` (or via the legacy `Vouch-Token` header for v0.x compatibility; the prior `application/vouch+credential+json` Content-Type is retained as a transitional alias).
4. **Verify**: API resolves the issuer's DID, validates the Data Integrity proof, checks temporal claims and the resource binding, returns a `CredentialPassport`.

### The Trust Model

```mermaid
flowchart TB
  subgraph IDENTITY["Identity Layer"]
    DID["DID<br/>did:web / did:key"]
    MK["Multikey<br/>algorithm-agnostic key encoding"]
  end
  subgraph FORMAT["Credential Layer"]
    VC["Verifiable Credential<br/>(VC Data Model 2.0)"]
    INTENT["Intent payload<br/>action · target · resource"]
  end
  subgraph CRYPTO["Cryptographic Proof"]
    JCS["JCS canonicalization (RFC 8785)"]
    DEFAULT["eddsa-jcs-2022<br/>(Ed25519, default)"]
    HYBRID["hybrid-eddsa-mldsa44-jcs-2026<br/>(Ed25519 + ML-DSA-44, optional)"]
  end
  IDENTITY --> FORMAT
  FORMAT --> CRYPTO
  JCS --> DEFAULT
  JCS --> HYBRID
```

**Trust = Verifiable Credentials + Data Integrity + Decentralized Identifiers + Multikey, with optional hybrid post-quantum signatures.** The same math that secures SSL/TLS, plus the standardized primitives that secure verifiable credentials elsewhere on the web, applied to AI agents.

---

## Why Vouch Protocol?

### vs. DIY JWT

| Feature | Vouch Protocol | DIY JWT |
|---------|---------------|---------|
| **Agent-specific** | ✅ (designed for agents) | ❌ (generic) |
| **MCP integration** | ✅ (native) | ❌ (manual) |
| **Framework integrations** | ✅ (LangChain, CrewAI, etc.) | ❌ |
| **Audit trail format** | ✅ (VC standardized) | ❌ (custom) |
| **standards-aligned** | ✅ (`eddsa-jcs-2022` Data Integrity) | ❌ |
| **Multikey verification methods** | ✅ (algorithm-agnostic) | ❌ |
| **Hybrid post-quantum signatures** | ✅ (`hybrid-eddsa-mldsa44-jcs-2026`) | ❌ |
| **Cross-implementation interop tests** | ✅ (Python, TypeScript, Go) | ❌ |
| **Security best practices** | ✅ (built-in) | ⚠️ (easy to mess up) |

---

## Quick Start

### 1. Install
```bash
# Linux and macOS: one line
curl -fsSL https://vouch-protocol.com/install.sh | sh

# Or with pip (any platform)
pip install vouch-protocol
```

### 2. Generate Identity
```bash
vouch init --domain your-agent.com
```

### 3. Sign an Action (Agent Side)

**v1.0 path (VC + Data Integrity, recommended):**
```python
from vouch import Signer
import os

signer = Signer(
  private_key=os.environ['VOUCH_PRIVATE_KEY'],
  did=os.environ['VOUCH_DID']
)

credential = signer.sign_credential(intent={
  'action': 'read_database',
  'target': 'users_table',
  'resource': 'https://api.example.com/v1/users',
})
# Send credential as the JSON body of the API request, content-type
# application/vc+vouch  (legacy: application/vouch+credential+json)
```

**Legacy v0.x path (JWS, still supported):**
```python
token = signer.sign({'action': 'read_database', 'target': 'users'})
# Include token in Vouch-Token header
```

### 4. Verify (API Side)

**v1.0 path:**
```python
from fastapi import FastAPI, Request, HTTPException
from vouch import Verifier

app = FastAPI()

@app.post("/api/resource")
async def protected_route(request: Request):
  credential = await request.json()
  public_key = '{"kty":"OKP", ...}' # Resolved from did:web or trusted root

  is_valid, passport = Verifier.verify_credential(credential, public_key=public_key)
  if not is_valid:
    raise HTTPException(status_code=401, detail="Untrusted Agent")

  return {
    "status": "Verified",
    "agent": passport.sub,
    "intent": passport.intent,
  }
```

**Legacy v0.x path:**
```python
from vouch import Verifier

@app.post("/api/legacy")
def legacy_route(vouch_token: str = Header(alias="Vouch-Token")):
  is_valid, passport = Verifier.verify(vouch_token, public_key_jwk=public_key)
  if not is_valid:
    raise HTTPException(status_code=401, detail="Untrusted Agent")
  return {"status": "Verified", "agent": passport.sub}
```

**That's it.** A few lines to sign, a few to verify, on either path.

---

## Integrations

Works with all major AI frameworks out-of-the-box:

- **Model Context Protocol (MCP)**: native integration for Claude Desktop and Cursor
- **LangChain**: sign tool calls automatically
- **CrewAI**: multi-agent identity management
- **AutoGPT**: autonomous agent signing
- **AutoGen**: Microsoft multi-agent framework
- **Google Vertex AI**: sign function calls
- **Google ADK**: native ADK tool integration
- **n8n**: low-code agent workflows

[See all integrations →](https://github.com/vouch-protocol/vouch/tree/main/vouch/integrations)

---

## Enterprise Features

- **Key Rotation**: automatic rotating keys for production
- **Voice AI Signing**: sign audio frames in real-time
- **Cloud KMS**: AWS KMS, GCP Cloud KMS, Azure Key Vault
- **Reputation Scoring**: track agent behavior over time
- **Revocation Registry**: blacklist compromised keys
- **Redis Caching**: production-scale verification
- **Hybrid Post-Quantum Profile**: optional Ed25519 + ML-DSA-44 composite signatures (`hybrid-eddsa-mldsa44-jcs-2026`) for regulated deployments aligning with NIST CNSA 2.0 / NSM-10 migration timelines

### Hybrid Post-Quantum Example

```python
# Optional v1.0 profile, requires `pip install pqcrypto`
credential = signer.sign_credential_hybrid(intent={
  'action': 'submit_clinical_finding',
  'target': 'trial:NCT00000001',
  'resource': 'https://fda-submissions.example.com/api/findings',
})
# Carries both Ed25519 and ML-DSA-44 signatures over the same JCS canonical form.
# Verification REQUIRES both to validate.
```

---

## Use Cases

### Financial Services
```python
# SEC-compliant trade logging
agent.sign({'action': 'execute_trade', 'amount': 10000, 'symbol': 'AAPL'})
```

### Customer Service
```python
# Data access accountability
agent.sign({'action': 'read_customer_data', 'customer_id': 'cust_abc'})
```

### Healthcare AI
```python
# HIPAA-compliant audit trail
agent.sign({'action': 'access_phi', 'patient_id': '12345'})
```

To keep this space free from patent capture, the project publishes **61 defensive prior-art disclosures** under CC0, covering cryptographic identity, media provenance, voice biometrics, AI safety, post-quantum cryptography, AI coding governance, and per-region human-or-AI code authorship. See [docs/disclosures](docs/disclosures/README.md).

---

## Use cases

- **Financial services.** A signed, accountable record of every trade or transfer an agent makes.
- **Healthcare.** An auditable trail for every access to patient data.
- **Customer service.** Proof of which agent touched which customer record, and on whose authority.
- **Agent to agent.** When one organization's agent calls another's, each can verify the other before acting.

[See full examples →](https://github.com/vouch-protocol/vouch/tree/main/examples)

---

## Documentation

- [Quick Start](https://github.com/vouch-protocol/vouch#quick-start)
- [Vouch Specification (v1.6 normative)](https://vouch-protocol.com/specs/)
- [Hybrid Post-Quantum Implementation Guide](https://github.com/vouch-protocol/vouch/blob/main/docs/hybrid-pq-implementation-guide.md)
- [Protocol Specification (developer guide)](https://github.com/vouch-protocol/vouch/blob/main/docs/vouch_guide.md)
- [Integration Guides](https://github.com/vouch-protocol/vouch/tree/main/vouch/integrations)
- [Threat Model and Security Considerations](https://github.com/vouch-protocol/vouch/blob/main/docs/THREAT_MODEL.md)
- [Defensive Prior Art Disclosures (61 PADs, CC0)](https://github.com/vouch-protocol/vouch/tree/main/docs/disclosures)
- [FAQ and Discussions](https://github.com/vouch-protocol/vouch/discussions)

---

## Community

- **Discord** - Ask questions, share use cases → [Join now](https://discord.gg/mMqx5cG9Y)
- **GitHub Discussions** - Technical discussions → [Start a discussion](https://github.com/vouch-protocol/vouch/discussions)
- **Twitter/X** - Updates and announcements → [@Vouch_Protocol](https://x.com/Vouch_Protocol)

---

## Roadmap

### v1.6 (current release)

- [x] **Verifiable Credentials + Data Integrity** (`eddsa-jcs-2022` cryptosuite)
- [x] **Multikey verification methods** (algorithm-agnostic, multibase + multicodec)
- [x] **Hybrid post-quantum profile** (`hybrid-eddsa-mldsa44-jcs-2026`, NIST CNSA 2.0 / NSM-10 aligned)
- [x] **Three-language reference implementation** (Python, TypeScript, Go) with byte-identical canonical form via RFC 8785 JCS, verified against shared test vectors
- [x] **Specification drafted** and submitted to the open standards group for incubation
- [x] **55 Prior Art Disclosures** (CC0 defensive publications)
- [x] Identity Sidecar architecture (LLM-isolated keys)
- [x] Heartbeat Protocol with adaptive Trust Entropy
- [x] Resource-bound delegation chains with capability narrowing
- [x] MCP integration (Claude Desktop, Cursor)
- [x] Framework adapters (LangChain, CrewAI, AutoGPT, AutoGen, Vertex AI, Google ADK, n8n)
- [x] C2PA Content Credentials integration
- [x] Audio watermarking (Vouch Sonic, sub-band steganography)
- [x] DID-linked voice biometric enrollment
- [x] Browser extension (Chrome / Edge content signing)
- [x] GitHub App and Cloudflare Workers verification gateway

### Next (v1.7 and beyond)

- [ ] Independent third-party cryptographic security audit (Trail of Bits / NCC Group / Cure53)
- [ ] Specification stabilization and external review
- [ ] Algorithm Quorum verification (M-of-N cryptosuite diversity, per PAD-046)
- [ ] Verifiable Delay Function rate-limiting for high-stakes agent actions (per PAD-047)
- [ ] Cryptographic Weight Binding for model-intrinsic AI identity (per PAD-043)
- [ ] Ephemeral ZK-State Channels for high-frequency agent-to-agent negotiation (per PAD-044)
- [ ] Retrieval-anchored proof of non-hallucination (per PAD-045)
- [ ] Standardized agent ledger metadata schema (per PAD-042)
- [ ] Edge-first WASM + ONNX client-side processing
- [ ] Hardware key support (YubiKey, TPM, Secure Enclave)
- [ ] Native Rust implementation for edge and embedded deployments

[View full roadmap and issue tracker →](https://github.com/vouch-protocol/vouch/issues)

---

## License

**Apache License 2.0**: See [LICENSE](https://github.com/vouch-protocol/vouch/blob/main/LICENSE)

You can use this freely in commercial and open-source projects.

The 61 defensive prior-art disclosures are released under **CC0 1.0 Universal** to ensure ecosystem freedom from patent capture.

*The Vouch Protocol specification is being developed as a open standard submission via the open standards group. The implementation is also being proposed to the Linux Foundation's AI & Data Foundation.*

---

## Acknowledgments

Inspired by:
- **SSL/TLS** (the gold standard for identity)
- **OAuth 2.0** (federated identity done right)
- **Verifiable Credentials** (the future of digital identity)

Built by [Ramprasad Gaddam](https://www.linkedin.com/in/rampy) ([Twitter/X](https://x.com/rampyg))

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](https://github.com/vouch-protocol/vouch/blob/main/CONTRIBUTING.md). Looking for a place to start? Browse our [good first issues](https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22), and open a ready-made dev environment with one click using the [Open in GitHub Codespaces](https://codespaces.new/vouch-protocol/vouch) badge above.

**Areas where help is most useful:**
- [ ] Additional framework integrations (Haystack, Semantic Kernel, LlamaIndex, others)
- [ ] Cross-implementation interop test vectors (additional edge cases for JCS, VC, hybrid PQ)
- [ ] Tutorials and worked examples for regulated-sector deployments
- [ ] Independent security review and audit
- [ ] Reference implementations in additional languages (Rust, Java, .NET)

## Contributors

Thanks goes to these wonderful people. This section is maintained automatically by the [all-contributors](https://allcontributors.org/) bot.

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
<!-- ALL-CONTRIBUTORS-BADGE:END -->

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

---

**Star this repo if you find it useful.**

[Star on GitHub](https://github.com/vouch-protocol/vouch) | [Join Discord](https://discord.gg/mMqx5cG9Y) | [Follow on X](https://x.com/Vouch_Protocol)

---

## Prior Art Disclosures

To ensure ecosystem freedom, we publish **55 defensive prior art disclosures** (CC0 public domain) covering novel methods across cryptographic identity, media provenance, voice biometrics, AI safety, post-quantum cryptography, AI coding assistant governance, and content authenticity:

| ID | Title | Category |
|----|-------|----------|
| [PAD-001](docs/disclosures/PAD-001-cryptographic-agent-identity.md) | Cryptographic Agent Identity | Identity |
| [PAD-002](docs/disclosures/PAD-002-chain-of-custody.md) | Chain of Custody Delegation | Identity |
| [PAD-003](docs/disclosures/PAD-003-identity-sidecar.md) | Identity Sidecar Pattern | Architecture |
| [PAD-004](docs/disclosures/PAD-004-smart-scan-verification.md) | DOM-Traversing Signature Matching | Verification |
| [PAD-005](docs/disclosures/PAD-005-reverse-lookup-registry.md) | Detached Signature Recovery | Verification |
| [PAD-006](docs/disclosures/PAD-006-trust-graph-url-chaining.md) | URL-Based Credential Chaining | Trust |
| [PAD-007](docs/disclosures/PAD-007-ghost-signature-telemetry.md) | Automated Provenance via Input Telemetry | Provenance |
| [PAD-008](docs/disclosures/PAD-008-hybrid-ssh-verification.md) | Hybrid Identity Bootstrapping | Identity |
| [PAD-009](docs/disclosures/PAD-009-localhost-identity-bridge.md) | Unified Local Identity via Localhost Bridge | Architecture |
| [PAD-010](docs/disclosures/PAD-010-semantic-consent-signing.md) | Context-Adaptive Semantic Consent | Privacy |
| [PAD-011](docs/disclosures/PAD-011-hierarchical-discovery-protocol.md) | Hierarchical Discovery Protocol | Discovery |
| [PAD-012](docs/disclosures/PAD-012-vouch-covenant.md) | Executable Usage Covenants in Media Manifests | Media / Rights |
| [PAD-013](docs/disclosures/PAD-013-vouch-airgap.md) | Air-Gapped Identity via Psychoacoustic Steganography | Audio |
| [PAD-014](docs/disclosures/PAD-014-vouch-sonic.md) | Robust Acoustic Provenance via Steganography | Audio |
| [PAD-015](docs/disclosures/PAD-015-ambient-witness-protocol.md) | Ambient Witness Protocol (BLE Crowdsourcing) | IoT / Provenance |
| [PAD-016](docs/disclosures/PAD-016-dynamic-credential-renewal.md) | Dynamic Credential Renewal ("Heartbeat Protocol") | Identity |
| [PAD-017](docs/disclosures/PAD-017-cryptographic-proof-of-reasoning.md) | Cryptographic Proof of Reasoning | AI Safety |
| [PAD-018](docs/disclosures/PAD-018-model-lineage-provenance.md) | Model Lineage Provenance ("Birth Certificate Protocol") | AI Safety |
| [PAD-019](docs/disclosures/PAD-019-glass-channel-protocol.md) | Transparent Agent Communication | AI Safety |
| [PAD-020](docs/disclosures/PAD-020-ratchet-lock-protocol.md) | Capability Acquisition Containment | AI Safety |
| [PAD-021](docs/disclosures/PAD-021-inverse-capability-protocol.md) | Graduated Autonomy via Inverse Capability Scaling | AI Safety |
| [PAD-022](docs/disclosures/PAD-022-swarm-limits-protocol.md) | Agent Population Governance | AI Safety |
| [PAD-023](docs/disclosures/PAD-023-content-policy-watermarking.md) | Machine-Readable Content Usage Policies in Audio Watermarks | Audio / Rights |
| [PAD-024](docs/disclosures/PAD-024-temporal-video-fingerprinting.md) | Temporal Perceptual Hashing for Video Provenance | Video |
| [PAD-025](docs/disclosures/PAD-025-edge-first-content-provenance.md) | Edge-First Content Provenance via Client-Side WASM | Architecture |
| [PAD-026](docs/disclosures/PAD-026-did-linked-voiceprint-enrollment.md) | DID-Linked Voice Biometric Enrollment | Voice / Biometrics |
| [PAD-027](docs/disclosures/PAD-027-shamir-split-biometric-recovery.md) | Shamir Secret Sharing of Biometric Enrollment Data | Recovery / Biometrics |
| [PAD-028](docs/disclosures/PAD-028-cross-modal-identity-provenance.md) | Unified Cross-Modal Identity-Bound Provenance | Multi-Modal / Identity |
| [PAD-029](docs/disclosures/PAD-029-eldear-scam-protection-identity.md) | Identity-Verified Communication Shield | Elder Safety / Voice |
| [PAD-030](docs/disclosures/PAD-030-zk-reputation-portability.md) | Zero-Knowledge Reputation Portability | Privacy / Trust |
| [PAD-031](docs/disclosures/PAD-031-canary-provenance-honeypots.md) | Adversarial Provenance Honeypots | Adversarial Detection |
| [PAD-032](docs/disclosures/PAD-032-cryptographic-mortality-protocol.md) | Cryptographic Mortality Protocol | Identity Lifecycle |
| [PAD-033](docs/disclosures/PAD-033-zk-pq-signature-compression.md) | ZK Proof Compression for Post-Quantum Signatures | Post-Quantum / ZKP |
| [PAD-034](docs/disclosures/PAD-034-composite-threshold-swarm-consensus.md) | Composite Threshold Aggregation for Swarm Consensus | Post-Quantum / Swarm |
| [PAD-035](docs/disclosures/PAD-035-async-chunked-edge-pq-signatures.md) | Asynchronous Chunked Verification and Edge PQ Signatures | Post-Quantum / Edge |
| [PAD-036](docs/disclosures/PAD-036-aggregated-reputation-scoring.md) | Aggregated Reputation Scoring via Verifiable State Receipts | Trust / Enterprise |
| [PAD-037](docs/disclosures/PAD-037-credential-federation.md) | Cross-Protocol Agent Credential Federation | Identity / Enterprise |
| [PAD-038](docs/disclosures/PAD-038-agent-capability-discovery.md) | Decentralized Agent Capability Discovery | Discovery / Multi-Agent |
| [PAD-039](docs/disclosures/PAD-039-jcs-deterministic-multi-party-trust-state.md) | Cross-Implementation Deterministic Multi-Party Trust State via JCS | Cross-Impl Determinism |
| [PAD-040](docs/disclosures/PAD-040-hybrid-composite-signature-same-canonical-bytes.md) | Hybrid Composite Signature Bound to Same Canonical Bytes (Ed25519 + ML-DSA-44) | Post-Quantum / Hybrid |
| [PAD-041](docs/disclosures/PAD-041-multikey-algorithm-agnostic-verification.md) | Algorithm-Agnostic Verification Method Resolution via Multikey Multicodec | Verification / Multikey |
| [PAD-042](docs/disclosures/PAD-042-standardized-metadata-schema-agent-ledger.md) | Standardized Metadata Schema for AI Agent Ledger Signatures | Metadata / Audit |
| [PAD-043](docs/disclosures/PAD-043-cryptographic-weight-binding.md) | Cryptographic Weight Binding for Model-Intrinsic AI Identity | AI Identity / Model |
| [PAD-044](docs/disclosures/PAD-044-ephemeral-zk-state-channels.md) | Ephemeral ZK-State Channels for Agentic Layer 2 Scalability | Scalability / ZK |
| [PAD-045](docs/disclosures/PAD-045-proof-of-non-hallucination-retrieval-anchoring.md) | Proof of Non-Hallucination via Cryptographic Retrieval Anchoring | AI Safety / RAG |
| [PAD-046](docs/disclosures/PAD-046-algorithm-quorum-cryptosuite-diversity.md) | Algorithm Quorum Verification via M-of-N Cryptosuite Diversity | Defense in Depth |
| [PAD-047](docs/disclosures/PAD-047-vdf-rate-limited-agent-actions.md) | Verifiable Delay Functions for Cryptographic Rate-Limiting | Agent Containment |
| [PAD-048](docs/disclosures/PAD-048-write-only-async-context-ledger.md) | Write-Only Async Context Ledger for LLM Coding Assistants | AI Coding / IP Protection |
| [PAD-049](docs/disclosures/PAD-049-decoupled-semantic-policy-extraction.md) | Decoupled Semantic Policy Extraction via Passive Source Monitoring | AI Coding / IP Protection |
| [PAD-050](docs/disclosures/PAD-050-zero-context-deterministic-egress-interception.md) | Zero-Context Deterministic Egress Interception | AI Coding / Egress Control |
| [PAD-051](docs/disclosures/PAD-051-parallel-intent-extraction-shadow-models.md) | Parallel Intent Extraction via Local Shadow Models | AI Coding / Local-First |
| [PAD-052](docs/disclosures/PAD-052-ui-state-sniffing-closed-box-ai-tools.md) | UI State Sniffing for Closed-Box AI Coding Tools | AI Coding / Compatibility |
| [PAD-053](docs/disclosures/PAD-053-time-bounded-ephemeral-rules.md) | Time-Bounded Ephemeral Rules with Auto-Expiry | AI Coding / Lifetime |
| [PAD-054](docs/disclosures/PAD-054-filesystem-hierarchy-policy-inheritance.md) | Filesystem-Hierarchy Policy Inheritance for AI Coding Workspaces | AI Coding / Composition |
| [PAD-055](docs/disclosures/PAD-055-cross-session-policy-re-anchoring.md) | Cross-Session Policy Re-Anchoring via Pre-Flight Context Replay | AI Coding / Continuity |

[View all disclosures →](docs/disclosures/README.md)
