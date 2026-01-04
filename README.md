# Vouch Protocol

<p align="center">
  <img src="docs/assets/vouch_hero.jpg" alt="Vouch Protocol - The Identity Layer for AI Agents" width="500">
</p>

<p align="center">
  <strong>The Identity Layer for the Agentic Web</strong>
</p>

<p align="center">
  <a href="https://github.com/vouch-protocol/vouch"><img src="https://img.shields.io/badge/Protected_by-Vouch_Protocol-00C853?style=flat&labelColor=333&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0Ij48cGF0aCBmaWxsPSIjMDBDODUzIiBkPSJNMTIgMjBMMiA0aDRsNiAxMC41TDE4IDRoNEwxMiAyMHoiLz48L3N2Zz4=" alt="Protected by Vouch"></a>
  <a href="https://www.bestpractices.dev/projects/11688"><img src="https://www.bestpractices.dev/projects/11688/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://discord.gg/VxgYkjdph"><img src="https://img.shields.io/badge/Discord-Join_Community-7289da?logo=discord&logoColor=white" alt="Discord"></a>
</p>

<p align="center">
  <a href="https://github.com/vouch-protocol/vouch/blob/main/licenses/LICENSE-SPEC"><img src="https://img.shields.io/badge/Spec-Community_License-green.svg" alt="Spec License"></a>
  <a href="https://github.com/vouch-protocol/vouch/blob/main/LICENSE"><img src="https://img.shields.io/badge/Client-Apache_2.0-blue.svg" alt="Client License"></a>
  <a href="https://github.com/vouch-protocol/vouch/blob/main/licenses/LICENSE-SERVER"><img src="https://img.shields.io/badge/Server-AGPL_3.0-orange.svg" alt="Server License"></a>
</p>

---

## ⚡ Quick Start

```bash
pip install vouch-protocol

# One command to configure SSH signing + Vouch branding
vouch git init

# All future commits are now signed and show ✅ Verified on GitHub
git commit -m "Secure commit"
```

---

> **The Open Standard for AI Agent Identity & Accountability**
> 
> When Anthropic launched MCP, they solved "how agents call tools."  
> They didn't solve "how we TRUST those agents."
> 
> **Vouch Protocol is the SSL certificate for AI agents.**

[Read the spec →](https://github.com/vouch-protocol/vouch/blob/main/docs/vouch_guide.md) | [Join Discord →](https://discord.gg/VxgYkjdph)

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

✅ **Ed25519 signatures** (industry-standard cryptography)  
✅ **JWK key format** (works with existing infrastructure)  
✅ **Audit trail** (cryptographic proof of every action)  
✅ **Framework-agnostic** (works with MCP, LangChain, CrewAI, etc.)  
✅ **Open source** (Apache 2.0 license)

**Think of it as:**
- SSL certificate = Proves website identity
- **Vouch Protocol = Proves AI agent identity**

---

## How It Works

### The Workflow

![Vouch Protocol Workflow](docs/images/how-it-works.png)

**4 Simple Steps:**
1. **Generate Identity** - Create keypair and DID
2. **Sign Action** - Agent signs every API call
3. **Send to API** - Include token in HTTP header
4. **Verify** - API checks signature with public key

### The Trust Model

![Trust Model](docs/images/trust-model.png)

**Trust = Public Key Cryptography + JWT + DID**  
The same math that secures SSL/TLS, just for AI agents.

---

## Why Vouch Protocol?

### vs. DIY JWT

| Feature | Vouch Protocol | DIY JWT |
|---------|---------------|---------|
| **Agent-specific** | ✅ (designed for agents) | ❌ (generic) |
| **MCP integration** | ✅ (native) | ❌ (manual) |
| **Framework integrations** | ✅ (LangChain, CrewAI, etc.) | ❌ |
| **Audit trail format** | ✅ (standardized) | ❌ (custom) |
| **Security best practices** | ✅ (built-in) | ⚠️ (easy to mess up) |

---

## Quick Start

### 1. Install
```bash
pip install vouch-protocol
```

### 2. Generate Identity
```bash
vouch init --domain your-agent.com
```

### 3. Sign an Action (Agent Side)
```python
from vouch import Signer
import os

signer = Signer(
    private_key=os.environ['VOUCH_PRIVATE_KEY'],
    did=os.environ['VOUCH_DID']
)

token = signer.sign({'action': 'read_database', 'target': 'users'})
# Include token in Vouch-Token header
```

### 4. Verify (API Side)
```python
from fastapi import FastAPI, Header, HTTPException
from vouch import Verifier

app = FastAPI()

@app.post("/api/resource")
def protected_route(vouch_token: str = Header(alias="Vouch-Token")):
    public_key = '{"kty":"OKP"...}' # From agent's vouch.json
    
    is_valid, passport = Verifier.verify(vouch_token, public_key_jwk=public_key)
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Untrusted Agent")
        
    return {"status": "Verified", "agent": passport.sub}
```

**That's it.** 3 lines to sign, 3 lines to verify.

---

## Integrations

Works with all major AI frameworks out-of-the-box:

- ✅ **Model Context Protocol (MCP)** - Native integration for Claude Desktop & Cursor
- ✅ **LangChain** - Sign tool calls automatically
- ✅ **CrewAI** - Multi-agent identity management
- ✅ **AutoGPT** - Autonomous agent signing
- ✅ **AutoGen** - Microsoft multi-agent framework
- ✅ **Google Vertex AI** - Sign function calls
- ✅ **n8n** - Low-code agent workflows

[See all integrations →](https://github.com/vouch-protocol/vouch/tree/main/vouch/integrations)

---

## Enterprise Features

- 🔐 **Key Rotation** - Automatic rotating keys for production
- 🎙️ **Voice AI Signing** - Sign audio frames in real-time  
- ☁️ **Cloud KMS** - AWS KMS, GCP Cloud KMS, Azure Key Vault
- 📊 **Reputation Scoring** - Track agent behavior over time
- 🚫 **Revocation Registry** - Blacklist compromised keys
- ⚡ **Redis Caching** - Production-scale verification

---

## 🎯 Use Cases

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

[See full examples →](https://github.com/vouch-protocol/vouch/tree/main/examples)

---

## 📚 Documentation

- 🚀 [Quick Start](https://github.com/vouch-protocol/vouch#quick-start)
- 🔧 [Integration Guides](https://github.com/vouch-protocol/vouch/tree/main/vouch/integrations)
- 📖 [Protocol Specification](https://github.com/vouch-protocol/vouch/blob/main/docs/vouch_guide.md)
- 🏢 [Enterprise Features](https://github.com/vouch-protocol/vouch#enterprise-features)
- 🛡️ [Security Best Practices](https://github.com/vouch-protocol/vouch/blob/main/docs/vouch_guide.md)
- ❓ [FAQ](https://github.com/vouch-protocol/vouch/discussions)

---

## 🤝 Community

- **Discord** - Ask questions, share use cases → [Join now](https://discord.gg/VxgYkjdph)
- **GitHub Discussions** - Technical discussions → [Start a discussion](https://github.com/vouch-protocol/vouch/discussions)
- **Twitter/X** - Updates and announcements → [@Vouch_Protocol](https://x.com/Vouch_Protocol)

---

## 🛣️ Roadmap

- [x] Core protocol (Ed25519, JWK, JWT)
- [x] MCP integration
- [x] LangChain, CrewAI, AutoGPT integrations
- [ ] W3C Verifiable Credentials compatibility
- [ ] Multi-signature support
- [ ] Hardware key support (YubiKey, etc.)
- [ ] Browser extension (verify agents in real-time)

[View full roadmap →](https://github.com/vouch-protocol/vouch/issues)

---

## 📜 License

**Apache License 2.0** - See [LICENSE](https://github.com/vouch-protocol/vouch/blob/main/LICENSE) file

**This is NOT AGPL.** You can use this in commercial, closed-source products.

For multi-license details (Client SDK/Server SDK/Specification), see our [3-layer license structure](https://github.com/vouch-protocol/vouch#-license--legal).

---

## 🙏 Acknowledgments

Inspired by:
- **SSL/TLS** (the gold standard for identity)
- **OAuth 2.0** (federated identity done right)
- **W3C Verifiable Credentials** (the future of digital identity)

Built by [Ramprasad Gaddam](https://www.linkedin.com/in/rampy) ([Twitter/X](https://x.com/rampyg))

---

## 🚀 Contributing

We welcome contributions! See [CONTRIBUTING.md](https://github.com/vouch-protocol/vouch/blob/main/CONTRIBUTING.md).

**Areas where we need help:**
- [ ] Add integrations (Haystack, Semantic Kernel, etc.)
- [ ] Improve documentation
- [ ] Write tutorials
- [ ] Build examples
- [ ] Security audits

---

**⭐ Star this repo if you find it useful!**

[Star on GitHub](https://github.com/vouch-protocol/vouch) | [Join Discord](https://discord.gg/VxgYkjdph) | [Follow on Twitter](https://x.com/Vouch_Protocol)

---

## 📜 Prior Art Disclosures

To ensure ecosystem freedom, we publish defensive prior art disclosures for novel methods:

| ID | Title | Key Claims |
|----|-------|------------|
| [PAD-001](docs/disclosures/PAD-001-cryptographic-agent-identity.md) | Cryptographic Agent Identity | Intent-bound tokens, agent DIDs |
| [PAD-002](docs/disclosures/PAD-002-chain-of-custody.md) | Chain of Custody | Recursive delegation, intent chains |
| [PAD-003](docs/disclosures/PAD-003-identity-sidecar.md) | Identity Sidecar Pattern | LLM key isolation, JIT signing |

[View all disclosures →](docs/disclosures/README.md)
