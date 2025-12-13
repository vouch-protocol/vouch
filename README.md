# VOUCH PROTOCOL

[![Discord](https://img.shields.io/discord/123456789?label=discord&style=for-the-badge&color=5865F2)](https://discord.gg/RXuKJDfC)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

```text

__      __  ____   _    _    _____   _    _ 
\ \    / / / __ \ | |  | |  / ____| | |  | |
 \ \  / / | |  | || |  | | | |      | |__| |
  \ \/ /  | |__| || |__| | | |____  |  __  |
   \__/    \____/  \____/   \_____| |_|  |_|

```

![Status](https://img.shields.io/badge/Status-Alpha-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Standard](https://img.shields.io/badge/DID-Web-orange) ![Build](https://img.shields.io/github/actions/workflow/status/rampyg/vouch-protocol/tests.yml)

> ⚠️ **v0.1 Alpha Notice:** This is an experimental protocol designed to spark discussion around AI Identity. It is **not yet audited** for production use. Contributions and security critiques are highly welcome.

> **"The 'Green Lock' for the Agentic Web."**

**Vouch** is the open-source standard for **AI Agent Identity, Reputation, & Liability**. It provides the missing cryptographic handshake to allow autonomous agents to prove their intent and accountability.

---

## 1. The Premise
The web was built for humans using browsers. The new web is being browsed by AI Agents. Currently, these agents are treated as second-class citizens—blocked by firewalls because they cannot prove their intent.

* **Existing ID:** Relies on User Identity ("Who are you?").
* **Agent ID:** Requires Intent Identity ("What are you doing, and who is accountable?").

**Vouch is the protocol that allows an AI Agent to prove its legitimacy to a server without human intervention.**

---

## 2. The Philosophy
1.  **Identity must be machine-readable:** Verification must happen in milliseconds via HTTP headers, not CAPTCHAs.
2.  **Reputation is the new Firewall:** We move from "Block all bots" to "Trust verified agents."
3.  **Liability is the Anchor:** An agent must carry a cryptographic signature that links its actions back to a legal entity.

---

## 3. The Technical Standard
Vouch binds a **Reputation Key** to an **Agent Instance** via the `did:web` standard.

| Component | Description |
| :--- | :--- |
| **The Passport** | A `vouch.json` file hosted on the agent's domain containing public keys. |
| **The Handshake** | A cryptographic proof sent via the `Vouch-Token` header. |
| **The Score** | A dynamic Reputation Score signed by the issuer. |

---

## ⚡ Quick Start

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. The Standard (`vouch.json`)
Host this file at `https://your-domain.com/.well-known/vouch.json`.

```json
{
  "id": "did:web:finance-bot.example.com",
  "verificationMethod": [{
      "type": "JsonWebKey2020",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
  }]
}
```

### 3. Usage (Python SDK)

**For Gatekeepers (Verifying an incoming agent):**

```python
from fastapi import FastAPI, Header, HTTPException
from vouch import Verifier

app = FastAPI()
verifier = Verifier(trusted_key_json)

@app.post("/api/resource")
def protected_route(vouch_token: str = Header(alias="Vouch-Token")):
    # 1. Verify the Cryptographic Signature
    is_valid, passport = verifier.check_vouch(vouch_token)
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Untrusted Agent")
        
    # 2. Check Reputation & Liability
    agent_id = passport['sub']
    score = passport['vc'].get('reputation_score', 0)
    
    return {
        "status": "Welcome", 
        "agent": agent_id,
        "trust_score": score
    }
```

---

## 4. Architecture & Roadmap

* **Phase 1 (Current):** Client-side Python SDK (MIT License) to drive adoption among agent builders (LangChain, AutoGen).
* **Phase 2:** Server-side Gatekeeper Middleware (Nginx/Cloudflare) to enforce verification.
* **Phase 3:** The Vouch Registry (Federated Reputation History).

## 🤝 Contributing
We are looking for adapters for LangChain and CrewAI.

Run the Red Team security suite locally:
```bash
python tests/red_team.py
```

**License:** MIT

## 📜 License
This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
* **Open Source:** Free to use, modify, and distribute.
* **Network Use:** If you run Vouch as a service (SaaS), you must share your modifications.
* **Commercial:** Contact us for commercial licensing options.

## 🔌 Integrations

### 1. Model Context Protocol (MCP) for Claude & Cursor
Vouch includes a native MCP server. This allows AI Assistants (like Claude Desktop) to cryptographically sign sensitive actions before executing them.

**Configuration for `claude_desktop_config.json`:**

    {
      "mcpServers": {
        "vouch": {
          "command": "python3",
          "args": ["-m", "vouch.integrations.mcp.server"],
          "env": {
            "VOUCH_PRIVATE_KEY": "YOUR_PRIVATE_KEY",
            "VOUCH_DID": "did:web:your-domain.com"
          }
        }
      }
    }

### 2. LangChain Adapter

    from vouch.integrations.langchain.tool import VouchSignerTool
    tools = [VouchSignerTool()]

### 3. AutoGPT Command
Vouch automatically registers the `sign_with_vouch` command when installed in the AutoGPT plugins folder.

## 🛡️ Defensive Disclosure (Prior Art)
**Publication Date:** December 14, 2025
**Subject:** Cryptographic Binding of AI Agent Intent via Model Context Protocol (MCP)

To ensure the freedom of the ecosystem to build secure agents, we explicitly disclose the following novel method as Prior Art:

**1. The "Identity Sidecar" Pattern**
This protocol describes a method where an MCP Server acts as a local "Identity Proxy" for a stateless Large Language Model (LLM). Unlike traditional architectures where keys are embedded in the application code, this method isolates the cryptographic keys within the MCP interface layer.

**2. Just-in-Time (JIT) Intent Signing**
The system implements a workflow where the LLM must request a "Vouch-Token" for a specific action *before* execution. The MCP server acts as an Auditor, reviewing the `integrity_hash` of the proposed tool call. If valid, it signs the intent with a `did:web` identity.

**3. Non-Repudiation of Tool Execution**
This generates a cryptographically verifiable audit trail that binds three distinct entities:
1. The **Identity** (The DID holding the key).
2. The **Intent** (The specific function call and parameters).
3. The **Time** (Nonce-protected timestamp).

This disclosure is intended to prevent the patenting of "Identity-Aware Tool Execution" mechanisms by third parties.
