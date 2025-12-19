# Vouch Protocol

[![Discord](https://img.shields.io/badge/Discord-Join_Community-7289da?logo=discord&logoColor=white)](https://discord.gg/RXuKJDfC)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/vouch-protocol/vouch/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/Status-Public_Beta-yellow)](https://github.com/vouch-protocol/vouch)

    __      __  ____   _    _    _____   _    _ 
    \ \    / / / __ \ | |  | |  / ____| | |  | |
     \ \  / / | |  | || |  | | | |      | |__| |
      \ \/ /  | |__| || |__| | | |____  |  __  |
       \__/    \____/  \____/   \_____| |_|  |_|

> **"The 'Green Lock' for the Agentic Web."**

**Vouch** is the open-source standard for **AI Agent Identity, Reputation, & Liability**. It provides the missing cryptographic handshake to allow autonomous agents to prove their intent and accountability.

> **⚠️ Public Beta:** This protocol is v1.0 compliant but the implementation is currently in **Beta**. Please report issues on GitHub.

---

## ⚡ Quick Start

### 1. Installation

    pip install vouch-protocol

### 2. Usage

**For Gatekeepers (Verifying an incoming agent):**

    from fastapi import FastAPI, Header, HTTPException
    from vouch import Verifier

    app = FastAPI()

    @app.post("/api/resource")
    def protected_route(vouch_token: str = Header(alias="Vouch-Token")):
        # Verify the cryptographic intent
        is_valid, passport = Verifier.verify(vouch_token)
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Untrusted Agent")
            
        return {"status": "Verified", "agent": passport.sub}

---

## 🔌 Integrations

### 1. Model Context Protocol (MCP)
Vouch includes a native MCP server for Claude Desktop & Cursor.

**Configuration:**

    {
      "mcpServers": {
        "vouch": {
          "command": "python3",
          "args": ["-m", "vouch.integrations.mcp.server"],
          "env": {
            "VOUCH_PRIVATE_KEY": "YOUR_KEY",
            "VOUCH_DID": "did:web:your-domain.com"
          }
        }
      }
    }

### 2. LangChain Integration
Add cryptographic identity to your LangChain tools.

    from vouch.integrations.langchain.tool import VouchSignerTool
    
    tools = [VouchSignerTool()]

### 3. CrewAI Integration
Works natively with CrewAI agents.

    from vouch.integrations.crewai.tool import VouchSignerTool

    agent = Agent(
        role='Analyst', 
        tools=[VouchSignerTool()]
    )

### 4. AutoGPT Integration
Register the signer command with your agent.

    # In your plugins/vouch folder
    from vouch.integrations.autogpt import register_commands

---


### 7. n8n Integration (Low-Code Agents)
You can use Vouch directly in n8n using the **Python Code Node**.

**Prerequisite:**
Ensure your n8n instance installs the library:
`export EXTERNAL_PYTHON_PACKAGES=vouch-protocol`

**Code Node Snippet:**

    from vouch import Signer
    import os

    # 1. Initialize
    signer = Signer(
        private_key=os.environ.get('VOUCH_PRIVATE_KEY'), 
        did=os.environ.get('VOUCH_DID')
    )

    # 2. Sign the incoming workflow data
    # (Copy full snippet from vouch.integrations.n8n)


## 📜 License & Legal

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
[View Full License](https://github.com/vouch-protocol/vouch/blob/main/LICENSE)

## Defensive Disclosure (Prior Art)
**Publication Date:** December 14, 2025
**Subject:** Cryptographic Binding of AI Agent Intent via Model Context Protocol (MCP)

To ensure the freedom of the ecosystem to build secure agents, we explicitly disclose the following novel method as Prior Art:

1.  **The "Identity Sidecar" Pattern:** An MCP Server acting as a local "Identity Proxy" for a stateless LLM, isolating keys from application code.
2.  **Just-in-Time (JIT) Intent Signing:** A workflow where the LLM requests a signed "Vouch-Token" for a specific action *before* execution.
3.  **Non-Repudiation:** Generating a cryptographically verifiable audit trail binding Identity, Intent, and Time.

### CLI
`vouch init --domain x.com`
`vouch sign 'msg'`
`vouch verify 'tok'`
