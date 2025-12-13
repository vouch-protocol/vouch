# Vouch Protocol

[![Discord](https://img.shields.io/discord/123456789?label=discord&style=for-the-badge&color=5865F2)](https://discord.gg/RXuKJDfC)
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

## �� Integrations

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

### 2. LangChain & CrewAI
Vouch works as a native Tool for most agent frameworks.

    from vouch.integrations.crewai.tool import VouchSignerTool

    agent = Agent(
        role='Analyst', 
        tools=[VouchSignerTool()]
    )

---

## 📜 License & Legal

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
[View Full License](https://github.com/vouch-protocol/vouch/blob/main/LICENSE)

## 🛡️ Defensive Disclosure
This protocol includes a defensive disclosure (Prior Art) published Dec 14, 2025, to protect the ecosystem from patent trolls.
[Read Disclosure](https://github.com/vouch-protocol/vouch/blob/main/README.md#%EF%B8%8F-defensive-disclosure-prior-art)
