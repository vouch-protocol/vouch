# Vouch Protocol

[![Discord](https://img.shields.io/badge/Discord-Join_Community-7289da?logo=discord&logoColor=white)](https://discord.gg/RXuKJDfC)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/vouch-protocol/vouch/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/Status-Public_Beta-yellow)](https://github.com/vouch-protocol/vouch)

    __      __  ____   _    _    _____   _    _ 
    \ \    / / / __ \ | |  | |  / ____| | |  | |
     \ \  / / | |  | || |  | | | |      | |__| |
      \ \/  / | |__| || |__| | | |____  |  __  |
       \__/    \____/  \____/   \_____| |_|  |_|

> **"The 'Green Lock' for the Agentic Web."**

**Vouch** is the open-source standard for **AI Agent Identity, Reputation, & Liability**. It provides the missing cryptographic handshake to allow autonomous agents to prove their intent and accountability.

> **⚠️ Public Beta:** This protocol is v1.0 compliant but the implementation is currently in **Beta**. Please report issues on GitHub.

---

## ⚡ Quick Start

### 1. Installation

    pip install vouch-protocol

### 2. Generate Identity

    # Generate a new keypair
    vouch init --domain your-agent.com
    
    # Export as environment variables
    vouch init --domain your-agent.com --env

### 3. Sign a Payload

    from vouch import Signer
    import os

    signer = Signer(
        private_key=os.environ['VOUCH_PRIVATE_KEY'],
        did=os.environ['VOUCH_DID']
    )

    token = signer.sign({'action': 'read_database', 'target': 'users'})
    # Use token in Vouch-Token header

### 4. Verify a Token (Gatekeepers)

    from fastapi import FastAPI, Header, HTTPException
    from vouch import Verifier

    app = FastAPI()

    @app.post("/api/resource")
    def protected_route(vouch_token: str = Header(alias="Vouch-Token")):
        # Verify with the agent's public key
        public_key = '{"kty":"OKP","crv":"Ed25519","x":"..."}'  # From agent's vouch.json
        
        is_valid, passport = Verifier.verify(vouch_token, public_key_jwk=public_key)
        
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

    from vouch.integrations.autogpt import register_commands

### 5. AutoGen Integration
Use with Microsoft AutoGen agents.

    from vouch.integrations.autogen import sign_action
    
    # Register as a function tool
    assistant.register_function(sign_action)

### 6. Google Vertex AI Integration
Sign function calls in Vertex AI Agent Builder.

    from vouch.integrations.google import VertexAISigner
    
    signer = VertexAISigner()
    token = signer.sign_tool_call('search_database', {'query': 'test'})

### 7. n8n Integration (Low-Code Agents)
You can use Vouch directly in n8n using the **Python Code Node**.

**Prerequisite:**
Ensure your n8n instance installs the library:
`export EXTERNAL_PYTHON_PACKAGES=vouch-protocol`

**Code Node Snippet:**

    from vouch import Signer
    import os

    signer = Signer(
        private_key=os.environ.get('VOUCH_PRIVATE_KEY'), 
        did=os.environ.get('VOUCH_DID')
    )

    # Sign the incoming workflow data
    for item in _input.all():
        item.json['vouch_token'] = signer.sign(item.json)
    
    return _input.all()

---

## 🏢 Enterprise Features

### Key Rotation

    from vouch.kms import RotatingKeyProvider, KeyConfig

    keys = [
        KeyConfig(private_key_jwk='...', did='did:web:agent.com', key_id='key1'),
        KeyConfig(private_key_jwk='...', did='did:web:agent.com', key_id='key2'),
    ]

    provider = RotatingKeyProvider(keys, rotation_interval_hours=24)
    signer = provider.get_signer()  # Automatically uses active key

### Voice AI Signing

    from vouch import Signer
    from vouch.audio import AudioSigner

    signer = Signer(private_key='...', did='did:web:voice-ai.com')
    audio_signer = AudioSigner(signer)

    signed_frame = audio_signer.sign_frame(audio_bytes)
    print(signed_frame.vouch_token)

---

## 🖥️ CLI Reference

    # Generate new identity
    vouch init --domain example.com
    vouch init --domain example.com --env  # Output as env vars

    # Sign a message
    vouch sign "Hello World"
    vouch sign '{"action": "test"}' --json
    vouch sign "message" --header  # Include Vouch-Token prefix

    # Verify a token
    vouch verify <token>
    vouch verify <token> --key '{"kty":"OKP",...}'  # With public key
    vouch verify <token> --json  # Output as JSON

---

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
