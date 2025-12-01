import os

# Safe code block construction
TICK = "`" * 3

# We use r""" (Raw String) so backslashes don't break the art
ascii_art = r"""
__      __  ____   _    _    _____   _    _ 
\ \    / / / __ \ | |  | |  / ____| | |  | |
 \ \  / / | |  | || |  | | | |      | |__| |
  \ \/ /  | |__| || |__| | | |____  |  __  |
   \__/    \____/  \____/   \_____| |_|  |_|
"""

readme_content = f"""# VOUCH PROTOCOL

{TICK}text
{ascii_art}
{TICK}

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
{TICK}bash
pip install -r requirements.txt
{TICK}

### 2. The Standard (`vouch.json`)
Host this file at `https://your-domain.com/.well-known/vouch.json`.

{TICK}json
{{
  "id": "did:web:finance-bot.example.com",
  "verificationMethod": [{{
      "type": "JsonWebKey2020",
      "publicKeyJwk": {{ "kty": "OKP", "crv": "Ed25519", "x": "..." }}
  }}]
}}
{TICK}

### 3. Usage (Python SDK)

**For Gatekeepers (Verifying an incoming agent):**

{TICK}python
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
    
    return {{
        "status": "Welcome", 
        "agent": agent_id,
        "trust_score": score
    }}
{TICK}

---

## 4. Architecture & Roadmap

* **Phase 1 (Current):** Client-side Python SDK (MIT License) to drive adoption among agent builders (LangChain, AutoGen).
* **Phase 2:** Server-side Gatekeeper Middleware (Nginx/Cloudflare) to enforce verification.
* **Phase 3:** The Vouch Registry (Federated Reputation History).

## 🤝 Contributing
We are looking for adapters for LangChain and CrewAI.

Run the Red Team security suite locally:
{TICK}bash
python tests/red_team.py
{TICK}

**License:** MIT
"""

with open("README.md", "w") as f:
    f.write(readme_content)

print("✅ Manifesto updated successfully! ASCII Art is clean.")
