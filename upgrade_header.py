import os

# ==========================================
# 1. UPDATE THE SERVER CODE (examples/fastapi_server.py)
# ==========================================
fastapi_code = """from fastapi import FastAPI, Header, HTTPException
from vouch import Verifier

app = FastAPI()
# (Mock key for demo)
verifier = Verifier('{"kty":"OKP","crv":"Ed25519","x":"..."}')

# STANDARD COMPLIANCE: Use 'Vouch-Token' (RFC 6648)
@app.post("/agent/connect")
def connect_agent(vouch_token: str = Header(None, alias="Vouch-Token")):
    if not vouch_token:
        raise HTTPException(status_code=400, detail="Missing Vouch-Token header")
        
    is_valid, data = verifier.check_vouch(vouch_token)
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Agent Reputation Check Failed")
        
    return {
        "status": "Connected", 
        "agent": data['sub'],
        "reputation": data['vc']['reputation_score']
    }
"""

# ==========================================
# 2. UPDATE THE README (Documentation)
# ==========================================
# We rebuild the readme to ensure docs match code exactly
TICK = "`" * 3

readme_content = f"""# VOUCH PROTOCOL

{TICK}text
__      __  ____   _    _    _____   _    _ 
\\ \\    / / / __ \\ | |  | |  / ____| | |  | |
 \\ \\  / / | |  | || |  | | | |      | |__| |
  \\ \\/ /  | |__| || |__| | | |____  |  __  |
   \\__/    \\____/  \\____/   \\_____| |_|  |_|
{TICK}

![Status](https://img.shields.io/badge/Status-Alpha-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Standard](https://img.shields.io/badge/DID-Web-orange) ![Build](https://img.shields.io/github/actions/workflow/status/rampyg/vouch-protocol/tests.yml)

> ⚠️ **v0.1 Alpha Notice:** This is an experimental protocol. Contributions welcome.

> **"The 'Green Lock' for the AI Era."**

**Vouch** is the open-source standard for **AI Agent Identity & Liability**.

## 🛡️ The Solution: Three Pillars

| Pillar | Concept | Technology |
| :--- | :--- | :--- |
| **1. Identity** | "Who owns this agent?" | **W3C DID (`did:web`)** |
| **2. Integrity** | "Is the code safe?" | **SHA-256 Hashing** |
| **3. Liability** | "Who is responsible?" | **Verifiable Credentials** |

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

**For Gatekeepers (The Vouch-Token Header):**

{TICK}python
from fastapi import FastAPI, Header
from vouch import Verifier

app = FastAPI()
verifier = Verifier(trusted_key)

@app.post("/agent/connect")
def connect(vouch_token: str = Header(alias="Vouch-Token")):
    # 1. Look for 'Vouch-Token' (Not Authorization)
    is_valid, passport = verifier.check_vouch(vouch_token)
    
    if is_valid:
        return {{"status": "Welcome", "agent": passport['sub']}}
{TICK}

## 🤝 Contributing
We are looking for adapters for LangChain and AutoGen.

Run tests:
{TICK}bash
python tests/red_team.py
{TICK}

**License:** MIT
"""

# --- EXECUTE UPDATES ---
with open("examples/fastapi_server.py", "w") as f:
    f.write(fastapi_code)

with open("README.md", "w") as f:
    f.write(readme_content)

print("✅ UPGRADE COMPLETE: Switched to 'Vouch-Token' header.")
print("   - Updated examples/fastapi_server.py")
print("   - Updated README.md documentation")
