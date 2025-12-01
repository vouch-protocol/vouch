# VOUCH PROTOCOL

```text
__      __  ____   _    _    _____   _    _ 
\ \    / / / __ \ | |  | |  / ____| | |  | |
 \ \  / / | |  | || |  | | | |      | |__| |
  \ \/ /  | |__| || |__| | | |____  |  __  |
   \__/    \____/  \____/   \_____| |_|  |_|
```

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

**For Gatekeepers (The Vouch-Token Header):**

```python
from fastapi import FastAPI, Header
from vouch import Verifier

app = FastAPI()
verifier = Verifier(trusted_key)

@app.post("/agent/connect")
def connect(vouch_token: str = Header(alias="Vouch-Token")):
    # 1. Look for 'Vouch-Token' (Not Authorization)
    is_valid, passport = verifier.check_vouch(vouch_token)
    
    if is_valid:
        return {"status": "Welcome", "agent": passport['sub']}
```

## 🤝 Contributing
We are looking for adapters for LangChain and AutoGen.

Run tests:
```bash
python tests/red_team.py
```

**License:** MIT
