import os

# We build the internal code fences safely
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

> **"The 'Green Lock' for the AI Era."**

**Vouch** is the open-source standard for **AI Liability & Identity**. It provides the missing infrastructure to bridge Web2 (DNS) and Web3 (Cryptography), creating a verifiable "Digital Passport" system for autonomous agents.

---

## 🛑 The Problem: The AI "Wild West"

As of late 2025, millions of autonomous agents are coming online. They are booking flights, executing code, and negotiating contracts. But the infrastructure of trust hasn't kept up.

1.  **No Identity:** If an agent emails you claiming to be "Expedia Support," you have no cryptographic way to verify that origin.
2.  **No Integrity:** You cannot prove if the agent's code or model weights have been tampered with since deployment.
3.  **No Liability:** If an agent hallucinates and deletes your database, there is no signed contract linking that action to a legal entity.

**Web2 had SSL. Web3 has Wallets. AI needs Vouch.**

---

## 🛡️ The Solution: Three Pillars of Trust

Vouch creates a standardized `vouch.json` file that sits at the root of an agent's domain, acting as its root of trust.

| Pillar | Concept | Technology |
| :--- | :--- | :--- |
| **1. Identity** | "Who owns this agent?" | **W3C DID (`did:web`)** linking Agent ID to DNS Domain. |
| **2. Integrity** | "Is the code safe?" | **SHA-256 Hashing** of model weights & source code. |
| **3. Liability** | "Who is responsible?" | **Verifiable Credentials** signing specific capabilities (e.g., "Read Only"). |

---

## ⚡ Quick Start

### 1. Installation
{TICK}bash
pip install -r requirements.txt
{TICK}

### 2. The Standard (`vouch.json`)
To be compliant, an agent must host this file at `https://your-domain.com/.well-known/vouch.json`.

{TICK}json
{{
  "id": "did:web:finance-bot.example.com",
  "verificationMethod": [{{
      "id": "#primary-key",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {{ "kty": "OKP", "crv": "Ed25519", "x": "..." }}
  }}]
}}
{TICK}

### 3. Usage (Python SDK)

**For Gatekeepers (Verifying an incoming agent):**

{TICK}python
from vouch import Verifier

# Initialize with the agent's public key (fetched from their DID)
gatekeeper = Verifier(trusted_key_json)

# Verify the token sent by the agent
is_valid, passport = gatekeeper.check_vouch(incoming_token)

if is_valid:
    print(f"✅ Identity Confirmed: {{passport['sub']}}")
else:
    print("🛑 Access Denied: Untrusted Agent.")
{TICK}

---

## 🏗️ Architecture

* **Core SDK:** Lightweight Python wrapper for Ed25519 signing and verification (via `jwcrypto`).
* **Edge Compatible:** The verification logic is stateless and designed to run on Edge Workers (Cloudflare/Vercel) for <10ms latency.
* **Security:** Includes a Red Team test suite to simulate Replay Attacks and Forgery attempts.

## 🤝 Contributing

The Vouch Protocol is an open standard. We are looking for contributors to help build:
* **Adapters:** Middleware for LangChain, AutoGen, and CrewAI.
* **Bridges:** Compatibility with ERC-8004 (Blockchain Agent Identity).
* **Governance:** Defining the Liability Schema.

Run the security tests locally:
{TICK}bash
python tests/red_team.py
{TICK}

**License:** MIT
"""

with open("README.md", "w") as f:
    f.write(readme_content)

print("✅ README.md has been updated successfully!")
