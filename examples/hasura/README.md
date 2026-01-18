# Hasura + Vouch Protocol Integration

> **Secure Your Data Layer for the Agentic Age**

[![Protected by Vouch](https://img.shields.io/badge/Protected_by-Vouch_Protocol-00C853?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0Ij48cGF0aCBmaWxsPSIjMDBDODUzIiBkPSJNMTIgMjBMMiA0aDRsNiAxMC41TDE4IDRoNEwxMiAyMHoiLz48L3N2Zz4=)](https://github.com/vouch-protocol/vouch)

---

## The Problem

AI agents accessing Hasura endpoints look like **generic API clients**. There's no way to verify:

- **Which agent** is making the request?
- **What intent** does the agent have?
- **Is this agent** authorized for this operation?

Standard JWTs only prove "someone logged in" — they don't bind **intent to identity**.

---

## The Solution

**Vouch Protocol** provides cryptographic identity for AI agents. Each agent:

1. **Signs every request** with their private key
2. **Includes intent** (what they're trying to do)
3. **Proves identity** via Ed25519 signatures

Hasura verifies via Auth Webhook before processing any GraphQL request.

```
[AI Agent] → [Sign with Vouch] → [Hasura Auth Webhook] → [Verify] → [GraphQL]
```

---

## Quick Start

### 1. Install

```bash
pip install vouch-protocol[server]
```

### 2. Run the Webhook

```bash
python -m vouch.integrations.hasura.webhook --port 3000
```

### 3. Configure Hasura

```yaml
HASURA_GRAPHQL_AUTH_HOOK: http://localhost:3000/auth
HASURA_GRAPHQL_AUTH_HOOK_MODE: GET
```

---

## Docker Compose Demo

```bash
cd examples/hasura
docker-compose up
```

This starts:
- **Hasura** on `http://localhost:8080`
- **Vouch Webhook** on `http://localhost:3000`
- **PostgreSQL** as database

---

## How It Works

### Session Variables Returned

| Variable | Description |
|----------|-------------|
| `X-Hasura-Role` | Computed from DID + reputation |
| `X-Hasura-User-Id` | Agent's DID |
| `X-Hasura-Vouch-Reputation` | Agent's reputation score (0-100) |
| `X-Hasura-Vouch-Intent` | Hash of the stated intent |
| `X-Hasura-Vouch-Delegation-Depth` | If delegated, how many hops |

### Role Mapping

```
Reputation ≥ 80  →  agent_admin
Reputation ≥ 50  →  agent_writer
Reputation ≥ 30  →  agent_reader
Delegated agent  →  agent_delegated
Otherwise        →  agent_minimal
```

---

## Security Features

✅ **Replay Prevention** — Each token can only be used once  
✅ **Key Revocation** — Compromised keys can be blocked  
✅ **Delegation Chains** — Multi-agent workflows with audit trail  
✅ **Ed25519 Signatures** — Modern, fast, secure  

---

## Agent Example (LangChain)

```python
from langchain_openai import ChatOpenAI
from vouch import Signer

signer = Signer(private_key=PRIVATE_KEY, did="did:web:my-agent.com")

# Sign the intent
token = signer.sign({"action": "query_users", "query": "..."})

# Include in headers
response = requests.post(
    "http://localhost:8080/v1/graphql",
    headers={"Vouch-Token": token},
    json={"query": "{ users { id name } }"}
)
```

---

## Learn More

- [Vouch Protocol Documentation](https://github.com/vouch-protocol/vouch)
- [Hasura Auth Webhook Docs](https://hasura.io/docs/latest/auth/authentication/webhook/)

---

*Built with ❤️ for the Agentic Future*
