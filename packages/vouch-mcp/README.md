# vouch-mcp

A Model Context Protocol (MCP) server that issues [Vouch](https://vouch-protocol.com)
Credentials so an AI agent can cryptographically authorize the actions it takes.

MCP standardized how agents call tools. It does not say who is calling, or on
whose authority. `vouch-mcp` adds that layer: every signed action carries a
W3C Verifiable Credential with an `eddsa-jcs-2022` Data Integrity proof, and
optionally a delegation chain back to an accountable human principal.

## Install

```bash
pip install vouch-mcp
```

This pulls in `vouch-protocol[mcp]`, including the official MCP SDK.

## Configure

The server reads two environment variables:

- `VOUCH_PRIVATE_KEY` the agent's private key (JWK JSON string).
- `VOUCH_DID` the agent's DID, e.g. `did:web:agent.example.com`.

Generate a development identity:

```python
from vouch import generate_identity
kp = generate_identity()
print(kp.private_key_jwk)   # set as VOUCH_PRIVATE_KEY
```

## Run

```bash
VOUCH_PRIVATE_KEY='...' VOUCH_DID='did:web:agent.example.com' vouch-mcp
```

Register it with an MCP client (Claude Desktop, Cursor, ...) as an stdio server
running the `vouch-mcp` command.

## Tools

| Tool | What it does |
|---|---|
| `sign_action(action, target, resource)` | Issue a credential authorizing one action. Returns compact JSON to attach as a `Vouch-Credential` header. |
| `create_session(purpose, valid_seconds)` | Issue a longer-lived credential covering multiple actions. |
| `get_identity()` | Return the agent's DID. |

## Verify on the receiving side

```python
from vouch import Verifier
ok, passport = Verifier.verify_credential(received_json, public_key=agent_pubkey)
```

## License

Apache-2.0.
