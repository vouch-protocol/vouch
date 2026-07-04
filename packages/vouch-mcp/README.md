# vouch-mcp

A Model Context Protocol (MCP) server that lets AI agents **issue and verify**
[Vouch](https://vouch-protocol.com) Credentials, so every action an agent takes
carries cryptographic proof of who authorized it.

MCP standardized how agents call tools. It does not say *who* is calling, or on
*whose authority*. `vouch-mcp` adds that layer: every authorized action carries
a W3C Verifiable Credential with an `eddsa-jcs-2022` Data Integrity proof (or the
post-quantum hybrid profile), and any party can verify one over the same MCP
connection.

**The key stays out of the model.** MCP already runs this server in its own
process, so the agent's private key lives here, never in the LLM's context. That
is the Identity Sidecar boundary, provided natively by MCP's client/server split:
a prompt-injected model cannot exfiltrate a key it never holds.

## Install

```bash
pip install vouch-mcp
```

This pulls in `vouch-protocol[mcp]`, including the official MCP SDK. For the
post-quantum profile, install `pip install 'vouch-protocol[mcp,pq]'`.

## Configure

The server reads its identity from the environment:

- `VOUCH_PRIVATE_KEY` the agent's private key (JWK JSON string).
- `VOUCH_DID` the agent's DID, e.g. `did:web:agent.example.com`.

Generate a development identity:

```python
from vouch import generate_identity
kp = generate_identity("agent.example.com")
print(kp.did)               # did:web:agent.example.com
print(kp.private_key_jwk)   # set as VOUCH_PRIVATE_KEY
```

## Run

**Local (stdio)** for Claude Desktop, Cursor, and desktop agents:

```bash
VOUCH_PRIVATE_KEY='...' VOUCH_DID='did:web:agent.example.com' vouch-mcp
```

**Remote (Streamable HTTP)** for hosted / networked deployments:

```bash
VOUCH_MCP_TRANSPORT=http VOUCH_MCP_HOST=0.0.0.0 VOUCH_MCP_PORT=8080 \
  VOUCH_PRIVATE_KEY='...' VOUCH_DID='did:web:agent.example.com' vouch-mcp
```

Register it with an MCP client as an stdio server running `vouch-mcp`, or point
a networked client at `http://<host>:<port>/mcp`.

```jsonc
// Claude Desktop / Cursor MCP config
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_DID": "did:web:agent.example.com",
        "VOUCH_PRIVATE_KEY": "<jwk-json-string>"
      }
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `sign_action(action, target, resource, post_quantum=False)` | Issue a credential authorizing one action, bound to that exact resource. Set `post_quantum=True` for the `hybrid-eddsa-mldsa44-jcs-2026` profile. Returns compact JSON to attach as a `Vouch-Credential` header. |
| `verify_credential(credential_json, public_key=None)` | Verify a credential another agent or service presented. Any MCP client can verify without installing an SDK. |
| `create_session(purpose, valid_seconds, decay_lambda, initial_trust)` | Issue a trust-decaying session voucher (Heartbeat Protocol). Trust decays over time; a verifier can refuse high-stakes actions once it drops below a threshold. |
| `check_revocation(credential_json)` | Check a credential's `BitstringStatusList` entry: `ACTIVE`, `REVOKED`, or not individually revocable. |
| `get_identity()` | Return the agent's DID. |

## Why `verify_credential` matters

Signing proves *you* acted. Verifying is how *everyone else* benefits: any
MCP-capable agent, in any framework, can confirm another agent's credential with
a single tool call and no SDK. That is what turns Vouch from a per-app library
into an interoperable trust layer.

```
Agent A  --sign_action-->  credential  --verify_credential-->  Agent B / gateway
```

## Registry

This server ships a `server.json` manifest for the MCP registry, so it can be
discovered and installed like any other MCP server.

## License

Apache-2.0.
