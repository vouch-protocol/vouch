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
process, so the agent's private key lives here, never in the LLM's context. A
prompt-injected model cannot exfiltrate a key it never holds.

## When to use this vs `vouch.autosign`

Vouch gives you two front doors onto one signing primitive:

- **`vouch.autosign`** (in-process, Python): wrap a tool with `protect([...])`
  and every call is signed deterministically, before the tool runs, with no
  LLM cooperation. Best when your agent is Python and you want zero-effort,
  can't-forget signing.
- **`vouch-mcp`** (this package): the out-of-process, cross-language path. Any
  MCP client in any language calls `sign` / `verify` over the
  wire, and the key is isolated in the server process. Best for non-Python
  agents, key isolation, or exposing verification as a shared service.

Both call the same `sign_intent` core, so credentials are identical either way.

## Install

```bash
pip install vouch-mcp          # or: uvx vouch-mcp
```

This pulls in `vouch-protocol[mcp]`, including the official MCP SDK. For the
post-quantum profile, install `pip install 'vouch-protocol[mcp,pq]'`.

## Configure

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
| `sign(action, target, resource, post_quantum=False)` | Issue a credential authorizing one action, bound to that exact resource. Set `post_quantum=True` for the `hybrid-eddsa-mldsa44-jcs-2026` profile. |
| `verify(credential_json, public_key=None)` | Verify a credential another agent or service presented. Any MCP client can verify without installing an SDK. |
| `create_session(purpose, valid_seconds, decay_lambda, initial_trust)` | Issue a trust-decaying session voucher (Heartbeat Protocol). |
| `check_revocation(credential_json)` | Check a credential's `BitstringStatusList` entry: `ACTIVE`, `REVOKED`, or not individually revocable. |
| `get_identity()` | Return the agent's DID. |
| `evaluate_freshness(tier, snapshot_json=None, now_iso=None)` | Bounded-staleness revocation gate for offline/DTN use: decide if a last-synced revocation snapshot is fresh enough for the action's consequence tier, failing closed when too old. |
| `verify_disconnected_edge(credential_json, public_key)` | Authenticate any disconnected-edge (DTN) credential type (freshness token, presence, ephemeris grant, revocation, bundle custody, …); returns its type and subject. |

## Why `verify` matters

Signing proves *you* acted. Verifying is how *everyone else* benefits: any
MCP-capable agent, in any framework, can confirm another agent's credential with
a single tool call and no SDK. That is what turns Vouch from a per-app library
into an interoperable trust layer.

## Registry

This package ships a `server.json` manifest for the MCP registry, so it can be
discovered and installed like any other MCP server.

## License

Apache-2.0.

## MCP registry

This server is listed in the Model Context Protocol registry.

mcp-name: io.github.vouch-protocol/vouch-mcp
