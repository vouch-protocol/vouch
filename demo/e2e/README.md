# End to end agent authorization demo

One command shows an AI agent authorizing real actions with Vouch Protocol,
with the private key held in a separate signing sidecar and the agent code
carrying a single line of Vouch.

```bash
python demo/e2e/run_demo.py
```

No API keys and no network. The agent logic is deterministic so the
cryptographic pipeline is the only thing on display.

## What it demonstrates

1. An identity is minted for the agent.
2. The private key goes to a separate signing sidecar, the published
   `vouch-mcp` server, and stays in that process. The agent never holds it.
3. The agent decides on an action and signs that intent through the sidecar
   over the Model Context Protocol.
4. A bank verifies the credential and enforces the exact intent binding.
5. A replayed credential aimed at a different account is rejected.
6. The same flow runs under the post-quantum profile.
7. A trust-decaying session voucher (Heartbeat Protocol) is issued.

## The point: where the code lives

The files are split by role so the integration cost is visible on its own.

| File | Role | Vouch code |
| --- | --- | --- |
| `agent.py` | the AI agent's business logic | one call: `sidecar.sign(...)` |
| `vouch_sidecar.py` | the MCP client to the signing sidecar | the whole integration surface, written once |
| `bank.py` | the receiving service | verify, then check the intent binding |
| `run_demo.py` | the orchestrator that runs the scenes | mints the identity, starts the sidecar |

The agent process cannot leak the key, because it never receives it. It holds
one `VouchSidecar` handle and nothing else. A prompt-injected model in the agent
cannot exfiltrate a secret it does not have.

## Use the sidecar from your own MCP client

The demo launches the sidecar as a child process so it runs in one command. In a
real setup you install it once and register it with your MCP client, the same
way you add any other server. There is a ready-to-edit config next to this file,
[`mcp_client_config.json`](mcp_client_config.json):

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_DID": "did:web:your-agent.example.com",
        "VOUCH_PRIVATE_KEY": "PASTE_YOUR_PRIVATE_KEY_JWK_JSON_STRING"
      }
    }
  }
}
```

Install the server with `pip install vouch-mcp`, then drop that block into your
Claude Desktop or Cursor config. To get real values for the two env vars:

```python
from vouch import generate_identity
kp = generate_identity("your-agent.example.com")
print(kp.did)              # -> VOUCH_DID
print(kp.private_key_jwk)  # -> VOUCH_PRIVATE_KEY
```

Once it is registered, your agent has `sign`, `verify`, `create_session`,
`check_revocation`, and `get_identity` as ordinary MCP tools, and the key stays
in the server process.

## Turning this into a real framework agent

The agent here is framework-agnostic on purpose. To drive it with a real LLM
agent, wrap the single `sidecar.sign` call as a tool the framework can invoke.
One server serves every framework through its standard MCP client, so there is
no per-framework Vouch connector to maintain:

- [`examples/mcp-vouch/`](../../examples/mcp-vouch/) wires the same `vouch-mcp`
  server into LangChain, LangGraph, CrewAI, AutoGen, Google ADK, Vertex AI,
  AutoGPT, n8n, and Hasura, each through that framework's own MCP client.
- [`examples/05_integrations/`](../../examples/05_integrations/) has the
  per-framework agent scripts if you want a full runnable agent for one stack.

## The sidecar

The sidecar is the published `vouch-mcp` server, run here as a child process:

```
python -m vouch.integrations.mcp.server
```

with `VOUCH_PRIVATE_KEY` and `VOUCH_DID` in its environment. In production it is
`pip install vouch-mcp` and runs on its own, over stdio for local clients or
Streamable HTTP for hosted use. It exposes `sign`, `verify`, `create_session`,
`check_revocation`, and `get_identity`.
