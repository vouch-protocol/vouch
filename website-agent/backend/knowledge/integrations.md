# Framework Integrations Reference

Vouch is framework-agnostic. Each integration is a thin adapter that wraps
your existing framework's tool-call or action invocation with a signing
(or verification) step.

Every adapter resolves the agent identity from two environment variables:

```
VOUCH_PRIVATE_KEY   # the agent's private key, as a JWK JSON string
VOUCH_DID           # the agent's DID (e.g. did:web:agent.example.com)
```

Reference implementations live under `vouch/integrations/` in the Python SDK.
Install the SDK with `pip install vouch-protocol`.

The adapters return a Vouch-Token string. The convention is to attach it to
the outgoing request as a `Vouch-Token` header, then verify it on the
receiving side with a `Verifier`.

## LangChain

A LangChain `BaseTool` the agent can call to mint a Vouch-Token before an
authenticated request.

```python
from vouch.integrations.langchain.tool import VouchSignerTool, VouchSignerInput

# Reads VOUCH_PRIVATE_KEY and VOUCH_DID from the environment by default,
# or pass private_key_json= and agent_did= explicitly.
tool = VouchSignerTool()

# Give it to your agent alongside your other tools.
# agent = initialize_agent(tools=[tool, ...], llm=llm)

# Direct call (intent plus optional target):
token = tool._run("submit_claim", target="https://insurance.example.com")
```

`VouchSignerInput` is the tool's input schema (fields `intent` and optional
`target`).

## CrewAI

A CrewAI tool function, `sign_request`, plus a `VouchCrewTools` collection.

```python
from vouch.integrations.crewai.tool import sign_request, VouchCrewTools
from crewai import Agent

researcher = Agent(
    role="Researcher",
    goal="Find market data",
    tools=[sign_request],  # or VouchCrewTools.sign_request
)

# Direct call:
token = sign_request("market_research", target="https://market-data.example.com")
```

## AutoGen

A plain function, `sign_action`, that AutoGen can register as a callable tool.

```python
from vouch.integrations.autogen.tool import sign_action

# Register sign_action with your AutoGen agent's function map, then:
token = sign_action("execute_trade", target="https://broker.example.com")
```

## AutoGPT

A command, `sign_with_vouch`, plus `register_commands()` to expose it.

```python
from vouch.integrations.autogpt.commands import sign_with_vouch, register_commands

commands = register_commands()  # -> [sign_with_vouch]

# Direct call (note: target_service, not target):
result = sign_with_vouch("execute_trade", target_service="broker.example.com")
```

## Google Vertex AI

A standalone signing function for Vertex AI function calling.

```python
from vouch.integrations.vertex_ai.tool import sign_request_with_vouch

token = sign_request_with_vouch("submit_claim", target="https://insurance.example.com")
```

## Google Agent Development Kit (ADK)

A security sidecar that wraps ADK tool functions to sign every call, apply a
risk policy, and emit an audit log. Use `protect_tools(...)` for the quick
path, or `VouchIntegrator` with a custom `RiskPolicy` and `RiskLevel` rules.

```python
from vouch.integrations.adk import (
    protect_tools,
    VouchIntegrator,
    RiskPolicy,
    RiskLevel,
)

def transfer_funds(amount: int, to_account: str) -> str:
    return f"Transferred {amount} to {to_account}"

# Quick path: protect a list of tools with defaults.
protected = protect_tools([transfer_funds], block_high_risk=True)

# Custom path: explicit risk rules.
policy = RiskPolicy(custom_rules={"transfer_funds": RiskLevel.HIGH})
integrator = VouchIntegrator(risk_policy=policy, block_high_risk=True)
protected = integrator.protect([transfer_funds])

# Use the protected tools with your ADK agent.
```

## Google APIs (Vertex AI Agent Builder)

`VertexAISigner` signs a named tool call with its arguments; the module also
exposes a standalone `sign_request_with_vouch` function.

```python
from vouch.integrations.google import VertexAISigner, sign_request_with_vouch

signer = VertexAISigner()  # reads env vars, or pass private_key= and did=
token = signer.sign_tool_call("search_database", {"query": "claims"})

# Standalone helper:
token = sign_request_with_vouch("read_records", target="https://sheets.googleapis.com")
```

## n8n

`N8NHelper` returns a ready-to-paste Python Code Node snippet and can sign a
single workflow item.

```python
from vouch.integrations.n8n import N8NHelper

# Paste this into an n8n Python Code Node:
snippet = N8NHelper.get_code_node_snippet()

# Or sign one item directly:
token = N8NHelper.sign_workflow_item({"order_id": "A-1001"})
```

Set `EXTERNAL_PYTHON_PACKAGES=vouch-protocol` plus `VOUCH_PRIVATE_KEY` and
`VOUCH_DID` in the n8n environment so the Code Node can import and sign.

## Hasura

A Hasura Auth Webhook that verifies an incoming Vouch-Token and returns Hasura
session variables. `RoleMappingConfig` maps DIDs and reputation to roles.

```python
from vouch.integrations.hasura import HasuraAuthWebhook, create_webhook_handler
from vouch.integrations.hasura.webhook import RoleMappingConfig

config = RoleMappingConfig(
    did_roles={"did:web:cfo.example.com": "agent_admin"},
)

webhook = HasuraAuthWebhook(role_config=config)
ok, session_vars = webhook.authenticate({"Vouch-Token": "<token>"})

# Or run a standalone Flask server (GET /auth, GET /health):
app = create_webhook_handler(role_config=config)
# app.run(host="0.0.0.0", port=3000)
```

Point Hasura's `authorization_webhook` at the `/auth` endpoint.

## Streamlit

UI components that render a verification seal or a detailed card.

```python
import streamlit as st
from vouch.integrations.streamlit.seal import (
    vouch_seal_component,
    vouch_verification_card,
)

vouch_seal_component(is_verified=True, agent_name="Finance Bot")

vouch_verification_card(
    agent_name="Finance Bot",
    agent_did="did:web:agent.example.com",
    is_verified=True,
    reputation_score=82,
)
```

## Model Context Protocol (MCP)

Vouch ships a standalone MCP server (stdio) for Claude Desktop, Cursor, and
other MCP clients. It is not a client library; it is a server you run.

Run it as the `vouch-mcp` console script (installed with the SDK), with the
agent identity in the environment:

```bash
export VOUCH_PRIVATE_KEY='{"kty":"OKP", ...}'
export VOUCH_DID='did:web:agent.example.com'
vouch-mcp
```

The server exposes three tools to the connected model:

- `sign_action` (args: `intent`, optional `target`) mints a Vouch-Token.
- `get_identity` returns the configured agent DID.
- `create_session` (arg: `purpose`) issues a short-lived session token so the
  model does not have to sign every action individually.

The server entry point is `vouch.integrations.mcp.server:main` (class
`VouchMCPServer`).

## Generic pattern (build your own)

Three steps for any framework:

1. At emit time, mint a Vouch-Token whose `intent` matches the action you are
   about to take, signing with the agent's `Signer`. Attach it to the
   outgoing call as a `Vouch-Token` header (or request body).
2. At receive time, read the token and verify it with a `Verifier`. Reject if
   invalid, expired, or revoked.
3. In the audit log, record the verified token. The signed token itself is the
   audit record (who, what action, when).

If your framework has pre-tool/post-tool hooks, implement this as middleware.
If it has decorator-style tool registration, implement it as a decorator. The
ADK sidecar above is a worked example of the middleware pattern.

```python
from vouch import Signer, Verifier

signer = Signer(private_key="<jwk-json>", did="did:web:agent.example.com")
token = signer.sign({"intent": "submit_claim", "target": "claim:HC-001"})

verifier = Verifier()
ok, passport = verifier.check_vouch(token)
```

## Browser and mobile

For human-in-the-loop signing from a web app, use the TypeScript SDK
(`npm install @vouch-protocol-official/sdk`) so the user's key stays on the
device and the user approves each signature. The same `Vouch-Token` header
convention applies once the token reaches your backend.

## When to integrate Vouch

A pragmatic checklist:

- The action has real-world consequences (money, health, legal, safety)? Integrate.
- The action is irreversible or hard to reverse? Integrate.
- Audit or compliance asks "who authorized this?" Integrate.
- The action is in a regulated sector (healthcare, finance, government)? Integrate.
- The action is purely informational (search, summarize)? Optional, sometimes worth it for the audit-trail value alone.
- The action is internal and trusted? Often skip Vouch and save the latency.

The integration tax is small (single-digit milliseconds for signing, about
3 ms for hybrid post-quantum). The audit-trail value is large.
