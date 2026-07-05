# Framework Integrations Reference

Vouch is framework-agnostic, and adoption is one line. You wrap your existing
tools once, and every tool call the agent makes is signed in Python before it
runs. There is nothing for the model to remember and no prompt to write.

## Identity is resolved automatically

Set identity up once with `vouch init` (it persists to the keystore at
`~/.vouch/keys`), or export two environment variables:

```
VOUCH_PRIVATE_KEY   # the agent's private key, as a JWK JSON string
VOUCH_DID           # the agent's DID (e.g. did:web:agent.example.com)
```

`vouch init --yes` provisions and saves an identity without prompting, then
prints the one line to wire it in. After that, the signing layer resolves the
identity for you (explicit signer, then env vars, then the keystore), so agent
code needs no key plumbing.

## Three tiers of effort

```python
from vouch import protect, signed

# Tier 1: wrap a list of real tools (one line)
agent.tools = protect([charge_invoice, send_email])

# Tier 2: annotate a single tool
@signed(action="charge", target="api.payments.example.com")
def charge_invoice(invoice_id, amount): ...

# Tier 3 (decorator frameworks): sign every tool framework-wide
import vouch.integrations.crewai as vc
vc.autosign()
```

`protect` and `@signed` work everywhere. `autosign()` is available where the
framework exposes a global tool decorator to patch (CrewAI, LangChain, AutoGPT,
AutoGen). The signed credential for the most recent call is available via
`vouch.current_credential()`, and a tool can opt in to seeing its own credential
by declaring a `vouch_credential` keyword.

Install the SDK with `pip install vouch-protocol`. Reference implementations
live under `vouch/integrations/` in the Python SDK.

## CrewAI

```python
from vouch.integrations.crewai import protect, autosign
from crewai import Agent

# One line: wrap the agent's real tools.
researcher = Agent(role="Researcher", goal="Find market data",
                   tools=protect([market_research]))

# Or sign every @tool defined after this call.
autosign()  # patches crewai.tools.tool
```

## LangChain

```python
from vouch.integrations.langchain import protect, autosign

# Wrap a list of LangChain tools (BaseTool/StructuredTool) or plain functions.
tools = protect([search, send_email])

# Or sign every @tool framework-wide.
autosign()  # patches langchain_core.tools.tool (falls back to langchain.tools.tool)
```

## LangGraph

```python
from vouch.integrations.langgraph import protect, sign_node

# LangGraph tools are LangChain tools: wrap the tools for a ToolNode or create_react_agent.
tools = protect([search, send_email])

# Sign each graph node so the whole graph carries a signed trail.
@sign_node
def plan(state):
    ...
```

## AutoGen

AutoGen has no global tool decorator, but it registers tools through a
module-level call, so `autosign()` patches that.

```python
import vouch.integrations.autogen as va
from vouch.integrations.autogen import protect

# Wrap plain tool functions.
tools = protect([execute_trade])

# Or sign every tool registered via autogen.register_function.
va.autosign()
```

## AutoGPT

```python
import vouch.integrations.autogpt as vg
from vouch.integrations.autogpt import protect

tools = protect([execute_trade])

# Or sign every @command framework-wide.
vg.autosign()  # patches autogpt.command_decorator.command
```

## Google Vertex AI and Agent Builder

Vertex tools are plain functions, so `protect([...])` is the one-line path.

```python
from vouch.integrations.vertex_ai import protect    # or vouch.integrations.google
tools = protect([submit_claim, read_records])
```

## Google Agent Development Kit (ADK)

ADK has a richer sidecar that signs every call, applies a risk policy, and emits
an audit log. Use `protect_tools(...)` for the quick path, or `VouchIntegrator`
with a custom `RiskPolicy`.

```python
from vouch.integrations.adk import protect_tools, VouchIntegrator, RiskPolicy, RiskLevel

def transfer_funds(amount: int, to_account: str) -> str:
    return f"Transferred {amount} to {to_account}"

# Quick path.
protected = protect_tools([transfer_funds], block_high_risk=True)

# Custom risk rules.
policy = RiskPolicy(custom_rules={"transfer_funds": RiskLevel.HIGH})
protected = VouchIntegrator(risk_policy=policy, block_high_risk=True).protect([transfer_funds])
```

## Verifying on the receiving side

Verification is one line too. It is the counterpart to `protect`.

```python
import vouch

# Auto-resolves the issuer key via did:web, or pass public_key= for offline use,
# or call with no argument to verify the credential most recently signed here.
ok, passport = vouch.verify(credential)
```

For a web service, add one dependency. The gate reads the credential from the
`Vouch-Credential` header (or the request body), verifies it, optionally
enforces intent, and rejects unsigned or wrong-intent callers before the handler
runs.

```python
from fastapi import Depends, FastAPI
from vouch.integrations.fastapi import VouchGate

app = FastAPI()
gate = VouchGate(require_action="charge")   # auto-resolves issuers via did:web

@app.post("/charge")
async def charge(passport=Depends(gate)):
    return {"agent": passport.iss}
```

`VouchGate` is a thin shell over the framework-agnostic `vouch.gate.CredentialGate`,
which any web framework can use (`public_key=`, `trusted_keys=` allowlist,
`allow_did_resolution=`, and `require_action`/`require_target`/`require_resource`).

## Delegation: principal to agent in one line

A human or supervisor grants an agent narrow authority, and every action the
agent signs is chained under that grant. The protocol enforces that a worker can
only narrow the authority, never widen it.

```python
import vouch

grant = vouch.delegate(action="charge", target="api.payments.example.com",
                       resource="invoices", to=agent_did, signer=principal_signer)

agent.tools = vouch.protect([charge_invoice], parent=grant)
```

`parent=` also works on `@signed` and `sign_intent`.

## Zero-config runtime protection: Shield.guard

The full `Shield` is configurable (trust registry, capability files). For the
common case, `Shield.guard` needs no config files: it signs each call, checks a
tool allowlist (default: exactly the tools you pass, so the agent cannot be
steered into a tool you never granted), and writes a tamper-evident audit log.

```python
from vouch.shield import Shield

agent.tools = Shield.guard([charge_invoice, send_email])
```

## n8n

`N8NHelper` returns a ready-to-paste Python Code Node snippet and can sign a
single workflow item.

```python
from vouch.integrations.n8n import N8NHelper

snippet = N8NHelper.get_code_node_snippet()
token = N8NHelper.sign_workflow_item({"order_id": "A-1001"})
```

Set `EXTERNAL_PYTHON_PACKAGES=vouch-protocol` plus `VOUCH_PRIVATE_KEY` and
`VOUCH_DID` in the n8n environment so the Code Node can import and sign.

## Hasura

A Hasura Auth Webhook that verifies an incoming credential and returns Hasura
session variables. `RoleMappingConfig` maps DIDs and reputation to roles.

```python
from vouch.integrations.hasura import HasuraAuthWebhook, create_webhook_handler
from vouch.integrations.hasura.webhook import RoleMappingConfig

config = RoleMappingConfig(did_roles={"did:web:cfo.example.com": "agent_admin"})
webhook = HasuraAuthWebhook(role_config=config)
ok, session_vars = webhook.authenticate({"Vouch-Token": "<token>"})

# Or run a standalone Flask server (GET /auth, GET /health):
app = create_webhook_handler(role_config=config)
```

Point Hasura's `authorization_webhook` at the `/auth` endpoint.

## Streamlit

UI components that render a verification seal or a detailed card.

```python
from vouch.integrations.streamlit.seal import vouch_seal_component, vouch_verification_card

vouch_seal_component(is_verified=True, agent_name="Finance Bot")
vouch_verification_card(agent_name="Finance Bot", agent_did="did:web:agent.example.com",
                        is_verified=True, reputation_score=82)
```

## Model Context Protocol (MCP)

Vouch ships a standalone MCP server (stdio) for Claude Desktop, Cursor, and
other MCP clients. Run it as the `vouch-mcp` console script with the agent
identity in the environment:

```bash
export VOUCH_PRIVATE_KEY='{"kty":"OKP", ...}'
export VOUCH_DID='did:web:agent.example.com'
vouch-mcp
```

The server exposes tools to the connected model to mint a credential, return the
configured DID, and create a short-lived session token.

## Goose

Block's Goose loads its tools from MCP servers. Vouch ships one (vouch-mcp), so
register it as a Goose extension.

```bash
pip install vouch-goose
vouch-goose            # writes the extension into ~/.config/goose/config.yaml
```

## Browser and mobile

For human-in-the-loop signing from a web app, use the TypeScript SDK
(`npm install @vouch-protocol-official/sdk`) so the user's key stays on the
device and the user approves each signature.

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
