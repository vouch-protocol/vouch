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

## OpenAI

The `vouch-openai` package signs the tool (function) calls an OpenAI agent
makes, so each action carries a verifiable identity. It works with the OpenAI
Python SDK function calling (Chat Completions and the Responses API) and with the
OpenAI Agents SDK, because all of them dispatch to Python tool callables and
expose a tool call as a name plus JSON arguments.

```bash
pip install vouch-openai
```

```python
from vouch.integrations.openai import signed_tool, protect, sign_tool_call, verify_tool_call

# Wrap the tool callables you dispatch to, so each execution is signed.
@signed_tool
def get_weather(city: str) -> str: ...

tools = protect([get_weather, send_email])

# Or sign the model's requested call (name plus JSON arguments) before you run it.
for call in response.choices[0].message.tool_calls:
    credential = sign_tool_call(call)
    result = dispatch(call)

# Verify on the receiving side.
ok, passport = verify_tool_call(credential)
```

Identity is resolved automatically (an explicit signer, then `VOUCH_DID` and
`VOUCH_PRIVATE_KEY`, then the keystore), so agent code needs no key plumbing. The
reference lives at `vouch/integrations/openai.py`, and the standalone package
declares the `openai` dependency for you.

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

The full `Shield` is configurable (trust registry, a rules file). For the
common case, `Shield.guard` needs no config files: it signs each call, checks a
tool allowlist (default: exactly the tools you pass, so the agent cannot be
steered into a tool you never granted), and writes a tamper-evident audit log.

```python
from vouch.shield import Shield

agent.tools = Shield.guard([charge_invoice, send_email])
```

### Rules: action, target, resource

Shield rules match the same three fields a Vouch Credential binds in its intent:
`action`, `target`, and `resource`. Rules live in a YAML or JSON file:

```yaml
version: 2
rules:
  - did: did:web:agent.example.com
    allow:
      - { action: read_file, target: files, resource: "reports/**" }
deny_default: true
```

In a resource pattern, `*` matches exactly one path segment and `**` matches any
number. So `reports/**` covers `reports/q3.txt` and `reports/2026/q3.txt`, but
not `secrets/keys.txt`. Resources are normalised before matching, so a path like
`reports/../etc/passwd` cannot slip through a `reports/**` rule.

Anything that does not match a rule is denied, and so is a missing or malformed
rules file.

```python
decision = shield.check(
    "did:web:agent.example.com",
    action="read_file", target="files", resource="reports/q3.txt",
)
if decision.allow:
    run_the_tool()
```

`decision.reason` is one of a small set of stable strings you can log and alert
on: `no matching rule`, `resource outside scope`, `unknown did`,
`invalid resource`, `malformed rules`.

### A Vouch-protected MCP server

`vouch.mcp.FastMCP` is a drop-in replacement for the MCP SDK's `FastMCP`. Every
tool registered on it is protected by default: a call has to arrive with a Vouch
Credential that verifies, comes from a trusted issuer, authorises that exact
call, and passes Shield, before the tool body runs.

```python
from vouch.mcp import FastMCP          # replaces: from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")

@mcp.tool(resource=lambda args: args["path"])
def read_file(path: str) -> str:
    return open(path).read()
```

A tool opts out with `@mcp.tool(unprotected=True)`, which logs a warning when it
is registered and on every call. A server started without `VOUCH_RULES` and
`VOUCH_TRUSTED_ISSUERS` refuses to start rather than running unprotected.

By default a credential authorises one call with one set of arguments. The
`resource=` argument above loosens that to a chosen value, which is what lets a
rule glob over paths or table names.

This is the receiving side. The `vouch-mcp` server issues credentials and will
refuse to sign what your rules forbid, but it cannot stop a client from calling
some other tool server, so the check belongs where the work happens.

Working examples: `examples/mcp_server/` for the filesystem,
`examples/mcp_server_sqlite/` where the resource is a SQL table name, and
`examples/mcp_server_ts/` for the TypeScript equivalent.

The same one line works in TypeScript:

```ts
import { McpServer } from '@vouch-protocol-official/mcp';
// replaces: import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'files', version: '1.0.0' });

server.registerTool(
  'read_file',
  { inputSchema: { path: z.string() }, resource: (args) => args.path as string },
  async ({ path }: { path: string }) => ({ content: [{ type: 'text', text: read(path) }] }),
);
```

Shield itself is in both SDKs too, and both are checked against the same shared
decision vectors, so a rule means the same thing in either language.


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

The server exposes the full Vouch trust surface as MCP tools: issue and verify
credentials (`sign`, `verify`); identity, sessions, and revocation
(`get_identity`, `create_session`, `check_revocation`); key hygiene and DID
inspection (`scan`, `decode_did`); delegated authority and the rule check
(`delegate`, `check_action`); trust-over-time and AI-origin disclosure
(`check_trust`, `disclose_ai_origin`); reputation and authorship attribution
(`reputation`, `attribute`); and offline / disconnected-edge decisions
(`evaluate_freshness`, `verify_disconnected_edge`).

`sign` consults Shield before it signs. An intent your rules forbid never
becomes a credential; the caller gets a structured refusal instead.

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
3 ms for the post-quantum profile). The audit-trail value is large.
