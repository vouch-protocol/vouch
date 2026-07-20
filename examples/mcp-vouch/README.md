# Using Vouch Protocol from any framework, over MCP

`vouch-mcp` is a Model Context Protocol server. Any MCP-capable agent framework
can connect to it and gain the whole Vouch trust surface as tools. The core two
are `sign` (authorize an action with a Verifiable Credential) and `verify`
(check one someone else presented); around them sit the rest of the lifecycle:

- **Identity & sessions:** `create_session`, `check_revocation`, `get_identity`
- **Key hygiene & DID inspection:** `scan` (catch leaked keys before they cross
  a boundary), `decode_did` (inspect a peer's key algorithm)
- **Authority:** `delegate` (hand a worker one narrowed capability),
  `check_action` (the Shield capability gate)
- **Trust over time & transparency:** `check_trust` (recompute a session's
  decayed trust), `disclose_ai_origin` (sign an AI-origin claim over content)
- **Accountability:** `reputation` (score an agent from its outcomes),
  `attribute` (authorship blame from a signed manifest)
- **Disconnected edge (DTN):** `evaluate_freshness`, `verify_disconnected_edge`

See [`examples/mcp_trust_lifecycle.py`](../mcp_trust_lifecycle.py) for a single
task walked through the lifecycle tools in order.

The payoff: you do not need a bespoke Vouch connector per framework. You run one
server and wire it in through each framework's standard MCP client. The agent's
private key stays in the server process, never in the model's context.

> Python-only agent? You may prefer `vouch.autosign`: `protect([tool1, tool2])`
> signs every call deterministically in-process, no MCP round-trip. Use
> `vouch-mcp` when you want cross-language reach, key isolation, or verification
> as a shared service. Both produce identical credentials.

```
 LangChain ─┐
 CrewAI    ─┤
 AutoGen   ─┤   standard MCP client   ┌───────────────┐
 ADK       ─┼──────────────────────► │  vouch-mcp     │  holds the key,
 Vertex AI ─┤                         │  (FastMCP)     │  issues + verifies VCs
 AutoGPT   ─┤                         └───────────────┘
 n8n       ─┤   (MCP Client node)
 Hasura    ─┘   (verifies at the API gateway)
```

Start the server once (stdio for local, HTTP for hosted):

```bash
# local
VOUCH_PRIVATE_KEY='...' VOUCH_DID='did:web:agent.example.com' vouch-mcp
# hosted
VOUCH_MCP_TRANSPORT=http VOUCH_MCP_PORT=8080 \
  VOUCH_PRIVATE_KEY='...' VOUCH_DID='did:web:agent.example.com' vouch-mcp
```

Below, the only Vouch-specific lines are the MCP client pointing at `vouch-mcp`.
Everything else is each framework's normal setup.

## LangChain / LangGraph: `langchain-mcp-adapters`

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "vouch": {"command": "vouch-mcp", "transport": "stdio",
              "env": {"VOUCH_DID": "did:web:agent.example.com",
                      "VOUCH_PRIVATE_KEY": "<jwk>"}}
})
tools = await client.get_tools()          # sign, verify, ...

from langgraph.prebuilt import create_react_agent
agent = create_react_agent(model, tools)
```

## CrewAI: `crewai-tools` `MCPServerAdapter`

```python
from crewai import Agent
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

params = StdioServerParameters(command="vouch-mcp",
    env={"VOUCH_DID": "did:web:agent.example.com", "VOUCH_PRIVATE_KEY": "<jwk>"})

with MCPServerAdapter(params) as vouch_tools:
    agent = Agent(role="Claims agent", goal="Submit claims accountably",
                  tools=vouch_tools)
```

## AutoGen: `autogen_ext` MCP workbench

```python
from autogen_ext.tools.mcp import McpWorkbench, StdioServerParams

params = StdioServerParams(command="vouch-mcp",
    env={"VOUCH_DID": "did:web:agent.example.com", "VOUCH_PRIVATE_KEY": "<jwk>"})

async with McpWorkbench(params) as workbench:
    ...  # pass workbench to an AssistantAgent; it can call sign
```

## Google ADK: `MCPToolset`

```python
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters

toolset = MCPToolset(connection_params=StdioServerParameters(
    command="vouch-mcp",
    env={"VOUCH_DID": "did:web:agent.example.com", "VOUCH_PRIVATE_KEY": "<jwk>"}))

agent = LlmAgent(model="gemini-2.0-flash", name="claims_agent", tools=[toolset])
```

## Vertex AI (Gemini)

Vertex reaches MCP through ADK (above) when you deploy on Agent Engine, or you
can bridge the `vouch-mcp` tool schema into Gemini function-calling. Either way
the model calls `sign`; the credential is minted in the server process.

## AutoGPT

AutoGPT's platform consumes MCP servers as tool providers. Register `vouch-mcp`
in the block/tool configuration with the same `command` + `env`, and the agent
gains `sign` / `verify` as callable blocks.

## n8n: MCP Client Tool node

n8n ships an MCP Client Tool node. Point it at the server:

```
Connection:  Command Line (stdio)
Command:     vouch-mcp
Environment: VOUCH_DID=did:web:agent.example.com
             VOUCH_PRIVATE_KEY=<jwk>
```

Then any workflow can call `sign` before an outbound HTTP node and attach
the returned credential as a `Vouch-Credential` header.

## Hasura: verify at the gateway (the receiving side)

Hasura is not an MCP client; it is where you enforce the credential. Have your
webhook authorizer call `verify` (via the same MCP server, or the
`vouch` SDK directly) and reject requests whose credential is missing, invalid,
or out of scope:

```yaml
# hasura config: authorization webhook that runs Vouch verification
authorization_webhook:
  url: https://your-verifier.example.com/verify   # calls Verifier.verify
  timeout: 5
```

## The two-sided demo

The point of `verify` is that signing and verifying can live in
different frameworks and still interoperate:

1. A CrewAI agent calls `sign("submit_claim", ...)` and gets a credential.
2. A LangGraph service receives it and calls `verify(...)`, which
   confirms the issuer DID and the exact authorized intent, or rejects it.

Same credential, two frameworks, one protocol.
