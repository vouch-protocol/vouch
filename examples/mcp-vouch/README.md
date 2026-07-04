# Using Vouch Protocol from any framework, over MCP

`vouch-mcp` is a Model Context Protocol server. Any MCP-capable agent framework
can connect to it and gain two tools: `sign_action` (authorize an action with a
Verifiable Credential) and `verify_credential` (check one someone else
presented), plus `create_session`, `check_revocation`, and `get_identity`.

The payoff: you do **not** need a bespoke Vouch connector per framework. You run
one server and wire it in through each framework's standard MCP client. The
agent's private key stays in the server process, never in the model's context.

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

Below, the **only Vouch-specific lines are the MCP client pointing at
`vouch-mcp`**: everything else is each framework's normal setup.

---

## LangChain / LangGraph: `langchain-mcp-adapters`

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "vouch": {"command": "vouch-mcp", "transport": "stdio",
              "env": {"VOUCH_DID": "did:web:agent.example.com",
                      "VOUCH_PRIVATE_KEY": "<jwk>"}}
})
tools = await client.get_tools()          # sign_action, verify_credential, ...

# hand `tools` to any LangChain/LangGraph agent as usual:
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
                  tools=vouch_tools)      # sign_action available to the crew
```

## AutoGen: `autogen_ext` MCP workbench

```python
from autogen_ext.tools.mcp import McpWorkbench, StdioServerParams

params = StdioServerParams(command="vouch-mcp",
    env={"VOUCH_DID": "did:web:agent.example.com", "VOUCH_PRIVATE_KEY": "<jwk>"})

async with McpWorkbench(params) as workbench:
    # pass `workbench` to an AssistantAgent; it can now call sign_action
    ...
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
the model calls `sign_action`; the credential is minted in the server process.

## AutoGPT

AutoGPT's platform consumes MCP servers as tool providers. Register `vouch-mcp`
in the block/tool configuration with the same `command` + `env`, and the agent
gains `sign_action` / `verify_credential` as callable blocks.

## n8n: MCP Client Tool node

n8n ships an **MCP Client Tool** node. Point it at the server:

```
Connection:  Command Line (stdio)
Command:     vouch-mcp
Environment: VOUCH_DID=did:web:agent.example.com
             VOUCH_PRIVATE_KEY=<jwk>
```

Then any workflow can call `sign_action` before an outbound HTTP node and attach
the returned credential as a `Vouch-Credential` header.

## Hasura: verify at the gateway (the receiving side)

Hasura is not an MCP client; it is where you **enforce** the credential. Have
your webhook authorizer call `verify_credential` (via the same MCP server, or
the `vouch` SDK directly) and reject requests whose credential is missing,
invalid, or out of scope:

```yaml
# hasura config: authorization webhook that runs Vouch verification
authorization_webhook:
  url: https://your-verifier.example.com/verify   # calls Verifier.verify_credential
  timeout: 5
```

---

## The two-sided demo

The point of `verify_credential` is that signing and verifying can live in
different frameworks and still interoperate:

1. A **CrewAI** agent calls `sign_action("submit_claim", ...)` → credential.
2. A **LangGraph** service receives it and calls `verify_credential(...)` → it
   confirms the issuer DID and the exact authorized intent, or rejects it.

Same credential, two frameworks, one protocol. That is the interoperability MCP
users are looking for.
