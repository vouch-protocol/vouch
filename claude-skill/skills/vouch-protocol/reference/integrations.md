# Framework Integrations Reference

Vouch is framework-agnostic. Each integration is a thin adapter that
wraps your existing framework's tool-call or action invocation with a
signing and verification step.

Reference implementations under `vouch/integrations/` in the Python SDK.

## LangChain

```python
from vouch.integrations.langchain import VouchTool
from langchain.tools import Tool

# Wrap an existing tool
original_tool = Tool(
    name="submit_claim",
    func=submit_claim_to_api,
    description="Submit an insurance claim",
)

vouched_tool = VouchTool(
    tool=original_tool,
    signer=signer,
    intent_template={
        "action": "submit_claim",
        "target": "{claim_id}",
        "resource": "https://insurance.example.com/claims/{claim_id}",
    },
)

# Use in your agent
agent = initialize_agent(tools=[vouched_tool], ...)
```

The wrapper signs the tool's input before execution and emits a Vouch
credential to the chain-of-thought trace. The downstream API verifies
the credential before processing.

## CrewAI

```python
from vouch.integrations.crewai import VouchAgent
from crewai import Agent, Task

# Wrap an agent so all its tasks are signed
vouched_researcher = VouchAgent(
    base_agent=Agent(
        role='Researcher',
        goal='Find market data',
        tools=[market_search_tool],
    ),
    signer=signer,
    default_intent={
        "action": "market_research",
        "resource": "https://market-data.example.com",
    },
)

# Crew runs as normal; every action emits a Vouch credential
```

## AutoGen

```python
from vouch.integrations.autogen import vouch_wrap_agent

assistant = AssistantAgent(
    name="financial_assistant",
    llm_config={...},
)
vouched_assistant = vouch_wrap_agent(assistant, signer=signer)
```

## AutoGPT

```python
from vouch.integrations.autogpt import vouch_command_wrapper

# Decorate command handlers
@vouch_command_wrapper(signer=signer, action="execute_trade")
def execute_trade(symbol, quantity):
    ...
```

## Model Context Protocol (MCP)

MCP is framework-agnostic, so Vouch composes natively. Two patterns:

### Server-side: verify incoming tool calls

```python
from vouch.integrations.mcp.server import VouchMCPServer

server = VouchMCPServer(
    name="claims-server",
    trusted_principals=["did:web:cfo.example.com"],
)

@server.tool(action="submit_claim", resource_template="https://insurance.example.com/claims/{id}")
async def submit_claim(id: str, amount: float):
    # Tool call must arrive with a valid Vouch credential
    # The decorator verifies before this body runs
    ...

server.run()
```

The server checks every tool invocation for a Vouch credential matching
the registered `action` and `resource_template`. Unsigned invocations
are rejected.

### Client-side: sign outgoing tool calls

```python
from vouch.integrations.mcp.client import VouchMCPClient

client = VouchMCPClient(server_url="https://claims-server.example.com", signer=signer)
result = await client.call_tool(
    "submit_claim",
    arguments={"id": "HC-001", "amount": 1500.00},
    intent_overrides={"target": "claim:HC-001"},
)
```

Reference MCP server lives at `vouch/integrations/mcp/server.py`.

## Google Vertex AI

```python
from vouch.integrations.vertex import VouchVertexTool

# Tools you register with Vertex AI's tool-use API
tool = VouchVertexTool(
    name="submit_claim",
    function=submit_claim_fn,
    signer=signer,
    intent_template={...},
)
```

## Google Agent Development Kit (ADK)

```python
from vouch.integrations.google_adk import VouchAgentExecutor

executor = VouchAgentExecutor(
    underlying_executor=adk_executor,
    signer=signer,
)
```

## Google APIs (Sheets, Docs, Drive)

```python
from vouch.integrations.google_apis import VouchGoogleClient

# Wraps the Google API client so every API call is preceded by a Vouch credential
client = VouchGoogleClient(google_credentials=google_creds, signer=signer)
sheet = client.spreadsheets().get(spreadsheetId="...").execute()
```

## n8n

n8n has a Vouch node that signs outgoing webhooks and verifies incoming
ones. Configure in `n8n` settings -> Vouch:

```
Signer DID:        did:web:your-n8n.example.com
Signer Key Path:   /var/lib/n8n/vouch.jwk
```

Then the "Vouch Sign" and "Vouch Verify" nodes appear in the node
palette.

## Hasura

Hasura webhook authorizer that calls Vouch verification:

```yaml
# config.yaml
authorization_webhook:
    url: https://your-vouch-verifier.example.com/verify
    timeout: 5
    cache_max_age: 60
```

Custom verifier endpoint reads `Authorization: Vouch <credential-json>`
header and returns Hasura's session-variables on success.

## Generic pattern (build your own)

Three steps for any framework:

1. **At tool-call emit time**: build a Vouch credential whose `intent`
   matches the tool call. Sign with the agent's `Signer`. Attach to
   the outgoing call (as request body or `Authorization` header).
2. **At tool-call receive time**: parse the Vouch credential, verify
   with `Verifier`. Reject if invalid.
3. **In the audit log**: record the credential's `id`, `validFrom`,
   `intent`, and `proof.verificationMethod`. The signed credential
   itself is the audit record.

If your framework has middleware hooks (pre-tool, post-tool), implement
this as middleware. If it has decorator-style tool registration,
implement as a decorator. The Python SDK includes both patterns.

## Browser extension flow

For human-driven actions in a browser (e.g., signing a contract from
a web app):

```ts
import { VouchClient } from '@vouch-protocol/core';

// In a Chrome extension content script
const credential = await VouchClient.signFromExtension({
    intent: { action: 'approve_contract', target: 'doc:42', resource: 'https://docs.example.com/42' },
});

// Send to the page
window.postMessage({ type: 'vouch-credential', credential }, '*');
```

The extension's background script holds the user's key and prompts for
approval before signing.

## Mobile (iOS / Android)

The mobile SDK uses platform Secure Enclave / Android Keystore:

```kotlin
val client = VouchClient(
    did = "did:web:agent.example.com",
    keyAlias = "vouch-agent-key",  // Android Keystore alias
)

val signed = client.signCredential(
    intent = mapOf(
        "action" to "capture_photo",
        "target" to photo.id,
        "resource" to "evidence://${photo.id}",
    ),
)
```

Keys never leave the secure hardware element. Useful for evidence
capture, witness apps, courier signatures.

## When to integrate Vouch

A pragmatic checklist:

- The action has real-world consequences (money, health, legal, safety)? -> Integrate.
- The action is irreversible or hard to reverse? -> Integrate.
- Audit / compliance asks "who authorized this?" -> Integrate.
- The action is in a regulated sector (healthcare, finance, gov)? -> Integrate.
- The action is purely informational (search, summarize)? -> Optional, sometimes worth it for the audit-trail value alone.
- The action is internal and trusted? -> Often skip Vouch, save the latency.

The integration tax is small (single-digit milliseconds for signing,
~3 ms for hybrid). The audit-trail value is large.
