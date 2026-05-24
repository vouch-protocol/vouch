# Framework Integrations Reference

Vouch is framework-agnostic. Each integration is a thin adapter that
wraps your existing framework's tool-call or action invocation with a
signing (and optionally verification) step.

Reference implementations live under `vouch/integrations/` in the Python
SDK. Every import and symbol below is taken from that source tree.

> **Signing path.** The framework adapters below emit a legacy JWS
> `Vouch-Token` via `Signer.sign(payload)`. New code can instead issue a
> v1.0 Verifiable Credential with `Signer.sign_credential(intent={...})`
> (TypeScript: `signer.signCredential({...})`). The Amnesia adapter
> already uses the VC path. Both interoperate against the same DID.

All Python signing adapters read the agent identity from the
`VOUCH_PRIVATE_KEY` and `VOUCH_DID` environment variables (most also
accept them as explicit arguments). Generate them with `vouch init --env`.

## LangChain

`VouchSignerTool` is a LangChain `BaseTool` (named `vouch_signer`) that
returns a `Vouch-Token` for a given intent.

```python
from vouch.integrations.langchain import VouchSignerTool
from langchain.agents import initialize_agent

# Reads VOUCH_PRIVATE_KEY / VOUCH_DID from the environment,
# or pass private_key_json=... and agent_did=... explicitly.
vouch_tool = VouchSignerTool()

agent = initialize_agent(tools=[vouch_tool, ...], llm=llm)
# The agent calls vouch_signer(intent="submit_claim", target="HC-001")
# before the API call and attaches the returned Vouch-Token header.
```

Input schema: `intent` (required) and optional `target`
(`VouchSignerInput`). The tool returns the string `Vouch-Token: <jws>`.

## CrewAI

`sign_request` is a CrewAI `@tool`. Add it to any agent's tool list.

```python
from vouch.integrations.crewai import sign_request
from crewai import Agent

researcher = Agent(
    role="Researcher",
    goal="Find market data",
    tools=[market_search_tool, sign_request],
)
# The agent invokes sign_request(intent="market_research",
# target="market-data.example.com") and attaches the Vouch-Token.
```

`VouchCrewTools.sign_request` exposes the same callable for grouping.

## AutoGen

Register `sign_action` as a callable function with your assistant.

```python
from vouch.integrations.autogen import sign_action, VOUCH_FUNCTIONS

# Register directly with an AutoGen agent's function map:
assistant.register_function(function_map={"sign_action": sign_action})

# VOUCH_FUNCTIONS provides the ready-made schema entry:
#   {"name": "sign_action", "description": ..., "function": sign_action}
```

`sign_action(intent, target=None)` returns `Vouch-Token: <jws>`.

## AutoGPT

```python
from vouch.integrations.autogpt import sign_with_vouch, register_commands

# register_commands() returns [sign_with_vouch] for AutoGPT's
# command registry. The command is exposed to the agent as
# "sign_with_vouch" with args: intent (required), target_service.
commands = register_commands()
```

`sign_with_vouch(intent, target_service=None)` returns instructions
containing the generated `Vouch-Token`.

## Model Context Protocol (MCP)

The Vouch MCP server is a stdio JSON-RPC server that lets an MCP client
(Claude Desktop, Cursor, Gemini CLI) sign the agent's own actions. It is
**client-side signing**: the agent mints tokens; it does not verify
inbound calls.

Run it via the `vouch-mcp` console script (installed with
`pip install vouch-protocol`). Configure it in your MCP client:

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_PRIVATE_KEY": "<jwk>",
        "VOUCH_DID": "did:web:agent.example.com"
      }
    }
  }
}
```

Tools exposed: `sign_action` (intent, target), `get_identity`,
`create_session` (purpose). Reference implementation:
`vouch/integrations/mcp/server.py`. For Gemini CLI, the packaged
extension at `gemini-extension/` wires this server up directly; see also
`docs/mcp-quickstart.md`.

## Google Vertex AI

`VertexAISigner` signs Vertex AI function/tool calls.

```python
from vouch.integrations.google import VertexAISigner

signer = VertexAISigner()  # reads VOUCH_PRIVATE_KEY / VOUCH_DID
token = signer.sign_tool_call("search_database", {"query": "test"})
# Attach `token` to the outgoing call; the downstream API verifies it.
```

For a plain intent string, `vouch.integrations.vertex_ai` (and
`vouch.integrations.google`) expose `sign_request_with_vouch(intent,
target=None)`. A runnable end-to-end demo (signing function calls,
catching a tampered `book_hotel` argument) lives at
`examples/05_integrations/08_vertex_ai.py`.

## Google Agent Development Kit (ADK)

`protect_tools` wraps ADK tool functions with signing, risk-based policy
enforcement, and audit logging (optionally to Google Cloud Logging).

```python
from vouch.integrations.adk import protect_tools

protected = protect_tools([transfer_funds, read_account], block_high_risk=True)
# Pass `protected` to your ADK agent in place of the raw tools.
```

For full control use the `VouchIntegrator` class
(`risk_policy=`, `log_name=`, `enable_cloud_logging=`,
`block_high_risk=`) and call `integrator.protect([...])`.

## Signing Google API calls (Sheets, Docs, Drive)

There is no dedicated Google-API client wrapper. Sign each call with the
generic helper and attach the token to your request:

```python
from vouch.integrations.google import sign_request_with_vouch

token = sign_request_with_vouch(intent="read_spreadsheet",
                                target="sheets.googleapis.com")
# token == "Vouch-Token: <jws>" — record it alongside the API response
# for the audit trail.
```

## Streamlit

UI components to surface verification state in a Streamlit app:

```python
from vouch.integrations.streamlit import (
    vouch_seal_component,
    vouch_verification_card,
)

vouch_seal_component(is_verified=True, agent_name="Finance Bot",
                     agent_did="did:web:finance.example.com", show_details=True)

vouch_verification_card(
    agent_name="Finance Bot",
    agent_did="did:web:finance.example.com",
    is_verified=True,
    reputation_score=92,
)
```

Requires `pip install streamlit`.

## Amnesia (egress policy attestation)

Wrap an Amnesia `EgressDecision` in a signed VC 2.0 credential. This
adapter uses the v1.0 credential path (not the legacy JWS token).

```python
from vouch import Signer
from vouch.integrations.amnesia import attest_decision, attest_decision_from_log

signer = Signer(private_key=key_jwk, did="did:web:gateway.example.com")
attestation = attest_decision(egress_decision, signer)
# attestation.credential is the signed VC; .decision_overall and
# .rule_count summarize it. cryptosuite="hybrid-eddsa-mldsa44-jcs-2026"
# selects the post-quantum hybrid proof.

# Or attest straight from a decision log file:
attestation = attest_decision_from_log("egress.log.json", signer)
```

## n8n

`N8NHelper` generates Python for an n8n **Code Node** (n8n does not ship a
native Vouch node). Set `EXTERNAL_PYTHON_PACKAGES=vouch-protocol` plus
`VOUCH_PRIVATE_KEY` / `VOUCH_DID` in the n8n environment.

```python
from vouch.integrations.n8n import N8NHelper

# Paste this snippet into an n8n Python Code Node:
print(N8NHelper.get_code_node_snippet())

# Or sign a single workflow item programmatically:
token = N8NHelper.sign_workflow_item({"order_id": "A-100"})
```

## Hasura

A Hasura Auth Webhook that verifies inbound `Vouch-Token` headers and
returns Hasura session variables.

```python
# Standalone server:
from vouch.integrations.hasura import create_webhook_handler
app = create_webhook_handler()
app.run(host="0.0.0.0", port=3000)

# Or inside an existing Flask/FastAPI app:
from vouch.integrations.hasura import HasuraAuthWebhook
webhook = HasuraAuthWebhook()
result = webhook.authenticate(request.headers)  # reads the Vouch-Token header
```

Point Hasura at the webhook:

```yaml
# config.yaml
authorization_webhook:
    url: https://your-vouch-verifier.example.com/verify
    timeout: 5
    cache_max_age: 60
```

The handler reads the `Vouch-Token` header and returns Hasura's
session-variables on success.

## Generic pattern (build your own)

Three steps for any framework:

1. **At tool-call emit time**: build a Vouch credential whose `intent`
   matches the tool call. Sign with the agent's `Signer`. Attach to
   the outgoing call (as request body or `Vouch-Token` / `Authorization`
   header).
2. **At tool-call receive time**: parse the Vouch credential, verify
   with `Verifier`. Reject if invalid.
3. **In the audit log**: record the credential's `id`, `validFrom`,
   `intent`, and `proof.verificationMethod`. The signed credential
   itself is the audit record.

If your framework has middleware hooks (pre-tool, post-tool), implement
this as middleware. If it has decorator-style tool registration,
implement as a decorator. The Python SDK includes both patterns.

## Browser extension flow

For human-driven actions in a browser, sign with the TypeScript SDK
(`@vouch-protocol/sdk`). The extension's background script holds the
user's key and prompts for approval before signing.

```ts
import { Signer } from '@vouch-protocol/sdk';

const signer = new Signer({ privateKey: privateKeyJwk, did });

const credential = await signer.signCredential({
    intent: {
        action: 'approve_contract',
        target: 'doc:42',
        resource: 'https://docs.example.com/42',
    },
});

// Hand the credential to the page from the content script:
window.postMessage({ type: 'vouch-credential', credential }, '*');
```

`@vouch-protocol/sdk` also exports a Daemon Client for delegating signing
to a locally-running Vouch Bridge daemon when the key should not live in
the extension.

## Mobile (iOS / Android)

The reference mobile app is built on React Native / Expo. Keys are held
in the platform secure store (`expo-secure-store`); signing uses
Ed25519 via `expo-crypto`. The signing helpers live in the app at
`mobile/expo-app/src/signing/NativeSigner.ts`:

```ts
import { getOrCreateKeypair, signImage } from './signing/NativeSigner';

const identity = { did, displayName: 'Field Agent', credentialType: 'PRO' };
const result = await signImage(photoBase64, identity);
// result.signature, result.chainId, result.verifyUrl
```

Keys never leave the secure store. Useful for evidence capture, witness
apps, and courier signatures.

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
