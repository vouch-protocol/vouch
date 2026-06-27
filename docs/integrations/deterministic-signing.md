# Deterministic signing for agent tool calls

> Wrap a tool once. Every call is signed before it runs. The model never has to
> remember to sign.

## The problem with the old integrations

Every framework adapter used to ship a *"make a token"* tool — `sign_request`
(CrewAI), `VouchSignerTool` (LangChain), `sign_action` (AutoGen),
`sign_with_vouch` (AutoGPT), and so on. You added it to the agent's tool list
and then wrote a paragraph of prose asking the LLM to call it before every
sensitive action and to thread the returned token onward.

That makes security depend on a cooperative model. If the LLM forgets,
paraphrases, or hallucinates a token, **nothing is signed and nothing fails
loudly**. Signing should not be the model's job.

## The fix: sign in code, deterministically

`vouch.autosign` signs the call in Python, *before* the tool body runs. There is
nothing for the model to remember. Three tiers, smallest effort first.

### Tier 1 — `protect([...])` (one line)

```python
from vouch import protect            # or: from vouch.integrations.crewai import protect

agent = Agent(role=..., goal=..., tools=protect([charge_invoice, send_email]))
```

### Tier 2 — `@signed` (one decorator)

```python
from vouch import signed

@signed(action="charge", target="api.payments.example.com")
def charge_invoice(invoice_id, amount):
    ...
```

### Tier 3 — `autosign()` (near-zero, framework-wide)

```python
import vouch.integrations.crewai as vc
vc.autosign()                         # every @tool defined afterward is signed

@tool("Charge Invoice")               # signed transparently
def charge_invoice(...): ...
```

## Identity is resolved automatically

You set identity up once with `vouch init` (or `VOUCH_PRIVATE_KEY` /
`VOUCH_DID`). `resolve_signer()` then finds it in this order:

1. an explicit `signer=` argument,
2. the `VOUCH_PRIVATE_KEY` + `VOUCH_DID` environment variables,
3. the on-disk keystore at `~/.vouch/keys` (first unencrypted identity),
4. an ephemeral key, **only** if `VOUCH_AUTO_IDENTITY` is set (logged loudly).

If no identity is found, calls run **unsigned** with a warning rather than
crashing the agent — fail-open on availability, never silent on security.

## Getting the signed credential

The credential signed for the most recent call is published on a context
variable, so the receiving side (or your HTTP layer) can pick it up without the
tool body threading it through:

```python
from vouch import current_credential
from vouch.autosign import current_token_header

cred = current_credential()                       # the VC dict
headers = current_token_header()                  # {"Vouch-Token": "<json>"}
```

Verify it on the receiving end exactly as before:

```python
from vouch import Verifier
ok, passport = Verifier.verify_credential(cred, issuer_public_key)
```

A tool can also opt in to *seeing* its own credential by declaring a
`vouch_credential` keyword — the wrapper injects it automatically:

```python
@signed
def charge_invoice(invoice_id, amount, vouch_credential=None):
    ...   # vouch_credential is the signed VC for this call
```

## Coverage

Deterministic signing is wired into every agent-tool integration. `autosign()`
exists only where a framework exposes a single global tool-decorator to patch;
for frameworks whose tools are plain functions, `protect([...])` is the
equivalent one-liner.

| Integration | `protect` | `@signed` | `autosign()` | why |
| --- | --- | --- | --- | --- |
| CrewAI | ✅ | ✅ | ✅ | patches `crewai.tools.tool` |
| LangChain | ✅ | ✅ | ✅ | patches `langchain[_core].tools.tool` |
| AutoGPT | ✅ | ✅ | ✅ | patches `autogpt.command_decorator.command` |
| AutoGen | ✅ | ✅ | — | tools are plain functions; no decorator |
| Vertex AI | ✅ | ✅ | — | tools are plain functions; no decorator |
| Google (Vertex Agent Builder) | ✅ | ✅ | — | tools are plain functions; no decorator |
| Google ADK | ✅ (`protect_tools`) | — | — | tools are plain functions; no decorator |

The old LLM-driven "mint a token" tools (`sign_request`, `VouchSignerTool`,
`sign_action`, `sign_with_vouch`, `VertexAISigner`, …) have been **removed** —
they were never depended on, and deterministic signing replaces them entirely.

Verify-side and non-tool-call integrations (Vouch Shield, the MCP server, the
Hasura webhook, n8n, Streamlit) consume these credentials rather than producing
them, and are unchanged.
