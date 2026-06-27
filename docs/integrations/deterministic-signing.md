# Deterministic signing for agent tool calls

> Wrap a tool once. Every call is signed before it runs. The model never has to
> remember to sign.

## The problem with the old integrations

Every framework adapter used to ship a *"make a token"* tool - `sign_request`
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

### Tier 1 - `protect([...])` (one line)

```python
from vouch import protect            # or: from vouch.integrations.crewai import protect

agent = Agent(role=..., goal=..., tools=protect([charge_invoice, send_email]))
```

### Tier 2 - `@signed` (one decorator)

```python
from vouch import signed

@signed(action="charge", target="api.payments.example.com")
def charge_invoice(invoice_id, amount):
    ...
```

### Tier 3 - `autosign()` (near-zero, framework-wide)

```python
import vouch.integrations.crewai as vc
vc.autosign()                         # every @tool defined afterward is signed

@tool("Charge Invoice")               # signed transparently
def charge_invoice(...): ...
```

## From zero to signed in one command

```bash
vouch init --yes              # provision an identity, no prompts
```

`vouch init` provisions an identity and persists it to the keystore. With
`--yes` (or any non-interactive shell - CI, pipes) it never stops to prompt for
a passphrase, and it prints the one line to wire it in:

```python
from vouch import protect
agent.tools = protect([your_tool, another_tool])
```

That's the whole setup: identity is resolved automatically from the keystore (see
below), so no environment variables or key plumbing are needed in agent code.

## Identity is resolved automatically

You set identity up once with `vouch init` (or `VOUCH_PRIVATE_KEY` /
`VOUCH_DID`). `resolve_signer()` then finds it in this order:

1. an explicit `signer=` argument,
2. the `VOUCH_PRIVATE_KEY` + `VOUCH_DID` environment variables,
3. the on-disk keystore at `~/.vouch/keys` (first unencrypted identity),
4. an ephemeral key, **only** if `VOUCH_AUTO_IDENTITY` is set (logged loudly).

If no identity is found, calls run **unsigned** with a warning rather than
crashing the agent - fail-open on availability, never silent on security.

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

Verify it on the receiving end in one line - the counterpart to `protect()`:

```python
import vouch

ok, passport = vouch.verify(cred)                 # auto-resolves the issuer key
ok, passport = vouch.verify(cred, public_key=k)   # or offline, with a known key
ok, passport = vouch.verify()                      # or just verify the last signed call
```

`vouch.verify` resolves the issuer's key from trusted roots or `did:web`
automatically; pass `public_key=` for offline verification, or `credential=None`
to verify whatever was most recently signed in this context.

A tool can also opt in to *seeing* its own credential by declaring a
`vouch_credential` keyword - the wrapper injects it automatically:

```python
@signed
def charge_invoice(invoice_id, amount, vouch_credential=None):
    ...   # vouch_credential is the signed VC for this call
```

## Delegation: principal → agent in one line

A human (or supervisor agent) grants a worker narrow authority; the worker's
every signed action is automatically chained under that grant, and the protocol
enforces that a worker can only *narrow* the authority, never widen it
(Specification §9.3).

```python
import vouch

# The principal delegates, once:
grant = vouch.delegate(
    action="charge", target="api.payments.example.com",
    resource="invoices", to=agent_did, signer=principal_signer,
)

# The agent's tools are chained under the grant, once:
agent.tools = vouch.protect([charge_invoice], parent=grant)
```

Now every call the agent makes carries the delegation chain back to the
principal. A call that tries to act outside the grant (`resource="payroll"` when
the grant was `"invoices"`) fails the narrowing rule: no widened credential is
ever minted, so a verifier/gate rejects it. `parent=` works on `protect`,
`@signed`, and `sign_intent` alike. See `examples/05_integrations/04_delegation.py`.

## Server side: one-line gate

The production counterpart to `protect()`. Instead of hand-writing header
parsing + `verify_credential` + 401 in every endpoint, add one dependency:

```python
from fastapi import Depends, FastAPI
from vouch.integrations.fastapi import VouchGate

app = FastAPI()
gate = VouchGate(require_action="charge")     # auto-resolves issuers via did:web

@app.post("/charge")
async def charge(passport = Depends(gate)):    # rejects unsigned/untrusted callers
    return {"agent": passport.iss}
```

`VouchGate` reads the credential from the `Vouch-Credential` header (falling back
to the request body), verifies it, optionally enforces intent
(`require_action` / `require_target` / `require_resource`), and raises 401
(missing/invalid) or 403 (intent not allowed) before your handler runs. It is a
thin shell over the framework-agnostic `vouch.gate.CredentialGate`, which any web
framework can use:

```python
from vouch.gate import CredentialGate

gate = CredentialGate(trusted_keys={issuer_did: issuer_key})  # offline allowlist
result = gate.check(incoming_credential)
if not result.ok:
    reject(result.reason)
agent_did = result.passport.iss
```

## Runtime protection in one line: `Shield.guard`

The full `Shield` is configurable (trust registry, capability files, per-call
token threading). For the common case you want none of that - just sign every
call, allow only the tools you granted, and keep an audit trail:

```python
from vouch.shield import Shield

agent.tools = Shield.guard([charge_invoice, send_email])
```

No config files. Each call is signed (outbound identity), checked against a tool
allowlist (default: exactly the tools you passed, so the agent can't be steered
into a tool you never granted), and written to a tamper-evident audit log. A
disallowed call raises `PermissionError` (or returns `None` with
`on_block="skip"`). It composes with everything above - pass `sign=False` if the
tools are already `protect()`-ed.

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
| AutoGen | ✅ | ✅ | ✅ | patches `autogen.register_function` |
| Vertex AI | ✅ | ✅ | - | tools are plain functions; no decorator |
| Google (Vertex Agent Builder) | ✅ | ✅ | - | tools are plain functions; no decorator |
| Google ADK | ✅ (`protect_tools`) | - | - | tools are plain functions; no decorator |

The old LLM-driven "mint a token" tools (`sign_request`, `VouchSignerTool`,
`sign_action`, `sign_with_vouch`, `VertexAISigner`, …) have been **removed** -
they were never depended on, and deterministic signing replaces them entirely.

Verify-side and non-tool-call integrations (Vouch Shield, the MCP server, the
Hasura webhook, n8n, Streamlit) consume these credentials rather than producing
them, and are unchanged.
