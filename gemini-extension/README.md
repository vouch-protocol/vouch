# Vouch Protocol Gemini Extension

A [Gemini CLI extension](https://github.com/google-gemini/gemini-cli) that
gives Gemini cryptographic identity tools for AI agents, backed by the
Vouch Protocol. It bundles the `vouch-mcp` MCP server, a context file, and
custom `/vouch:*` commands.

## What this is — and what it is not

Gemini has several "extension"-shaped surfaces. They are not the same
thing, and only one of them is something a project can ship itself:

| Surface | Self-serve? | What you build |
|---|---|---|
| **Gemini CLI extension** (this folder) | ✅ Yes | `gemini-extension.json` + MCP server + commands |
| **Gemini API / Vertex AI function calling** | ✅ Yes | An OpenAPI/function spec your *own* app passes to the model — see `../openai-gpt/actions.yaml` |
| **Gemini Gem** | ✅ Yes | Persona + knowledge, no API calls — see `../gemini-gem/` |
| **Consumer Gemini app `@`-extension / "Connected Apps"** | ❌ No | Google-curated business partnership; there is no developer console to upload an OpenAPI spec and get a public `@Vouch` toggle |

This package is the **Gemini CLI extension**: the genuine, file-based,
self-serve "Gemini Extension." It lets a developer install Vouch into
their Gemini CLI and invoke it through the bundled MCP tools and commands.

## Files

- `gemini-extension.json` — the extension manifest (name, version, the
  `vouch` MCP server, and the context file name)
- `GEMINI.md` — context injected into the model so Gemini knows the tools,
  the safety rules, and the decision rules
- `commands/vouch/*.toml` — custom slash commands: `/vouch:sign`,
  `/vouch:identity`, `/vouch:session`

## Prerequisites

```bash
pip install vouch-protocol   # installs the `vouch` CLI and `vouch-mcp` server
vouch init --env             # prints VOUCH_DID and VOUCH_PRIVATE_KEY exports
```

Export the two values in the shell that launches Gemini CLI (or set them
in your shell profile). The MCP server signs locally with these; **no key
material is sent to the model.** Without them the signing tools return a
configuration error and the read-only `get_identity` tool reports
"Not configured."

## Install

Install from this directory (local checkout):

```bash
gemini extensions install /path/to/vouch/gemini-extension
```

Or from the repository:

```bash
gemini extensions install https://github.com/vouch-protocol/vouch \
  --path gemini-extension
```

Then start Gemini CLI. Confirm the extension loaded:

```bash
gemini extensions list
```

## Use

```text
/vouch:identity                         # show your agent DID and status
/vouch:sign send_payment to acme.example   # sign an action intent
/vouch:session email_management         # mint a multi-action session token
```

Or just ask in natural language — the model has the tools and will call
them, e.g. *"Sign my intent to read the calendar before we make the API
call."*

## MCP tools exposed

| Tool | Purpose |
|---|---|
| `sign_action` | Sign an `intent` (+ optional `target`) → `Vouch-Token` header |
| `get_identity` | Report the agent DID, auto-sign status, session state |
| `create_session` | Mint a session token for a multi-action `purpose` |

These come from the `vouch-mcp` server defined at
`vouch/integrations/mcp/server.py` and exposed via the `vouch-mcp` console
script (`pyproject.toml` → `[project.scripts]`).

## Updating

When the protocol, SDK, or MCP tools change:

1. Bump `version` in `gemini-extension.json`.
2. Refresh tool descriptions in `GEMINI.md` to match
   `vouch/integrations/mcp/server.py`.
3. Re-run `gemini extensions install --force` (or `update`).

## Downstream subscriber

a downstream product is a separate product that subscribes to Vouch's CA; it is
not part of this repository. To give downstream the same Gemini CLI extension,
replicate this folder in the downstream repo, point `mcpServers` at downstream's own
MCP server, and adapt `GEMINI.md` to downstream's tool surface.

## Links

- Gemini CLI: https://github.com/google-gemini/gemini-cli
- MCP quickstart: ../docs/mcp-quickstart.md
- Repo: https://github.com/vouch-protocol/vouch
