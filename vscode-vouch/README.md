# Vouch Protocol for VS Code

Sign AI agent actions with verifiable credentials. The Vouch Protocol extension
puts a local-first sign + verify quickstart, an identity scaffolder, and a
one-click link to the Vouch Assistant inside VS Code, so a developer building
an AI agent never has to leave the editor to figure out the Vouch story.

## Features

### 1. Local-first quickstart insertion

Ctrl/Cmd-Shift-P → **Vouch: Insert local-first quickstart at cursor**. Pick
Python, TypeScript, or Go. The extension drops in a working sign + verify
snippet that runs entirely in your dev env — no domain, no hosting, no
internet. Replace `domain="localhost"` with your real domain when you graduate
to production.

The same snippets are also available via IntelliSense:

| Prefix | Language | What you get |
|---|---|---|
| `vouch-quickstart` | Python, TS, Go | Local-first sign + verify loop |
| `vouch-hybrid-pq` | Python | Hybrid Ed25519 + ML-DSA-44 signer |
| `vouch-middleware` | Python (FastAPI), TS (Express) | Verifier middleware |

### 2. Identity scaffolding

Ctrl/Cmd-Shift-P → **Vouch: Generate a did:web identity**. The extension
prompts for a domain (default `localhost` for dev work), opens an integrated
terminal, and runs `vouch init --domain <domain>` for you. The private key is
stored in your platform's secure key store; the DID Document is printed to
the terminal so you can publish it at
`https://<domain>/.well-known/did.json` when you are ready.

Requires the `vouch` CLI installed (`pip install vouch-protocol`).

### 3. One-click access to the Vouch Assistant

Ctrl/Cmd-Shift-P → **Vouch: Ask the assistant**. Opens
[`vouch-protocol.com/ask`](https://vouch-protocol.com/ask) in your default
browser. Retrieval-grounded answers about the spec, the SDKs, conformance
levels, and compliance mappings. Every reply is itself Vouch-signed.

### 4. Status-bar shortcut

A small `● Vouch` button on the right of the status bar opens the Vouch
command group in the command palette. Disable via
`vouch.statusBar.enabled` if you prefer a quieter status bar.

## Settings

| Setting | Default | Description |
|---|---|---|
| `vouch.statusBar.enabled` | `true` | Show the Vouch status-bar shortcut. |
| `vouch.assistant.url` | `https://vouch-protocol.com/ask` | URL for **Ask the assistant**. |

## Requirements

- VS Code 1.85 or newer.
- For the **Generate identity** command: `vouch` CLI on your `PATH`
  (`pip install vouch-protocol`).

The extension itself has zero network or filesystem side-effects unless you
explicitly invoke a command. It does NOT phone home, does NOT scan your
source automatically, and does NOT require an internet connection to insert
snippets or open a terminal.

## Roadmap

Planned for v0.2:

- Diagnostic that flags external tool calls without a Vouch wrapper in
  popular agent frameworks (LangChain, CrewAI, AutoGen, MCP). Opt-in only;
  the extension will ask before enabling.
- Allow-list autogen: scan a project for `@vouch_tool`-decorated functions
  and emit `vouch-allowlist.json` from the inventory.
- Quick-fix code actions to wrap a function with `@vouch_tool`.

## Contributing

Source under `vscode-vouch/` at
[github.com/vouch-protocol/vouch](https://github.com/vouch-protocol/vouch).
Issues: [github.com/vouch-protocol/vouch/issues](https://github.com/vouch-protocol/vouch/issues).

## License

Apache-2.0.
