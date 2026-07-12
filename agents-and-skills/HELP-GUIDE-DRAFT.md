# Help Guide Draft (NOT PUBLISHED: awaiting your approval)

Long-form help content for the website. Probable home: a new page under
`/help/ai-assistants` (or merged into the existing `/help` route) for
the four AI surfaces, plus a section in `/help/sidecars` for sidecar
tiering. Show the user this file before merging.

---

# Part 1: Pick your sidecar

The Vouch sidecar holds the agent's signing key. Three implementations
ship today (Go, Python, TypeScript) and they are not interchangeable in
production. Pick by use case, not by language preference.

## The tier table

| Tier | Language | Use case | Key storage | When to pick |
|---|---|---|---|---|
| Production | **Go** | Real deployments | KMS / HSM / file | You will be audited. You want a small static binary. You need FIPS 140-3, sensitive-mode JWE, or KMS integration. |
| Lightweight | **Python** | Self-hosted, non-regulated | File or env | Your stack is already Python; ops simplicity matters more than minimal attack surface. |
| Lightweight | **TypeScript** | Self-hosted, non-regulated | File or env | Your stack is already Node; you want the sidecar in the same runtime family. |
| Dev | **Python `dev_sidecar`** | Local development only | Ephemeral, in-memory | You are iterating on the SDK or building a demo. Never run in production. |

Rule of thumb: **if your auditor will ask about the sidecar, run the
Go one.**

## Why the tiering

The sidecar is security-critical. The smaller and more auditable its
code surface, the better it does its job (which is to hold the signing
key away from the LLM). The Go binary is a few thousand lines of
audited code with no runtime dependencies; the Python and TypeScript
sidecars necessarily bring in their language runtimes and a web
framework. That is a real difference.

We ship Python and TypeScript sidecars anyway because:
- Local development should not require installing a Go toolchain.
- Operationally simpler one-language stacks are valuable for teams who
  cannot adopt Go for sidecar deployment.
- Reference implementations in three languages prove the protocol is
  not tied to one runtime.

## What stays out of the lightweight sidecars

To keep them minimal, the Python and TypeScript sidecars intentionally
omit:

- Hybrid post-quantum signing (`hybrid-eddsa-mldsa44-jcs-2026`)
- KMS / HSM key integration
- Sensitive-mode JWE wrapping (ML-KEM 768)
- Heartbeat session validation
- Multi-tenancy (one DID per sidecar process)

If you need any of those, switch to the Go sidecar. That switch is the
design intent, not a workaround.

## Cross-language equivalence

All three sidecars expose the same HTTP API:

- `GET  /health`: liveness probe
- `GET  /did`: the sidecar's DID
- `GET  /.well-known/did.json`: DID Document (optional, dev-friendly)
- `POST /sign`: sign an intent, return a Verifiable Credential

A contract test suite (`test-vectors/sidecar-contract/`) verifies that
each implementation accepts and rejects the same inputs and emits
semantically equivalent credentials. CI runs the suite against all
three on every commit.

## Switching tiers

The HTTP API is identical, so an agent that talks to the Python sidecar
can talk to the Go sidecar with one env-var change:

**macOS / Linux**

```bash
export VOUCH_SIDECAR_URL=http://localhost:8877  # same on all three
```

**Windows (PowerShell)**

```powershell
$env:VOUCH_SIDECAR_URL = "http://localhost:8877"  # same on all three
```

The agent code does not change. The DID changes (production agents use
a real did:web rooted on your domain), and the key material changes
(production loads from KMS).

---

# Part 2: Use the Vouch AI assistants

Vouch ships four AI surfaces. Pick the one that matches the tool you
already use; all four route to the same canonical documentation.

## Comparison at a glance

| Tool | Where it runs | Strengths | Limitations |
|---|---|---|---|
| Claude Skill | Claude Code (CLI) | Reads your local repo, edits files, runs commands. Best for hands-on integration. | CLI-only today; Desktop and web require manual paste. |
| Vouch Agent | Vouch website + mobile app | Streams answers in the browser. Signs real Vouch credentials. Live demo of the protocol. | Read-only on the docs; no access to your local code. |
| OpenAI Custom GPT | ChatGPT (Plus/Team/Enterprise) | Familiar UI for ChatGPT users. Optional Actions integration calls the hosted Vouch agent to sign. | Requires a paid ChatGPT plan for full Custom GPT features. |
| Gemini Gem | Gemini (Free/Advanced/Workspace) | Built-in Google Workspace tools (Docs, Sheets, Gmail, Search). Output lands in your Workspace. | No programmatic Actions; for signing you run the SDK locally. |

## Choose the right one

- You're integrating Vouch into your code right now → **Claude Skill**
- You want to try Vouch in your browser, fast → **Vouch Agent**
- Your team lives in ChatGPT → **OpenAI Custom GPT**
- Your team lives in Google Workspace → **Gemini Gem**

---

## Walkthrough: Claude Skill

### Install

```bash
# Linux / macOS / WSL
git clone https://github.com/vouch-protocol/vouch
cp -r vouch/claude-skill ~/.claude/skills/vouch-protocol
```

```powershell
# Windows PowerShell
git clone https://github.com/vouch-protocol/vouch
Copy-Item -Recurse vouch\claude-skill "$env:USERPROFILE\.claude\skills\vouch-protocol"
```

Restart Claude Code and run `/skills`. You should see `vouch-protocol`
in the list.

### When it triggers

The skill watches for phrases like `vouch-protocol`, `did:web`,
`eddsa-jcs-2022`, `BitstringStatusList`, `SessionVoucher`. When any of
those (or natural-language variants) appear in your prompt, Claude
opens the matching `reference/*.md` file before answering.

### Sample session

```
You: I want to sign a Vouch credential in Python and verify it.

Claude: [reads reference/python-sdk.md]
Here is a minimal end-to-end example.

  from vouch import Signer, Verifier, build_vouch_credential
  ...

Verifier returns result.ok == True. The credential carries a
proof.cryptosuite of eddsa-jcs-2022 by default.
```

### Customise for your team

Fork the `claude-skill/` directory and add references specific to your
stack: your DID prefix, your verifier hostname, your internal action
vocabulary. Update `SKILL.md`'s description string so it also triggers
on your team's terminology.

### Updating

**macOS / Linux**

```bash
cd ~/.claude/skills/vouch-protocol
git pull
```

**Windows (PowerShell)**

```powershell
cd $env:USERPROFILE\.claude\skills\vouch-protocol
git pull
```

The skill versions with the protocol. Pull whenever Vouch releases a
new cryptosuite or SDK shape.

### Troubleshooting

- **Skill does not appear in `/skills`**: check that
  `~/.claude/skills/vouch-protocol/SKILL.md` exists and starts with a
  valid YAML frontmatter block.
- **Claude does not use the skill on a Vouch question**: paste
  `SKILL.md` back into Claude and ask "Why did you not use this skill?"
  It will usually identify the gap.
- **Skill works but answers are stale**: pull the latest, then run
  `/skills reload` (or restart Claude Code).

---

## Walkthrough: Vouch Agent

### Where to find it

On the website, the "Ask the agent" widget is mounted on every docs
page and on the homepage. On the mobile app, it's the Help tab.

### What it can do

- Answer questions about the protocol, SDKs, and integrations using
  the canonical docs.
- Walk you through verification errors step by step.
- Sign a real Vouch credential for a small set of demo actions
  (`answer_question`, `share_quickstart`, `generate_starter`,
  `open_github_issue`, `send_email`). Each signed credential renders
  in a card with the issuer DID, intent, cryptosuite, and a "Show raw
  JSON" toggle.

### Demo: signing a credential

1. Open the chat.
2. Type "Share the Python quickstart with me by email at me@example.com".
3. The agent summarises the intent (action, target, resource) and asks
   you to confirm.
4. On confirmation, the assistant signs the credential, shows you the
   `proofValue`, and only then sends the email.
5. Click "Show raw JSON" on the credential card to copy and verify it
   yourself with `vouch verify` or the SDK.

### Self-host the agent locally

Three processes, three terminals.

**Terminal 1: dev sidecar (ephemeral key, dev only)**

macOS / Linux

```bash
cd ~/vouch-protocol/website-agent/backend
python -m vouch_agent.dev_sidecar --did did:web:agent.example.com --port 8877
```

Windows (PowerShell)

```powershell
cd $env:USERPROFILE\vouch-protocol\website-agent\backend
python -m vouch_agent.dev_sidecar --did did:web:agent.example.com --port 8877
```

**Terminal 2: agent backend**

macOS / Linux

```bash
cd ~/vouch-protocol/website-agent/backend
cp ../.env.example ../.env   # then edit ../.env to add your LLM key
uvicorn vouch_agent.main:app --host 127.0.0.1 --port 8000
```

Windows (PowerShell)

```powershell
cd $env:USERPROFILE\vouch-protocol\website-agent\backend
Copy-Item ..\.env.example ..\.env   # then edit ..\.env to add your LLM key
uvicorn vouch_agent.main:app --host 127.0.0.1 --port 8000
```

**Terminal 3: chat widget (standalone harness)**

macOS / Linux

```bash
cd ~/vouch-protocol/website-agent/standalone
npm install
npm run dev   # http://localhost:3200
```

Windows (PowerShell)

```powershell
cd $env:USERPROFILE\vouch-protocol\website-agent\standalone
npm install
npm run dev   # http://localhost:3200
```

Browse to **http://localhost:3200**. The page shows the backend's
status, the sidecar's status, and how many knowledge chunks are
indexed. Type any question and the answer streams back with source
citations.

For production-shaped deployment, use the Go sidecar (`vouch-sidecar`)
in place of the dev sidecar, and run the agent backend behind a
reverse proxy with TLS.

### Pick an LLM provider

The agent backend supports three:

**macOS / Linux**

```bash
# Anthropic (default)
export VOUCH_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
export VOUCH_LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# Google Gemini
export VOUCH_LLM_PROVIDER=gemini
export GEMINI_API_KEY=...
```

**Windows (PowerShell)**

```powershell
# Anthropic (default)
$env:VOUCH_LLM_PROVIDER = "anthropic"
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# OpenAI
$env:VOUCH_LLM_PROVIDER = "openai"
$env:OPENAI_API_KEY = "sk-..."

# Google Gemini
$env:VOUCH_LLM_PROVIDER = "gemini"
$env:GEMINI_API_KEY = "..."
```

Or set them in `website-agent/.env` (auto-loaded on backend start).

### Troubleshooting

- **`sidecar_ok: false` in `/healthz`**: the agent backend cannot
  reach the sidecar. Verify the sidecar is listening on the port set
  in `VOUCH_SIDECAR_URL`.
- **Chat returns `error` event with "API key not set"**: set the env
  var matching your `VOUCH_LLM_PROVIDER` and restart the backend.
- **`/sign` returns 400 "not in allow-list"**: the intent's `action`
  is not one of the five allow-listed values. This is the security
  gate; add to `ALLOWED_ACTIONS` in `vouch_agent/signer.py` only after
  threat-modeling the new action.
- **CORS error in the browser**: add your origin to
  `VOUCH_CORS_ORIGINS` (comma-separated) and restart.

---

## Walkthrough: OpenAI Custom GPT

### Build your own

We do not host a shared Custom GPT. Build your own:

1. Open https://chatgpt.com/gpts/editor and click Create.
2. Switch to the Configure tab.
3. Paste:
   - Name → `openai-gpt/name.txt`
   - Description → `openai-gpt/description.txt`
   - Instructions → `openai-gpt/instructions.md`
   - Conversation starters → one per line from
     `openai-gpt/conversation-starters.md`
4. Upload all files in `openai-gpt/knowledge/` to the Knowledge section.
5. Enable Web Browsing and Code Interpreter. Leave DALL-E off.
6. (Optional) Add Actions: paste `actions.yaml`, configure auth per
   `actions-auth.md`. This lets the GPT call the hosted Vouch agent
   to sign for you.
7. Save as "Only me" first; test in the preview pane; then "Anyone with
   the link" or "Public" when you're satisfied.

### Why we publish the config instead of a shared GPT

Custom GPTs are tied to an OpenAI account, change owner with
acquisitions, and cannot be forked. Publishing the source of truth in
the repo lets your team build a version it controls, audits, and
updates.

### Keep it private to your team

In the save dialog, pick "Anyone with the link" and share the URL only
within your team. ChatGPT Team and Enterprise plans let you publish
to your org workspace, which is the cleaner option if you have it.

### Updating

When Vouch ships a new SDK shape or cryptosuite, pull the latest
`openai-gpt/` from the repo. In the GPT editor, replace the knowledge
files (the builder deduplicates by filename) and bump the version
note in the Instructions.

### Troubleshooting

- **GPT does not cite the knowledge**: the Knowledge upload may have
  failed silently. Remove all files and re-upload from `knowledge/`.
- **Actions return 401**: your Bearer token is missing or expired;
  re-check the auth config from `actions-auth.md`.
- **GPT hallucinates a method name**: the Instructions tell it not to,
  but the LLM can drift. Add a Conversation starter that explicitly
  asks for SDK shapes; that triggers the knowledge-grounded path.

---

## Walkthrough: Gemini Gem

### Build the Gem

1. Open https://gemini.google.com/gems/create.
2. Click New Gem.
3. Paste `gemini-gem/name.txt`, `description.txt`, and
   `instructions.md` into the matching fields.
4. Upload everything in `gemini-gem/knowledge/`. The Gem accepts up
   to ten knowledge files; the corpus is ten files exactly.
5. Add the lines from `examples.md` as the Gem's Examples.
6. Preview and run a test prompt.
7. Save & share (Private / People with the link / Workspace org).

### Workspace integration

Because Gems live inside Gemini, they automatically have access to
Google Workspace. The Vouch Gem is instructed to:

- Confirm before creating any Doc, Sheet, or email.
- Use Google Search when you ask about current GitHub state.

### Sample session

```
You: Draft a Google Doc explaining agent identity to a non-technical
exec.

Vouch Gem: I'll draft a Doc titled "AI Agent Identity, in plain
English." It will cover: why agents need identity, what a Vouch
credential is, the threat model, and what to ask your team. Should I
create it?

You: Yes.

Vouch Gem: [creates Doc] Created: https://docs.google.com/document/d/...
```

### Sharing to your Workspace org

In the Gem's Save dialog, pick "Visible to anyone in <your org>". The
admin in your org's Workspace console can also install Gems for all
users; check with them if you want the Gem in the default Gem picker.

### Free tier vs Advanced

Free tier supports Gems with a smaller knowledge attachment. For free
tier, trim the corpus to: `overview.md`, `quickstart.md`,
`credential-format.md`, `troubleshooting.md`. Gemini Advanced and
Workspace plans support the full ten-file corpus and long context.

### Troubleshooting

- **Gem cannot create a Doc**: your Google account does not have
  Workspace access, or the Gem permissions block writes. Check the
  Gemini permissions panel.
- **Knowledge upload silently fails**: file size limit; trim large
  reference files (split if necessary) and re-upload.
- **Gem ignores instructions**: paste the instructions into a new
  conversation and ask "Are you following these instructions?" Gemini
  occasionally needs a reminder.

---

## Update cadence (all four)

| Surface | Update method | Recommended cadence |
|---|---|---|
| Claude Skill | `git pull` in `~/.claude/skills/vouch-protocol` | Per Vouch release; instant after pull |
| Vouch Agent | Deploy from `main`; restart backend | Continuous (hosted); on demand (self-hosted) |
| OpenAI GPT | Re-upload knowledge in the GPT editor | Per Vouch release; manual |
| Gemini Gem | Re-upload knowledge in the Gem editor | Per Vouch release; manual |

Vouch tags releases that change the protocol surface. Subscribe to
release notifications on https://github.com/vouch-protocol/vouch.

---

# Part 3: Reach agents by identity (transport)

Optional. Use this when agents need to reach each other by identity rather than
by a fixed domain or IP. The identity-first resolver ships today over commodity
HTTPS, and a standard HTTP path is always there as the fallback, so it is never
all-or-nothing.

## When to use it

- Agents are ephemeral or move across hosts, so a stable domain or IP is not
  available, but a DID always is.
- You want delivery to follow the identity, with a standard HTTP path as the
  fallback for peers that have a domain.

## How it works

An agent binds its DID to its current endpoint, signs that binding with its own
key, and publishes it to a rendezvous. A sender that knows only the DID resolves
it to the endpoint and verifies the agent itself asserted the route, then
delivers. `TransportManager` tries transports in order, identity-first and then
HTTP (did:web, DNS, HTTPS); a peer that cannot be reached over one transport
falls through to the next, and `DeliveryResult.attempts` records the path taken.
The message is a `VouchEnvelope` that carries the signed credential, liability
attestations, and provenance unchanged, with a content digest checked on
receipt, so the trust properties hold whichever path delivers it.

The rendezvous is untrusted: the sender re-verifies every signed record locally
and checks its DID, so a rendezvous cannot forge a route or redirect you to a
different identity. Swapping the rendezvous for a real overlay (libp2p, or
UDNA's DHT when its baseline lands) reuses the same record format and
verification, so what you build now keeps working.

## Reach an agent by DID

```python
from vouch.transport import (
    HttpRendezvousResolver, HttpRendezvousChannel, build_route_record,
)

# The agent announces its current inbox, signed under its DID.
resolver = HttpRendezvousResolver("https://rendezvous.example.com")
await resolver.announce(build_route_record(
    did=agent_did, endpoint="https://agent.example/inbox", private_key=agent_ed25519,
))

# A sender that knows only the DID resolves it and delivers, verifying locally.
channel = HttpRendezvousChannel(resolver)
reply = await channel.exchange(f"udna://{agent_did}/vouch.message", frame)
```

## Use the manager with HTTP fallback

```bash
pip install vouch-protocol[udna]   # optional; SDK-backed UDNA path
```

```python
from vouch.transport import TransportManager, build_envelope

envelope = build_envelope(from_did=my_did, to_did=peer_did, payload=credential)
manager = TransportManager.default(private_key_jwk=my_private_key_jwk)
result = await manager.dispatch(envelope)   # result.transport -> "udna" or "http"
```

Without the extra installed, the SDK-backed UDNA path stays dormant and dispatch
falls through to the rendezvous or HTTP, so the same code runs unchanged.

## Security note

The reference UDNA SDK (`udna_sdk` v1.0.x) authenticates the peer but does not
provide channel confidentiality yet, so do not treat a UDNA channel as private.
Vouch does not rely on it: envelope payloads are signed credentials, so their
integrity and authenticity hold end to end. For confidential payloads, encrypt
at the application layer before sealing.

---

# Notes for the user reviewing this draft

- The `/help/ai-assistants` and `/help/sidecars` routes are proposals;
  pick the actual URLs.
- Screenshots are intentionally omitted; add them after capturing
  the screens you want shown.
- The "agent.example.com" host in code blocks is a placeholder; if you
  prefer "agent.vouch-protocol.org" use that consistently. Same for
  any other example DID.
- The "Pro tier adds FIPS 140-3" line in Part 1 is a forward-looking
  commitment; reword if you don't want a public mention yet.
- Numbers (five allow-listed actions, ten knowledge files, eleven
  reference files, three processes) are tied to the current package
  contents; re-verify before publication.
- The free-tier Gemini Gem corpus trim list ({overview, quickstart,
  credential-format, troubleshooting}) is a guess at "the most useful
  four"; adjust to your judgement.
- Tone matches the rest of the docs (terse, technical, no emoji).
