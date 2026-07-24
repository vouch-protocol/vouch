# AI Assistants: Claude Skill, OpenAI GPT, Gemini Gem, Vouch Assistant

Vouch ships four AI surfaces that help developers integrate the protocol.
They share one canonical knowledge base, so answers are consistent
across them.

## Comparison at a glance

| Tool | Where it runs | Best for | Limitations |
|---|---|---|---|
| Claude Skill | Claude Code (CLI) | Hands-on integration: edits files, runs commands, audits your repo. | CLI-only today. |
| Vouch Assistant | Vouch website + mobile app | Quick Q&A in the browser; signs real Vouch credentials live. | No access to your local code. |
| OpenAI Custom GPT | ChatGPT (Plus / Team / Enterprise) | Familiar UI for ChatGPT users. Optional Actions integration calls the hosted assistant to sign. | Requires a paid ChatGPT plan. |
| Gemini Gem | Gemini (Free / Advanced / Workspace) | Google Workspace tools (Docs, Sheets, Gmail, Search). | No programmatic Actions. |

## Claude Skill

A drop-in skill for Claude Code that teaches Claude the Vouch SDK
shapes, DID conventions, cryptosuite identifiers, and integration
patterns. The skill is a directory of Markdown reference files;
Claude reads the matching file before answering Vouch questions.

### Install

**macOS / Linux**

```bash
mkdir -p ~/.claude/skills
cp -r ~/vouch-protocol/claude-skill ~/.claude/skills/vouch-protocol
```

**Windows (PowerShell)**

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills"
Copy-Item -Recurse "$env:USERPROFILE\vouch-protocol\claude-skill" "$env:USERPROFILE\.claude\skills\vouch-protocol"
```

Restart Claude Code and run `/skills` to confirm. You should see
`vouch-protocol` listed.

### How it triggers

Phrases that load the skill: `vouch-protocol`, `did:web`, `eddsa-jcs-2022`,
`mldsa44-jcs-2024`, `BitstringStatusList`, `SessionVoucher`,
`Heartbeat Protocol`, and natural-language variants like "sign a credential
with Vouch" or "verify a Vouch credential".

### What's in the skill

Eleven reference files: `python-sdk.md`, `typescript-sdk.md`,
`go-sidecar.md`, `credential-format.md`, `delegation.md`,
`post-quantum.md`, `revocation.md`, `state-verifiability.md`,
`integrations.md`, `sidecar.md`, `troubleshooting.md`. Plus
`SKILL.md` (the manifest) and `README.md` (install steps).

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

The skill versions with the protocol. Pull whenever Vouch releases
a new cryptosuite or SDK shape.

### Claude Desktop / web app

Skills are a Claude Code (CLI) feature. On the Desktop or web app,
paste the contents of `SKILL.md` and the relevant `reference/*.md`
files into your project's Custom Instructions or system prompt.

## OpenAI Custom GPT

We publish the GPT's configuration in the `openai-gpt/` directory of
the repo. You build your own GPT by pasting the instructions and
uploading the knowledge files. We do not host a shared GPT, so anyone
who needs one builds and owns their own.

### Build steps

1. Open https://chatgpt.com/gpts/editor and click Create.
2. Switch to the Configure tab.
3. Paste: Name (from `name.txt`), Description (from `description.txt`),
   Instructions (from `instructions.md`), Conversation starters (one
   per line from `conversation-starters.md`).
4. Upload all files in `openai-gpt/knowledge/` to the Knowledge section.
5. Capabilities: enable Web Browsing and Code Interpreter.
6. Optionally add Actions: paste `actions.yaml`, configure auth per
   `actions-auth.md`. This lets the GPT call the hosted Vouch
   Assistant's `/sign` endpoint.
7. Save as Only me (private), Anyone with the link, or Public.

### Why publish the config instead of a shared GPT

Custom GPTs are tied to an OpenAI account, change owner with
acquisitions, and cannot be forked. Publishing the source-of-truth in
the repo lets each team build a version it controls, audits, and updates.

### Requires

ChatGPT Plus, Team, or Enterprise. The Vouch content also works as
plain instructions in a free ChatGPT session, you just lose the
Knowledge file feature.

## Gemini Gem

A Gem (Google's Custom GPT equivalent) configured for Vouch. It uses
Google Workspace tools when relevant: Docs, Sheets, Gmail, Calendar,
Search.

### Build steps

1. Open https://gemini.google.com/gems/create and click New Gem.
2. Paste: Name (from `gemini-gem/name.txt`), Description, Instructions
   (from `gemini-gem/instructions.md`).
3. Upload all files in `gemini-gem/knowledge/` (up to ten knowledge files).
4. Add the prompts from `examples.md` as the Gem's Examples.
5. Preview, then Save & share (Private / Anyone with link / Workspace org).

### Tier compatibility

- Free tier: smaller knowledge attachment. Trim corpus to four files:
  `overview.md`, `quickstart.md`, `credential-format.md`, `troubleshooting.md`.
- Gemini Advanced / Google AI Pro: full ten-file corpus.
- Workspace plans: full corpus plus org-wide sharing through the admin
  console.

### What the Gem does that the GPT cannot

Native Google Workspace tools. The Gem can draft a Google Doc with a
quickstart, summarize a Sheet of credentials, or compose a Gmail draft,
within the Gemini surface. The GPT relies on Actions for any external
write.

The Gem confirms before any Workspace write. It will draft, show you
the draft, then ask before creating or sending.

## Vouch Assistant (the chat on the website)

The chat helper on vouch-protocol.com and the mobile app. Answers
questions about Vouch and signs real Vouch credentials when you ask
it to. It is open source under `website-agent/` in the repo.

### Built from

- LLM: Google Gemini 2.5 Flash (configurable: Anthropic, OpenAI, Gemini)
- RAG: in-process TF-IDF index over the canonical docs
- Web framework: FastAPI streamed via Server-Sent Events
- Signing: the Vouch Python SDK behind a small dev sidecar
- Frontend: a React chat component mounted in the Next.js site
- Audit log: append-only JSONL of every signed credential

### What it can do

- Answer questions about the protocol, SDKs, and integrations from
  the canonical docs.
- Walk through verification errors step by step.
- Sign a real Vouch credential for a small allow-list of demo actions:
  answer_question, share_quickstart, generate_starter, open_github_issue,
  send_email. Each signed credential renders inline as a card with the
  issuer DID, intent, cryptosuite, and a Show raw JSON toggle.

### Privacy and safety

- The assistant only sees what you type in chat.
- It refuses to operate on pasted private keys, JWKs, or mnemonics, and
  advises you to rotate the corresponding key.
- The signing key never enters the LLM process. It lives in the sidecar.
  Even if a prompt-injection attack convinces the LLM to leak the key,
  there is no key in the LLM process to leak.
- The assistant only signs intents in a small allow-list, so the LLM
  cannot mint arbitrary credentials.

### Run it yourself locally

Three processes:
1. Sidecar: `python -m vouch_agent.dev_sidecar --did did:web:agent.example.com --port 8877`
2. Backend: `uvicorn vouch_agent.main:app --host 127.0.0.1 --port 8000`
3. Frontend: copy the React widget into your Next.js site, or use the
   standalone harness under `website-agent/standalone/` on port 3200.

Set `VOUCH_LLM_PROVIDER` to `anthropic`, `openai`, or `gemini`, and the
matching API key.

## Which one should I use?

- You're integrating Vouch into your code right now -> **Claude Skill**
- You want to try Vouch in your browser, fast -> **Vouch Assistant**
- Your team lives in ChatGPT -> **OpenAI Custom GPT**
- Your team lives in Google Workspace -> **Gemini Gem**

All four route to the same documentation, so answers are consistent.
Pick the one that fits your daily tool.
