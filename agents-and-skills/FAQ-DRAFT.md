# FAQ Draft (NOT PUBLISHED — awaiting your approval)

Proposed FAQ entries for the website's `faq-data.ts`. Show the user this
file before merging into the live FAQ. Each entry is in the same shape
as existing entries (q + a fields). Sections are grouped roughly by
the live FAQ's existing categories.

---

## Sidecars (which language to run)

**Q: What is the Vouch sidecar?**
A: A separate process that holds the agent's signing key and exposes a
small HTTP API (`/sign`, `/did`, `/health`). The LLM-running process
calls it for signatures. Because the key lives in a different process
from the LLM, prompt injection cannot exfiltrate what is not there.

**Q: Vouch ships sidecars in Go, Python, and TypeScript. Which one
should I run?**
A: They are tiered:

| Tier | Language | Use case |
|---|---|---|
| Production | **Go** | Real deployments. Small static binary, KMS / HSM keys, FIPS path in Pro tier. |
| Lightweight | **Python** | Self-hosted, non-regulated stacks already in Python. File or env keys. |
| Lightweight | **TypeScript** | Self-hosted Node stacks. File or env keys. |
| Dev | **Python `dev_sidecar`** | Local iteration with an ephemeral in-memory key. Never for production. |

If your auditor will ask about the sidecar, you should be running the
Go one. For everything else, pick the language you already deploy.

**Q: Why are the Python and TypeScript sidecars minimal?**
A: The sidecar is security-critical; smaller code surface is safer.
Python and TS sidecars implement the bare minimum to be useful (sign
intents with Ed25519, return the credential) and intentionally leave
out features like hybrid post-quantum, KMS integration, sensitive-mode
JWE wrapping, and Heartbeat validation. When you need those, switch
to the Go sidecar.

**Q: How do I pick between Python and TypeScript for the lightweight
tier?**
A: Pick whichever runtime your existing application uses. There is no
protocol-level difference — both pass the same contract test suite.

**Q: Can I run all three side by side?**
A: Yes, but you should not. They serve the same role. Run one, decide
the tier, and stick with it. Each agent gets exactly one sidecar.

**Q: Do all three sidecars produce byte-identical credentials?**
A: Credentials are semantically equivalent across all three (same VC
shape, same `eddsa-jcs-2022` cryptosuite, same JCS canonicalization).
A cross-language contract test suite enforces this on every release.

**Q: Can the sidecar run as a serverless function (Lambda, Cloud Run)?**
A: Yes for the Go sidecar — it's a static binary and starts in
milliseconds. The Python and TS sidecars work as serverless too but
their cold-start latency makes them less suited to high-frequency
signing. For agent workloads (one credential per minute), any of them
is fine.

---

## Vouch Agent (the chat assistant)

**Q: What is the Vouch Agent?**
A: A chat assistant that lives on the Vouch website and inside the
mobile app. It answers questions about the protocol using the canonical
docs and signs a Vouch credential for any action it takes on your
behalf. The agent is open source under `website-agent/` in the
repository.

**Q: Which LLM providers does the Vouch Agent support?**
A: Anthropic (Claude), OpenAI (GPT), and Google (Gemini). Set
`VOUCH_LLM_PROVIDER` to `anthropic`, `openai`, or `gemini` and supply
the matching API key. The hosted instance uses Claude; self-hosters
choose what they want.

**Q: Can I run the Vouch Agent locally?**
A: Yes. Three processes:
1. The dev sidecar (`python -m vouch_agent.dev_sidecar`, port 8877)
2. The agent backend (`uvicorn vouch_agent.main:app`, port 8000)
3. A small Next.js page that mounts the chat widget (port 3200)

The repo's `website-agent/README.md` and `agents-and-skills/TESTING.md`
have step-by-step instructions.

**Q: Does the agent really sign credentials, or is it a mock?**
A: It really signs. The dev sidecar uses an ephemeral Ed25519 keypair;
the production sidecar uses a persistent KMS-backed key. The signed
credential you see in the chat UI verifies against the agent's DID
Document.

**Q: Is the agent free to use?**
A: On the public website, yes, with per-IP rate limits. For embedded
use in your own product, run the open-source backend yourself or
contact us about a managed instance.

**Q: What does the agent log?**
A: For each signed action, a small record: credential id, issuer DID,
intent, validity window, cryptosuite, verification method, and a
digest of the full credential. Logs are retained for abuse monitoring
only. Chat transcripts are not persisted beyond the active session.

**Q: Does the Vouch Agent work on mobile?**
A: Yes. The mobile app embeds the chat widget via a WebView. Mobile
actions that require device-bound evidence (camera capture, location)
sign with the device's Secure Enclave or Android Keystore rather than
the server-side sidecar.

**Q: Can the agent see my private key if I paste it?**
A: It refuses. The agent's instructions explicitly tell it to reject
pasted private keys, JWKs, mnemonics, or seed phrases, and to advise
you to rotate the corresponding key. The signed audit trail of the
refusal is visible to you.

**Q: Is the agent vulnerable to prompt injection?**
A: The LLM is, like any LLM. The architectural defense is that the
signing key lives in the sidecar process, which the LLM cannot reach.
The agent will only sign intents in a small allow-list, so even a
fully compromised LLM cannot mint arbitrary credentials.

---

## Claude Skill

**Q: What is the Vouch Protocol Claude Skill?**
A: A drop-in skill for Claude Code (the CLI) that teaches Claude the
Vouch SDK shapes, DID conventions, cryptosuite identifiers, and
integration patterns. Once installed, Claude reads the matching
reference file before answering Vouch questions, instead of guessing.

**Q: How do I install the Claude Skill?**
A: Copy the `claude-skill/` directory into your Claude skills folder:

**macOS / Linux**

```bash
mkdir -p ~/.claude/skills
cp -r claude-skill ~/.claude/skills/vouch-protocol
```

**Windows (PowerShell)**

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills"
Copy-Item -Recurse "claude-skill" "$env:USERPROFILE\.claude\skills\vouch-protocol"
```

Restart Claude Code and run `/skills`. You should see `vouch-protocol`
in the list.

**Q: Does the Claude Skill make any network calls?**
A: No. The skill ships as Markdown files; Claude reads them locally.
Nothing leaves your machine because of the skill.

**Q: Will the skill modify my code or run commands by itself?**
A: No. The skill is read-only context. It improves Claude's answers; it
does not act on your repository. Any `Edit`, `Write`, or `Bash` action
is still Claude's own decision, subject to the permissions your Claude
Code setup has.

**Q: How often does the skill update?**
A: The skill is versioned alongside the protocol. When Vouch ships a
new cryptosuite or SDK shape, `git pull` from the cloned repo and the
skill picks up the new references. We'll tag releases as the protocol
hits milestones.

**Q: Can I customize the skill for my organization?**
A: Yes. Fork `claude-skill/` and add or replace reference files
specific to your stack (your DID prefix, your verifier hostname, your
internal action vocabulary). Update `SKILL.md`'s `description` so it
also triggers on your team's terminology.

**Q: Does the skill work in Claude Desktop, the web app, or Claude in
an IDE plugin?**
A: Skills are a Claude Code (CLI) feature. On other Claude surfaces,
paste the contents of `SKILL.md` and the relevant `reference/*.md`
files into your project's Custom Instructions or system prompt; you
lose the auto-loading behavior but keep the canonical content.

**Q: What is in the skill, exactly?**
A: Eleven reference files: `python-sdk.md`, `typescript-sdk.md`,
`go-sidecar.md`, `credential-format.md`, `delegation.md`,
`post-quantum.md`, `revocation.md`, `state-verifiability.md`,
`integrations.md`, `sidecar.md`, and `troubleshooting.md`. Plus
`SKILL.md` (the manifest) and `README.md` (install steps).

---

## OpenAI Custom GPT

**Q: Where is the Vouch Protocol Custom GPT?**
A: We publish the configuration in the repo at `openai-gpt/`. Build
your own GPT by pasting the instructions and uploading the knowledge
files. We do not host a single shared GPT, so anyone who needs one
builds and owns their own.

**Q: Why not host a shared Custom GPT?**
A: Custom GPTs are tied to an OpenAI account, cannot be forked, and
change owner with acquisitions. Publishing the source-of-truth in the
repo lets your team build a version it controls, audits, and updates.

**Q: How do I build the GPT?**
A: Open https://chatgpt.com/gpts/editor, click Create, switch to the
Configure tab, then paste:
- Name -> `openai-gpt/name.txt`
- Description -> `openai-gpt/description.txt`
- Instructions -> `openai-gpt/instructions.md`
- Conversation starters -> each line from `openai-gpt/conversation-starters.md`
- Knowledge -> upload everything from `openai-gpt/knowledge/`
- Actions (optional) -> paste `openai-gpt/actions.yaml`, configure auth
  per `actions-auth.md`. Save.

**Q: Does the Custom GPT sign credentials?**
A: Only if you wire up Actions. With Actions enabled, the GPT calls the
hosted Vouch agent's `/sign` endpoint for a small allow-list of
intents. The sidecar holds the key; the GPT and ChatGPT itself never
see it.

**Q: Can I run the GPT without ChatGPT Plus?**
A: Custom GPTs require ChatGPT Plus, Team, or Enterprise. The Vouch
content also works as plain instructions you paste into a free ChatGPT
session — you lose the Knowledge file feature but get the same
guidance.

**Q: Can I keep the GPT private to my team?**
A: Yes. In the GPT builder's Save dialog, choose "Only me" (private),
"Anyone with the link" (semi-private), or "Public" (listed in the GPT
Store). For teams, "Anyone with the link" plus circulating the URL is
the common pattern.

**Q: How do I keep the GPT updated?**
A: When Vouch ships a new SDK shape or cryptosuite identifier, pull
the latest `openai-gpt/` from the repo, reopen your GPT in the editor,
and replace the knowledge files (the builder deduplicates by filename).
Bump the version note in your custom Instructions if you fork them.

**Q: Will the GPT leak my conversations to OpenAI for training?**
A: That is governed by your OpenAI account settings, not Vouch. Check
"Data Controls" in your ChatGPT settings; team and enterprise tiers
have organisation-level opt-out.

---

## Gemini Gem

**Q: What is the Vouch Protocol Gemini Gem?**
A: A Gem (Google's Custom GPT equivalent) configured for Vouch. It
helps developers integrate Vouch and uses Google Workspace tools
(Docs, Sheets, Gmail, Calendar, Search) when you ask it to.

**Q: How do I create the Gem?**
A: Open https://gemini.google.com/gems/create. Click "New Gem". Paste:
- Name -> `gemini-gem/name.txt`
- Description -> `gemini-gem/description.txt`
- Instructions -> `gemini-gem/instructions.md`
- Knowledge -> upload all files from `gemini-gem/knowledge/`
- Examples (optional) -> the prompts in `gemini-gem/examples.md`. Save.

**Q: Does the Gem require Gemini Advanced?**
A: For the full ten-file knowledge corpus and long context, yes. The
free tier supports Gems with a smaller knowledge attachment; trim to
the most relevant four files (`overview.md`, `quickstart.md`,
`credential-format.md`, `troubleshooting.md`) for the free tier.

**Q: Can my whole Workspace organisation use the Gem?**
A: Yes, on Workspace plans that include Gemini for Workspace. The Gem
creator can share to the org from the share dialog; admins can install
it for all users. Check with your Workspace admin for the org's
sharing policy.

**Q: Does the Gem work on the Gemini mobile app?**
A: Yes. Saved Gems appear in the mobile app's Gem picker; the same
knowledge corpus and instructions apply.

**Q: What can the Gem do that the Custom GPT cannot?**
A: The Gem has native Google Workspace tools. It can draft a Google
Doc with a quickstart, summarize a Sheet of credentials, or compose a
Gmail draft, all within the Gemini surface. The Custom GPT relies on
Actions for any external write.

**Q: Will the Gem create Docs or send emails without asking?**
A: No. The instructions explicitly require confirmation before any
Workspace write. The Gem will draft, show you the draft, then ask
before creating or sending.

**Q: How do I update the Gem?**
A: Pull the latest `gemini-gem/` from the repo. In the Gem editor,
remove the old knowledge files, upload the new ones, save. Gemini
deduplicates by filename so the upload replaces in place.

---

## Hosted agent

**Q: What is https://agent.vouch-protocol.org?**
A: The hosted instance of the Vouch Agent. It powers the chat
assistant on the website and exposes a small public API (`/chat`,
`/sign`, `/audit`, `/healthz`). The same code is open source under
`website-agent/` so you can self-host.

**Q: Can I point my own Custom GPT or Gem at the hosted agent?**
A: Yes for read endpoints (`/audit`, `/healthz`). For `/sign`, the
hosted agent rate-limits anonymous traffic and only signs intents in
its allow-list. For higher quota, contact us about a managed instance.

**Q: What signing key does the hosted agent use?**
A: A did:web DID rooted at vouch-protocol.org. The DID Document is
public at https://vouch-protocol.org/.well-known/did.json. Verification
methods rotate quarterly; the prior keys remain in the document for
the lifetime of credentials they signed.

**Q: How is the hosted agent's sidecar deployed?**
A: It runs the Go sidecar with a KMS-backed key in a Kubernetes pod
alongside the agent. The agent container has no access to the key
material; it speaks to the sidecar over loopback HTTP.

---

## Privacy & safety

**Q: Can the Vouch Agent see my private keys or credentials?**
A: It only sees what you type in chat. It refuses to operate on pasted
keys, JWKs, or mnemonics, and tells you to rotate the corresponding
key.

**Q: Is the agent vulnerable to prompt injection?**
A: The LLM is, like any LLM. Vouch's defense is defense-in-depth: the
signing key is in the sidecar process, isolated from the LLM. Even a
fully compromised LLM cannot leak a key it never had, and cannot mint
intents outside the sidecar's allow-list.

**Q: How do I report abuse of the hosted agent?**
A: Open an issue at https://github.com/vouch-protocol/vouch/issues with
the credential id (from the audit log) if you have it. We will
investigate within five business days.

---

## Notes for the user reviewing this draft

- "https://agent.vouch-protocol.org" is the proposed hostname for the
  hosted agent; substitute the actual host once you provision it.
- The "30-day retention for abuse monitoring" claim is a placeholder;
  set this to whatever policy you intend to publish.
- The "Pro tier adds FIPS 140-3" line is a future commitment;
  reword if you don't want a public timeline pinned here.
- The Workspace org-share answer assumes Vouch is not the Workspace
  admin; if you publish under a Vouch-owned Workspace, you may also
  want to add a "How do I get added?" entry.
- Numbers (eleven reference files, ten knowledge files, three
  processes) should be re-verified against the package contents before
  publication.
