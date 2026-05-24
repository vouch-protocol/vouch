# Vouch Protocol Claude Skill

A Claude Code skill that turns any Claude session into a Vouch Protocol expert.
Once installed, Claude knows the SDK shapes, the cryptosuite ids, the
DID conventions, the delegation chain rules, the revocation model, and
the state-verifiability runtime, and reaches for the right file before
answering.

## What it does

When you ask Claude something like:

- "How do I sign an action with Vouch in Python?"
- "Generate a did:web setup script for our agent"
- "Why is my hybrid PQ signature failing to verify?"
- "Wrap this LangChain tool with Vouch"
- "Build a heartbeat session for my agent"
- "Add BitstringStatusList revocation to my issuer"

Claude loads the matching reference file, gives you working code, and
sticks to the protocol's conventions. No hallucinated field names, no
wrong cryptosuite ids, no made-up SDK methods.

## Install

The skill lives in this folder:

```
claude-skill/
├── SKILL.md
├── README.md           (this file)
└── reference/
    ├── credential-format.md
    ├── delegation.md
    ├── go-sidecar.md
    ├── integrations.md
    ├── post-quantum.md
    ├── python-sdk.md
    ├── revocation.md
    ├── sidecar.md
    ├── state-verifiability.md
    ├── troubleshooting.md
    └── typescript-sdk.md
```

### For Claude Code (CLI)

Copy the folder into your Claude Code skills directory:

```bash
# Linux / macOS / WSL
mkdir -p ~/.claude/skills
cp -r claude-skill ~/.claude/skills/vouch-protocol

# Windows (PowerShell)
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills"
Copy-Item -Recurse claude-skill "$env:USERPROFILE\.claude\skills\vouch-protocol"
```

Restart Claude Code. The skill registers automatically; check with:

```bash
/skills
```

You should see `vouch-protocol` in the list.

### For Claude Desktop / web app

Skills are a Claude Code feature today. If you're on the desktop or
web app, you can still use this folder as a knowledge dump: paste
`SKILL.md` and the relevant `reference/*.md` files into your project's
custom instructions.

## How Claude uses it

1. Claude reads `SKILL.md` on every session start (it's small).
2. When your question matches one of the trigger phrases, Claude opens
   the relevant `reference/*.md` file before answering.
3. Code blocks in the references are the canonical shapes; Claude
   reproduces them rather than guessing.

The skill is read-only context. It doesn't modify your project, doesn't
sign anything, doesn't install any SDK on its own. It just makes Claude
better at the protocol.

## Updating

```bash
cd ~/.claude/skills/vouch-protocol
git pull   # if you cloned the vouch-protocol repo
# or re-copy from a fresh clone
```

The skill versions itself with the protocol. When Vouch ships a new
cryptosuite id or a new SDK shape, update the skill alongside.

## Triggers (full list)

The skill fires on any of these (and many natural-language variants):

- `vouch-protocol`, `vouch protocol`, `@vouch-protocol/sdk`
- `pip install vouch-protocol`, `npm install @vouch-protocol/sdk`
- `did:web`, `did:key`, `did:vouch`, DID Document, Verifiable Credential
- `eddsa-jcs-2022`, `hybrid-eddsa-mldsa44-jcs-2026`
- BitstringStatusList, revocation registry
- SessionVoucher, Heartbeat Protocol, trust entropy, canary commitment
- Identity Sidecar, vouch-sidecar
- delegation chain, parentProofValue

See `SKILL.md` for the full description string.

## Reporting issues

If Claude gives you a wrong answer that should be covered by the skill:

1. Note which file it pulled from (Claude will tell you, or check the
   `reference/` folder for the topic).
2. Open an issue: https://github.com/vouch-protocol/vouch/issues
3. Tag it `claude-skill`.

PRs that improve the reference files are welcome.

## License

Same license as the main Vouch Protocol repository (Apache-2.0).
