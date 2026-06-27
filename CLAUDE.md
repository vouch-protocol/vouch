# Project notes for Claude Code

## Conventions (follow these without being asked)

- **Commit author**: Ramprasad Gaddam <groups.rampy1@gmail.com>. Never commit as
  Claude or any AI identity.
- **No AI attribution** anywhere: no "Generated with/by Claude Code", no
  "Co-Authored-By: Claude", no Claude-Session trailers, in commits, PR titles or
  bodies, code, or docs. The repo sets `includeCoAuthoredBy: false` in
  `.claude/settings.json`; if a PR is created with an auto-appended attribution
  footer, strip it with an update immediately.
- **No em-dashes** anywhere: not in code, comments, docstrings, docs, commit
  messages, PR bodies, or chat replies. Use commas, hyphens, parentheses, or
  separate sentences.
- **DCO**: every commit must be signed off (`git commit -s`, trailer
  `Signed-off-by: Ramprasad Gaddam <groups.rampy1@gmail.com>`). CI enforces it.
- **Ruff**: code must pass `ruff check` and `ruff format --check`. FastAPI
  dependencies use `Annotated[..., Depends(...)]`, not call-in-default, to
  satisfy bugbear B008.

## Glossary

- **FHKCOG**: the set of assistant-facing surfaces to keep in sync when the API
  or philosophy changes. It stands for:
  - **F** = FAQ (`agents-and-skills/FAQ-DRAFT.md`)
  - **H** = Help Guide (`agents-and-skills/HELP-GUIDE-DRAFT.md`)
  - **K** = Knowledge Base for the Vouch Assistant
    (`website-agent/backend/knowledge/`)
  - **C** = Claude Skill (`claude-skill/skills/vouch-protocol/`)
  - **O** = OpenAI Custom GPT (`openai-gpt/`)
  - **G** = Gemini Gem (`gemini-gem/`)

  The four assistant surfaces (Knowledge Base, Claude Skill, OpenAI GPT, Gemini
  Gem) share the same knowledge files (`quickstart.md`, `integrations.md`,
  `delegation.md`, etc.). Keep them identical: edit one canonical copy and
  propagate to all four.

## Product philosophy

- **One-line adoption.** Make the easiest, most secure path a single line, like
  `vouch git init`. The deterministic signing API is the reference:
  `vouch init --yes` to set up identity, `protect([tools])` / `@signed` /
  `<framework>.autosign()` to sign, `vouch.verify(...)` / `VouchGate` to verify,
  `vouch.delegate(...)` for delegation, and `Shield.guard([tools])` for
  zero-config runtime protection. The old per-framework "minting" tools have
  been removed.
