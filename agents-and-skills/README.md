# Agents and Skills — Index

Four ways to put Vouch help in front of users, plus the supporting
testing and documentation drafts.

```
vouch-protocol/
├── claude-skill/         # Phase 1: Claude Code Skill
├── website-agent/        # Phase 2: Website / mobile chat agent (FastAPI + React)
├── openai-gpt/           # Phase 3: OpenAI Custom GPT package
├── gemini-gem/           # Phase 4: Google Gemini Gem package
└── agents-and-skills/    # This folder
    ├── README.md         # You are here
    ├── TESTING.md        # Test/verification steps for all four
    ├── FAQ-DRAFT.md      # FAQ entries — NOT PUBLISHED
    └── HELP-GUIDE-DRAFT.md  # Help guide page — NOT PUBLISHED
```

## What is shipped vs. what is staged

- `claude-skill/` — ready to install locally with `cp` into
  `~/.claude/skills/`. Not auto-pushed.
- `website-agent/` — backend and frontend ready for local run via
  `docker compose up` (you supply LLM key + signing key).
- `openai-gpt/` and `gemini-gem/` — config files ready to paste into
  the respective builders. Nothing is auto-created in either platform.
- `agents-and-skills/FAQ-DRAFT.md` and `HELP-GUIDE-DRAFT.md` — content
  drafts. **Not** added to `website/data/faq-data.ts` or the website's
  `/help` route until you approve.

## Verification

See `TESTING.md` for command-by-command verification of each package.

## Awaiting your decisions

Before any of this lands on the live website or in shared accounts:

1. Review `FAQ-DRAFT.md`. Approve, edit, or reject each entry. The
   draft now covers: Sidecar tiers (Go vs Python vs TS), the Vouch
   Agent, Claude Skill, OpenAI Custom GPT, Gemini Gem, Hosted agent,
   Privacy & safety.
2. Review `HELP-GUIDE-DRAFT.md`. Two parts: Part 1 explains the
   sidecar tiering; Part 2 walks through each of the four AI surfaces
   with install, sample session, customise, update, and troubleshoot.
   Decide on the final route(s) (`/help/sidecars`, `/help/ai-assistants`,
   or merge into existing `/help`).
3. Decide whether the hosted Vouch agent gets the
   `agent.vouch-protocol.org` hostname or another.
4. Confirm the retention claim (30-day audit log) matches your actual
   policy.
5. Decide whether to publish a shared Custom GPT / Gemini Gem under a
   Vouch-owned account, or keep the publish-the-config model.
6. Decide whether the "Pro tier adds FIPS 140-3" line in Part 1 of the
   Help Guide is OK to ship today (it is a forward-looking statement).

After your approval I will write the corresponding website edits
(faq-data.ts entries, new `/help/*` pages) and prepare them for review.
No edits to the live website until you say go.
