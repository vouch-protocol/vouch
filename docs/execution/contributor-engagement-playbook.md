# Contributor Engagement Playbook

Execution reference for growing and retaining contributors to Vouch Protocol.
Consolidates the discovery, onboarding, recognition, responsibility, and
community ideas in one place. Owner: @rampyg.

## Why this exists

Two strangers self-served starter work within a day of the `good first issue`
label being applied (PRs #110 and the interest on #92, #107). The recipe that
worked: a labeled, well-scoped issue with acceptance criteria and a file
pointer, plus fast labeling. This document scales that recipe and turns
one-off contributors into stakeholders.

The guiding principle: stars measure attention; stakeholders are made by
transferring ownership. Recognize publicly, delegate responsibility early,
give a voice, and let contributors carry a piece of the project's identity.

---

## 1. Discovery: help newcomers find us

- **Keep the queue stocked.** Aim for 5-10 open `good first issue`s at all
  times, each with: a one-paragraph scope, acceptance criteria, a file or line
  pointer, and a size label (`size: S/M`). When the queue empties, inflow stops.
- **Tier the labels** (do not stop at beginners; see section 6):
  - `good first issue`: under ~30 min, fully specified.
  - `good second issue` / `help wanted`: needs a small design choice.
  - `complex` / `design` / `rfc` / `security`: for experienced contributors.
- **List on aggregators** (each pulls from the `good first issue` label):
  - up-for-grabs.net: fork `up-for-grabs/up-for-grabs.net`, add
    `_data/projects/vouch.yml`, open a PR. (Fork-first is expected; they have
    no form.)
  - goodfirstissue.dev: PR to `DeepSourceCorp/good-first-issue`, add our path
    to `data/repositories.toml`. Requires 3+ `good first issue` issues.
  - goodfirstissues.com: PR to `iedr/goodfirstissues`, add `vouch-protocol/vouch`
    to `repositories.json` (owner/name, lexicographic order). Requires 3+
    `good first issue` issues and a README with setup steps.
  - MunGell/awesome-for-beginners: PR adding a one-line entry.
  - GitHub's own "For Good First Issue" (forgoodfirstissue.github.com).
- **Repo topics** (free, instant): `good-first-issue`, `ai-agents`, `web3`,
  `cryptography`, `decentralized-identity`, plus `hacktoberfest` seasonally.

The label filter URL to share everywhere:
`https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22`

## 2. Onboarding: get them to green fast

- **Welcome bot** (`.github/workflows/welcome.yml`): greets first-time issue
  and PR authors with CONTRIBUTING, the DCO sign-off, dev setup, Codespaces, and
  Discord. Also points to the AI helper tools (Claude skill, Custom GPT, Gemini
  Gem) so repeat contributors move even faster.
- **Dev container + Codespaces** (`.devcontainer/devcontainer.json` + README
  badge): one click gives a Python 3.11 environment with the `dev` extra
  preinstalled, so a newcomer reaches green tests with zero local setup. This
  fixes real friction (missing build deps, `pytest` only in the `dev` extra).
- **AI co-pilots**: `claude-skill/`, `openai-gpt/`, `gemini-gem/` each teach an
  assistant the SDK shapes, cryptosuite ids, DID conventions, and delegation
  rules. Point contributors to these for future, faster contributions.
- **First response is the top retention driver.** Assign quickly, review within
  24-48h, and always thank.

## 3. Recognition

- **all-contributors bot** (installed; config in `.all-contributorsrc`, markers
  in README). To credit: comment `@all-contributors please add @user for code`
  on any issue or PR; merge the bot's PR. (The native GitHub contributors graph
  is automatic on merge regardless.)
- **Release-note credit**: name contributors in `CHANGELOG.md` / `RELEASES.md`.
- **Vouch Verified Contributor credential** (`scripts/mint_contributor_credential.py`
  + `.github/workflows/verified-contributor.yml`): on merge, mint a signed
  Verifiable Credential for the PR author and post it as a thank-you. This is
  the highest-leverage, most on-brand recognition: an ownable badge that also
  demonstrates the protocol working on humans.
- **Spotlights**: periodic contributor shout-outs in Discord and on X.

## 4. Responsibility: the biggest stakeholder driver

- **CODEOWNERS** (`.github/CODEOWNERS`): when someone lands 2-3 solid PRs in an
  area, add their handle so they are auto-requested for review there. Keep
  core/crypto under lead review.
- **Contributor ladder** (see `GOVERNANCE.md`): make the rungs and the criteria
  to climb them visible. People climb ladders they can see.
- **Let them mentor**: ask a returning contributor to review the next
  newcomer's PR.

## 5. Agency and belonging

- Invite strong contributors to comment on `ROADMAP.md`, open RFCs and
  Discussions, and propose their own `good first issue`s.
- Discord: a `#good-first-issues` channel (fed by the announcer workflow), a
  `#introductions` channel, and an auto-granted `Contributor` role.

## 6. Beyond beginners: senior and professional contributors

Do not limit everything to `good first issue`. Provide a path for experienced
people:

- Labels: `help wanted`, `good second issue`, `complex`, `design`, `rfc`,
  `security`, `performance`.
- An **RFC / design-proposal** process via Discussions for protocol-level work
  (e.g. the v1.7 delegation redesign).
- A `#dev-discussion` channel for architecture and deep dives.
- Reach senior folks where they are: DIF, W3C Credentials CG, Trust over IP,
  IIW (identity); LangChain / CrewAI / AutoGen / MCP communities (AI agents).

## 7. On stars and forks

Do not personally solicit stars or forks (forking already happens when someone
contributes, and incentivized stars violate GitHub's terms and cheapen a
trust-focused project). Keep the ambient nudges (README footer, welcome bot).
Sequence matters: deliver value, recognize, then a soft ask at most.

## 8. The flywheel

Stocked, well-scoped issues -> listed on aggregators -> fast warm welcome ->
frictionless setup -> recognition (credential + all-contributors) -> a slightly
harder issue -> area ownership via CODEOWNERS -> maintainer. Repeat.

## 9. What is automated vs manual

Automated (in-repo): welcome bot, devcontainer/Codespaces, Discord announcer,
Verified Contributor credential, all-contributors config.

Manual (owner actions): approve CI for first-time contributors, install the
all-contributors app, set the `DISCORD_WEBHOOK_URL`, `VOUCH_PRIVATE_KEY`, and
`VOUCH_DID` secrets, submit the aggregator PRs, and run the `@all-contributors`
add command per contributor.
