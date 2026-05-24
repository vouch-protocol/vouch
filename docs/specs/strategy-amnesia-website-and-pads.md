# Strategy Notes: Amnesia Integration, Website Surface, and Next PADs

**Date:** May 14, 2026
**Author:** Ramprasad Gaddam (with prep by Claude session)
**Status:** Open work items for next session

> Companion to [`strategy-lfai-and-w3c.md`](./strategy-lfai-and-w3c.md). That
> document covers standards-body positioning (LF AAIF, W3C, IETF). This
> document captures three distinct strategic threads decided in the
> 2026-05-14 session: (1) how to surface the Amnesia sibling project on the
> Vouch website without diluting Vouch's identity-layer message, (2) how
> the Vouch Assistant should handle Amnesia-related questions, and (3)
> which additional defensive publications (PADs) to file beyond the
> existing PAD-048 through PAD-055 coverage of Amnesia.

---

## 1. Context: where Amnesia stands today

- **What it is:** A local developer utility for AI coding assistants
  (Claude Code, Cursor, Aider, Continue, etc.). Captures `<r>...</r>`
  tagged rules from prompts and source comments, persists them to
  `.vouch/ledger/`, compacts them into `.vouchpolicy`, and enforces at
  `git push` via a pre-push hook. Solves "the AI forgot the rule I told
  it 200 turns ago" and "the rule is gone after a fresh session
  tomorrow."
- **Repo:** [github.com/vouch-protocol/amnesia](https://github.com/vouch-protocol/amnesia)
  (sibling to [github.com/vouch-protocol/vouch](https://github.com/vouch-protocol/vouch))
- **Vouch ↔ Amnesia bridge:** Already shipped at
  `vouch-protocol/vouch/integrations/amnesia.py` (Python) and
  `packages/sdk-ts/src/integrations/amnesia.ts` (TypeScript). Produces
  signed W3C Verifiable Credentials as cryptographic attestations of
  Amnesia's egress decisions. Documented at
  `docs/integrations/amnesia.md`.
- **Current website visibility:** Minimal. One-line mention in the FAQ
  integrations list. No dedicated FAQ entry, no Help guide article, no
  footer link.

## 2. Recommended website surface for Amnesia

The two projects target the same audience (developers building with AI)
but solve different problems: identity vs. operational memory. They are
**sibling products, not features of each other.** Cross-promote without
merging the messages.

Four touchpoints, all opt-in, all in places where someone curious about
the AI-agent-tooling ecosystem will discover Amnesia without being
marketed to:

| Where | What |
|---|---|
| Nav | Nothing. Keep Vouch's nav focused on Vouch. |
| Hero | Nothing. Don't dilute "the identity layer for AI agents." |
| Footer → Resources column | Add link: "Amnesia, operational memory for AI" → GitHub repo. |
| FAQ → Standards & Interoperability section | Add Q&A: *"How does Vouch relate to Amnesia?"* One paragraph: sibling project, optional bridge produces W3C VCs from Amnesia egress decisions, link to repo + integration doc. |
| Help guide → Framework Integrations part | Add article: *"Attesting Amnesia policy decisions with Vouch."* Translate the existing `docs/integrations/amnesia.md` into the friendly house voice, with code snippets in Python and TypeScript. |

### What NOT to do

- Do not put Amnesia in the main nav, hero, or sign-up CTA.
- Do not blend Amnesia features into Vouch documentation as if they were
  Vouch features. They are not. Keep the conceptual boundary clean.
- Do not auto-redirect from `vouch-protocol.com/amnesia` to the Amnesia
  repo. If we add an Amnesia URL on the Vouch site, it should be a real
  page on the Vouch site (the FAQ entry or Help guide article) that
  *links out* to the Amnesia repo.

## 3. Vouch Assistant scope for Amnesia questions

The Assistant is currently scoped to "answer questions about Vouch
Protocol." Amnesia questions are adjacent, not core.

**Decision: light scope, deferred wide scope.**

- **Light scope (do now):** The Assistant pulls from the FAQ entry and
  the Help guide article above. It can answer "what is Amnesia, how does
  it relate to Vouch, where do I learn more." Detailed Amnesia questions
  ("how do I install it," "what does the `<r>` tag syntax do") get
  redirected to the Amnesia repo and docs. No new Assistant code needed
  beyond writing the FAQ + Help content; the Assistant reads from
  `faq-data.ts` and `help-data.ts` automatically.
- **Wide scope (later, if there's demand):** Build a separate Amnesia
  Assistant on the Amnesia repo. Two assistants, one per project, with
  cross-links between them. Probably worth doing once Amnesia has its
  own steady-state user base.

## 4. Additional defensive publications (PADs)

PAD-048 through PAD-055 already cover Amnesia's core architecture:

| PAD | Covers |
|---|---|
| 048 | Write-only async ledger + compactor daemon (recorder/enforcer separation) |
| 049 | Rule extraction from source-code comments |
| 050 | Pre-push hook intercepting code egress, optional crypto attestation |
| 051 | Parallel local small LM for rule extraction with zero overhead on primary assistant |
| 052 | OS-level cache sniffing for closed-source AI tools (Cursor, Windsurf, etc.) |
| 053 | Time-bounded ephemeral rules with auto-expiry |
| 054 | Filesystem hierarchy policy inheritance |
| 055 | Cross-session policy re-anchoring via pre-flight context injection |

### Comparison: how Amnesia differs from PromptML / PQL

Different problem entirely. PromptML / PQL are prompt-markup / prompt-query
languages: they focus on how to **structure the input** going into an LLM
(templates, variables, control flow, tool routing). Amnesia is about what
**survives between prompts** and what **fires at git push**. The categories
don't overlap, the two-line summary is **"PromptML structures input;
Amnesia constrains output."**

### Three additional PADs proposed

**PAD-059: Vouch ↔ Amnesia attestation bridge as a composition pattern**
- Provisional title: *"Method for cryptographically anchoring deterministic
  pre-push policy decisions to W3C Verifiable Credentials with optional
  hybrid post-quantum profile."*
- Why it matters: documents the **composition** of two independently-novel
  systems (Amnesia's deterministic policy + Vouch's W3C VCs + hybrid PQ).
  Establishes prior art on the broader pattern "sign your policy engine's
  decisions, not just events."
- Priority: HIGHEST. This is the most strategically valuable of the three
  because it sits at the intersection of both projects.

**PAD-060: Single-use audited override of a deterministic egress block**
- Provisional title: *"Method for one-time time-bounded override of a
  deterministic egress-time policy block, with cryptographic audit trail
  of the override event."*
- The `amnesia approve-once` mechanism. Today's exception-handling patterns
  in policy engines are usually "log and continue" or "require approval
  from a second party." This is a third pattern: structurally bounded
  self-override with audit, and the override itself is signed as evidence
  the human took responsibility.
- Priority: HIGH.

**PAD-061: Cross-vendor directive-file portability for AI coding assistants**
- Provisional title: *"Method for declaring uniform operational directives
  for multiple closed-source AI coding assistants via a single root-level
  directive file consumed by each assistant's own startup convention."*
- One project-root `CLAUDE.md` works for Claude Code; Cursor reads
  `.cursorrules`; Aider reads its own file; Continue reads its own. The
  portable PATTERN of a project-root directive file (and the convention
  for how each tool finds it) is itself a novel coordination mechanism
  worth documenting.
- Priority: MEDIUM. The per-tool conventions are public; the META-PATTERN
  of coordinating across them is what would be claimed. More defensible
  as a system design than as an isolated method.

### Recommended publication order

1. Draft and publish **PAD-059** first. Highest leverage, directly
   relevant to both Vouch and Amnesia.
2. Publish **PAD-060** within a month of PAD-059.
3. Hold **PAD-061** until at least one more cross-vendor extension is
   shipped (e.g., a Continue.dev startup convention plugin or Aider
   directive-file recognizer). The stronger the demonstrated pattern,
   the more defensible the disclosure.

## 5. Action items for next session

In rough priority order:

- [ ] **Website FAQ entry on Amnesia** under "Standards & Interoperability"
      (one Q&A in `website/src/app/faq/faq-data.ts`)
- [ ] **Help guide article on Amnesia attestation bridge** under "Framework
      Integrations" part (one article in `website/src/app/help/help-data.ts`,
      house voice, code snippets in Python and TypeScript)
- [ ] **Footer link to Amnesia** in `website/src/components/Footer.tsx` →
      Resources column
- [ ] **Draft PAD-059** (Vouch ↔ Amnesia attestation bridge) in
      `docs/disclosures/PAD-059-vouch-amnesia-attestation-bridge.md`,
      following the same format as PAD-048 through PAD-055
- [ ] **Draft PAD-060** (single-use audited override)
- [ ] **Defer PAD-061** until cross-vendor pattern is more clearly
      demonstrated

## 6. Open questions

- Should the Help guide article live on the Vouch site or on the Amnesia
  repo's documentation page? Recommendation: **on the Vouch site**,
  because it documents Vouch's role in the composition. The Amnesia repo
  should have its own quickstart that does not require Vouch.
- Should we also propose PAD-062 (or higher) covering the `<r>` tag
  syntax with its `scope`, `expires`, `severity` attributes? Currently
  PAD-048 covers the ledger and PAD-053 covers expiry, but the specific
  tag MARKUP with attribute semantics is not its own PAD. Likely overlaps
  enough with 048+053 to skip, but worth a review.
- Should the Vouch Assistant's system prompt explicitly enumerate the
  Amnesia integration as a knowledge area, or should it rely entirely on
  the FAQ/Help content it ingests? Recommendation: **rely on the content**;
  do not enumerate. Less to maintain, and the Assistant's behaviour
  matches what's visible on the site.

## 7. PAD vs arXiv: when is each the right venue?

This question came up specifically for PAD-060 (single-use audited override).
The general decision framework:

| Property | PAD | arXiv whitepaper |
|---|---|---|
| **Primary goal** | Establish prior art so the method cannot later be patented by someone else | Make a research contribution that can be cited and built on |
| **Audience** | Patent examiners, IP lawyers, prior-art searches | Researchers, academics, peer review |
| **Required contribution** | A concretely-described method or system | A theoretical contribution, an empirical evaluation, or a novel framework |
| **Length** | 200-400 lines (medium) | 20-40 pages (long, with related work and evaluation) |
| **Distribution** | CC0 in the GitHub repo; indexed by Google Scholar and prior-art crawlers | arXiv.org with persistent DOI |
| **Cost to author** | Hours to draft | Weeks to write, plus endorsement requirements |
| **Risk addressed** | Someone else patenting the same method | Lack of academic citability of the work |

**Decision for PAD-060:** publish as a PAD. The single-use-override-with-audit
pattern is an engineering method, not a research result. The risk we are
hedging is "someone files a patent on this in 2027." PAD-060 blocks that. An
arXiv paper would be a different artifact serving a different purpose.

**What WOULD make sense on arXiv (later, not now):** a single-author or
joint-author **systems whitepaper** that synthesizes the entire Amnesia
architecture, cites PADs 048 through 061 as the underlying disclosure
portfolio, and adds:

- **Empirical evaluation:** rule retention over long sessions (Claude Code
  sessions of 200+ turns), measured leak rates with and without Amnesia,
  cross-IDE compatibility benchmarks.
- **Theoretical framing:** position the recorder/enforcer separation in the
  context of trusted-computing literature; relate the write-only ledger to
  append-only-log + capability-based-security composition.
- **User study:** how developers actually use `<r>` tags in practice, what
  rule severities are most common, override frequency.

That artifact has real research contribution. It is worth writing once
Amnesia has six to twelve months of real-world usage data behind it.

## 8. Future-strategy items for Amnesia (not yet decided)

Captured here so they don't get lost between sessions:

- **Team / enterprise mode.** Today's Amnesia is per-developer-machine.
  Enterprise customers will want shared rule sets, central policy
  distribution, and aggregated audit trails across a fleet of developer
  machines. Design space: pull rules from a central policy server at
  session start, push attestations to a central audit log. Open question:
  is this Amnesia, or does it become its own product?
- **Beyond `git push`: other egress points.** Pre-push catches code leaving
  the developer machine via git. Other egress points worth covering:
  CI/CD pipelines, container builds, package publication (`npm publish`,
  `pip upload`), AI-coding-assistant tool calls that write to the
  filesystem outside the repo, clipboard exfiltration. Each is a separate
  enforcement hook.
- **Code-review tool integration.** GitHub PR webhook reads the
  `.vouchpolicy` and the diff, attaches an attestation comment to the PR.
  Useful in regulated environments where the PR review itself is the
  compliance gate.
- **Distribution channels for Amnesia.** Currently the README says
  `npm install -g vouch-amnesia` once the package is published.
  Decision item for a future session: actually publish the npm package,
  pick a versioning policy, set up automated release notes.
- **`<r>` tag syntax in non-text formats.** Should the same tag work
  inside Jupyter notebook markdown cells? Inside RST docstrings? Inside
  YAML front-matter? The cross-format portability decision affects the
  Amnesia recorder's scope.
- **Naming-collision risk with Vouch's `.vouch/` directory.** Amnesia
  writes to `.vouch/ledger/` and `.vouchpolicy`. Vouch's own Python SDK
  uses `~/.vouch/` for key storage. The shared `.vouch/` namespace is
  intentional (it signals the family) but creates a small risk of tools
  reaching for the wrong files. Worth documenting the convention
  explicitly in both repos, perhaps as a `.vouch/README.md` that
  enumerates which sibling project owns which path.
- **Legal / admissibility framing.** A signed Vouch credential attesting
  to an Amnesia egress decision is potentially admissible as evidence in
  litigation or regulatory audit. We should not make legal claims, but
  documenting the cryptographic chain-of-custody in a separate
  "Compliance Evidence Framework" doc (probably under `docs/`) gives
  customers a starting point for their legal teams.
- **Bridge to Vouch's State Verifiability runtime.** Heartbeat-renewed
  SessionVouchers could be the credential format that Amnesia signs its
  egress attestations as. Today the bridge signs a one-shot Vouch
  Credential per push. Future: a SessionVoucher that aggregates many
  push events under a single agent-identity continuum. Relevant to
  long-running CI agents.
- **Cross-promotion taglines for the Vouch landing page.** "Identity for
  AI agents, with optional memory via [Amnesia](https://github.com/vouch-protocol/amnesia)."
  Decide later whether this belongs in the hero or only in a sub-section.
- **The `.vouchpolicy` file format itself.** Currently described
  informally in PAD-048. Could be formalized as its own small
  specification (a YAML or JSON canonical form) that other tools can
  consume. Possible PAD or possible small standalone spec doc.

## 9. Decision log (running)

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-14 | PAD-059 to be drafted and published first | Highest-leverage: composes Vouch + Amnesia, signals the architectural pattern |
| 2026-05-14 | PAD-060 to be drafted and published as a PAD, not arXiv | Engineering method, not research result; cost is zero; risk addressed is patenting |
| 2026-05-14 | PAD-061 to be deferred | Per-tool conventions are public; META-pattern needs more cross-vendor implementations before it is defensibly novel |
| 2026-05-14 | Amnesia website surface is four light touchpoints, no nav or hero | Sibling project, not a Vouch feature; cross-promote without diluting |
| 2026-05-14 | Vouch Assistant scope is light (FAQ + Help only) | Less code to maintain; behaviour matches what is visible on the site |
| 2026-05-14 | arXiv systems whitepaper is a six-to-twelve-month future artifact | Need real-world usage data first to make the empirical contribution credible |

---

*End of strategy notes 2026-05-14. Next session: pick up at action items in
§5, in the order listed. The decision log in §9 should be appended to as new
strategic decisions are made.*
