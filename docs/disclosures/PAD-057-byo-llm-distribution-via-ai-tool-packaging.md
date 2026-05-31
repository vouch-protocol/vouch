# PAD-057: Bring-Your-Own-LLM Distribution of Protocol Capabilities via AI Tool Packaging

**Identifier:** PAD-057  
**Title:** Distribution of Protocol-Specific Developer Capabilities Through User-Owned AI Tool Subscriptions, Inverting the Hosted-Inference Model  
**Publication Date:** May 14, 2026  
**Prior Art Effective Date:** May 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Developer Tooling / AI Agent Distribution / Open-Source Economics / Protocol Adoption  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-003 (Identity Sidecar), PAD-038 (Agent Capability Discovery), PAD-042 (Standardized Metadata Schema), PAD-056 (Allow-List Bounded AI Assistant Signing)  

---

## 1. Abstract

A method for an open cryptographic protocol vendor to distribute
protocol-specific developer capabilities — documentation lookup, code
generation, repository auditing, integration scaffolding, error
diagnosis — **as content packages installed into the developer's
existing AI tool subscription** rather than as hosted SaaS APIs that
the vendor operates and pays inference costs for. The user's
Claude / OpenAI / Gemini subscription provides the inference; the
vendor provides only the structured knowledge base, the
prompt-engineering manifest, and the capability descriptors.

The novel contribution is the deliberate **inversion of the dominant
hosted-AI economic model** for protocol-vendor tooling: instead of
"vendor runs the AI service and bills the developer for inference,"
the model is "vendor publishes a package; developer's pre-existing AI
tool consumes the package; the vendor's inference cost is zero." This
allows protocol vendors with no central infrastructure to offer
sophisticated AI-assisted developer experiences without funding
ongoing inference at scale.

---

## 2. Problem Statement

### 2.1 The Hosted-AI Cost Trap for Open-Protocol Vendors

When a protocol vendor — typically an open-source project or
standards-body author with no commercial revenue — wants to offer an
AI-assisted developer experience, the conventional path is:

1. Build a chatbot or assistant service hosting the vendor's
   knowledge base.
2. Route every user query through a commercial LLM API
   (OpenAI / Anthropic / Google).
3. Pay the per-query inference cost from the vendor's budget.
4. Implement rate limits, abuse protection, billing, scaling.

This path has three failure modes for open-protocol vendors:

- **Inference cost grows linearly with adoption**: success punishes
  the vendor. A protocol that achieves wide adoption finds itself
  paying tens of thousands of dollars per month for inference on
  queries the developers could have run on their own subscriptions.
- **Single point of failure**: if the vendor's wallet runs out or the
  upstream LLM provider rate-limits the vendor's account, the entire
  developer community loses access simultaneously.
- **Privacy / data-locality concerns at enterprise scale**: enterprise
  developers cannot send their proprietary code to a third-party
  vendor's chatbot for analysis, regardless of how well the chatbot
  answers protocol questions.

### 2.2 The Knowledge Resides in Documents, Not in the Model

A protocol vendor's value to its AI assistant is not the inference
itself; commercial LLMs handle that well. The vendor's value is the
**curated, canonical knowledge of the protocol**: the wire format,
the SDK shapes, the cryptosuite identifiers, the gotchas, the
integration patterns. These are documents, not model weights.

If the documents can be installed directly into the developer's AI
tool, the inference happens on the developer's subscription, and the
vendor's contribution is reduced to maintaining the documents.

### 2.3 No Existing Open-Protocol Vendor Has Articulated This Model

As of the publication date, the standard pattern among
open-protocol vendors offering AI-assisted documentation is some
combination of: (a) a hosted chatbot consuming the vendor's tokens,
(b) static documentation with no AI integration, or (c)
generic-LLM-with-RAG demos that require the developer to wire up
their own inference. No vendor has published the **deliberate
inversion** as an architectural choice with the explicit goal of
zero vendor-paid inference at any scale of adoption.

---

## 3. Disclosed Method

### 3.1 Three Packaging Targets

The method packages the protocol's developer capabilities for three
existing AI tool ecosystems:

1. **Claude Skill** (for Anthropic's Claude Code CLI): a directory
   containing a `SKILL.md` manifest with name, description, and
   trigger phrases; plus a `reference/` subdirectory of canonical
   protocol documentation in Markdown.
2. **OpenAI Custom GPT**: a configuration bundle for ChatGPT's GPT
   builder: name, description, instructions, conversation starters,
   knowledge files (the same canonical Markdown), optional Actions
   schema for tool-use against the protocol vendor's APIs.
3. **Google Gemini Gem**: a parallel configuration for Gemini Gems:
   name, description, instructions, knowledge files, example prompts.

Each package is **self-contained**: a developer installs it into
their own AI tool account, and the package thereafter runs on the
developer's inference subscription.

### 3.2 Canonical Knowledge Base Shared Across Packages

A single canonical knowledge base is the source of truth across all
three packages. The vendor maintains one set of Markdown files; a
build step (or manual copy) replicates them into each package's
knowledge directory. Updating the protocol updates one source; the
three packages are regenerated identically.

```
~/vouch-protocol/
├── claude-skill/
│   ├── SKILL.md
│   └── reference/         <-- canonical knowledge
├── openai-gpt/
│   ├── instructions.md
│   └── knowledge/         <-- copy of canonical knowledge
└── gemini-gem/
    ├── instructions.md
    └── knowledge/         <-- copy of canonical knowledge
```

A developer using Claude Code, ChatGPT, or Gemini receives the same
authoritative protocol guidance because the same source documents
ground all three.

### 3.3 No Vendor Inference, At Any Scale

When a developer asks "how do I sign a Vouch credential in Python?":

- The Claude Skill: Claude Code (running on the developer's
  Anthropic subscription) opens the relevant reference file from
  `~/.claude/skills/vouch-protocol/reference/python-sdk.md` and
  answers using the developer's tokens.
- The OpenAI Custom GPT: ChatGPT (running on the developer's ChatGPT
  Plus / Team / Enterprise subscription) reads the relevant knowledge
  file and answers using the developer's tokens.
- The Gemini Gem: Gemini (running on the developer's Gemini Advanced
  or Workspace subscription) reads the relevant knowledge file and
  answers using the developer's tokens.

The protocol vendor's servers are not in the request path. The
vendor's contribution per query is zero compute, zero tokens, zero
storage.

### 3.4 Bring-Your-Own-LLM Repository Audit (Capability Beyond Q&A)

The same packages enable a higher-leverage capability: **auditing the
developer's repository for protocol integration opportunities**, all
on the developer's own tokens.

A developer with the Claude Skill installed runs Claude Code inside
their repository and asks: "Audit this codebase for places where
Vouch credentials would make sense. Use the Vouch protocol skill for
reference."

Claude Code:
1. Reads the developer's repository using its native file-system
   access.
2. Loads the matching reference files from the Vouch Skill.
3. Cross-references high-stakes tool calls and API endpoints against
   integration patterns in the Skill.
4. Produces a written audit identifying specific functions that
   should sign, specific verifier-side code needed, DID conventions
   that fit, and a migration sequence.
5. Optionally writes the changes as PR-ready edits.

All inference and all file access run on the developer's subscription
inside the developer's tool. The Vouch vendor sees nothing, pays
nothing, and stores nothing.

### 3.5 Capability Discovery Manifest

Each package declares which capabilities it offers via its
description string (Claude Skill `description` field, OpenAI GPT
description, Gemini Gem description). The developer's AI tool
surfaces these capabilities to the developer in a uniform discovery
flow (the tool's own `/skills`, "My GPTs", or "My Gems" listing).
This produces a consistent capability-discovery experience across
the three ecosystems without requiring custom vendor infrastructure.

---

## 4. Relationship to Vouch Pro (Commercial Tier)

The open-source PAD-057 method covers the **architectural pattern**.
Several extensions appropriate for commercial / enterprise deployment
do not fall under the open disclosure and remain the proprietary
domain of a vendor's commercial tier (in Vouch's case, Vouch Pro):

| Concern | Open (PAD-057) | Commercial extension |
|---|---|---|
| Knowledge content | Public protocol docs | Enterprise addenda: customer's DID prefix, internal verifier endpoints, validator policies, KMS configuration |
| Distribution | Public Skill / GPT / Gem the developer builds | Pre-built bundled distribution via the customer's enterprise AI plan; updates via MDM / config management |
| Audit capability | Generic "integration opportunities" using the user's LLM tokens | Audit against **the customer's** policies; CI integration for continuous compliance |
| BYO-tokens isolation | Public Anthropic / OpenAI / Google plans | Support for Anthropic Bedrock, Azure OpenAI, Vertex AI — keeps data in the customer's cloud account |
| Repo access | Reads public repos only | OAuth / GitHub App / GitLab integration with scoped read access for private repos |
| Telemetry | None | Aggregate usage metrics for the customer's own dashboard |

The disclosure here covers the **architectural pattern**: a protocol
vendor publishes content packages for user-owned AI tool
subscriptions, with zero vendor inference cost. The commercial
extensions add enterprise plumbing on top of that pattern; they are
not claimed in this disclosure.

---

## 5. Distinction from Prior Art

### 5.1 vs. Hosted Documentation Chatbots

Hosted documentation chatbots (e.g., Algolia DocSearch with LLM
overlay, Mintlify AI, GitBook AI) operate the inference on the
vendor's side and bill or pay for queries. They do not invert the
economic model; they accept the conventional hosted-AI cost
structure. PAD-057 explicitly inverts it.

### 5.2 vs. Generic Documentation in Vendor-Neutral Format

Protocol documentation published as Markdown, OpenAPI specs,
JSON-Schema, or similar vendor-neutral formats does not constitute
PAD-057. Such documents are inputs to any retrieval-augmented
generation pipeline a developer chooses to build, but they do not
package the prompt engineering, capability descriptors, and
discovery manifest needed to deliver a working assistant inside the
developer's existing AI tool. PAD-057's claim is the **packaging
shape** specific to Claude Skills, OpenAI Custom GPTs, and Gemini
Gems — three concrete distribution channels where the developer's
existing tool consumes the package directly.

### 5.3 vs. Plugin / Tool Marketplaces (LangChain Hub, etc.)

Tool marketplaces distribute executable code (LangChain tools, MCP
servers) that the developer runs locally or hosts. These ship
behavior, not knowledge. PAD-057 ships knowledge as packaged
documents and prompt-engineering manifests — no executable code is
shipped, no runtime is required beyond the developer's existing AI
tool.

### 5.4 vs. Model Context Protocol (MCP) Servers

MCP servers expose tools and resources to an AI assistant via a
defined protocol. An MCP server is executable code with a runtime
the developer hosts. PAD-057 is complementary: a Vouch MCP server
can coexist with the Vouch Skill / GPT / Gem; the MCP server
provides interactive tools (sign, verify), while the Skill / GPT /
Gem provides domain knowledge for the LLM to reason about when and
why to use those tools. The disclosure does not claim novelty over
MCP; it claims novelty in the knowledge-package distribution path
that pairs with MCP without requiring it.

### 5.5 vs. Custom Instructions / Project Files in AI Tools

Developers paste arbitrary instructions into their AI tool's project
or custom-instructions field daily. PAD-057 is distinct because it
ships a **vendor-maintained, versioned, structured package** with
identifiable triggers, layered references, and a manifest that
declares the package's capabilities to the AI tool's discovery
surface. Ad-hoc instruction pasting does none of these things.

---

## 6. Claims

The defensive disclosure asserts public prior art for:

1. A method for a cryptographic protocol vendor to distribute
   developer capabilities as content packages consumed by the
   developer's pre-existing AI tool subscription, where the
   protocol vendor incurs zero inference cost at any scale of
   adoption.
2. The specific packaging shapes for Claude Skills, OpenAI Custom
   GPTs, and Gemini Gems, each carrying the protocol's canonical
   knowledge base in the host tool's expected format.
3. The pattern of maintaining a single canonical knowledge source
   and replicating identical content into the three packages such
   that all three packages give consistent answers to the same
   developer question.
4. The capability of **auditing a developer's repository for
   protocol integration opportunities entirely within the
   developer's AI tool**, using the developer's tokens, without any
   protocol-vendor infrastructure in the request path.
5. The pattern of using each AI tool's native discovery surface
   (`/skills`, "My GPTs", "My Gems") as the protocol vendor's
   capability-discovery channel.
6. The economic property that the protocol vendor's marginal cost
   per developer query approaches zero as adoption scales, because
   the developer's existing AI subscription absorbs the inference
   cost.

---

## 7. Reference Implementation

The Vouch Protocol publishes its three packages at:

- `claude-skill/` — 11 reference files + manifest + README
- `openai-gpt/` — instructions, knowledge corpus, actions schema, auth doc
- `gemini-gem/` — instructions, knowledge corpus, examples

All three share content sourced from the same canonical Markdown
files. Build / sync is a directory copy in the current
implementation; future iterations may use a generator that derives
all three from a single source-of-truth manifest.

The repository at `https://github.com/vouch-protocol/vouch/tree/main/`
provides the running reference. Installation instructions for each
target ecosystem are in the respective directory's README.

---

## 8. Security and Privacy Considerations

### 8.1 Knowledge-Base Integrity

The Markdown files distributed via each package MUST be cryptographic
ally signed by the protocol vendor (e.g., signed git commits, GPG-
signed releases, or — appropriately for the Vouch Protocol — Vouch
credentials bound to the file Merkle root). A developer installing a
package SHOULD verify the signature before installation. Tampering
with a package's knowledge files could mislead the developer's AI
tool into producing incorrect or insecure integration guidance.

### 8.2 Developer Token Cost

The economic burden shifts from the vendor to the developer. A
developer running heavy repository audits or large-volume Q&A
consumes their own AI subscription. The disclosure does not claim to
eliminate the cost of AI assistance; it claims to relocate that cost
from the protocol vendor to the developer who already has an AI
subscription.

### 8.3 Privacy of Developer Code

When the developer asks their AI tool to audit a repository, the
repository contents flow to the AI tool's inference servers
(Anthropic, OpenAI, Google). The protocol vendor does not see this
data, but the developer's chosen AI provider does. Developers
concerned about code privacy should choose providers / plans with
suitable data handling (Anthropic's API zero-retention by default,
OpenAI Enterprise, Vertex AI inside the customer's GCP project, etc.).

### 8.4 Stale Knowledge Risk

Developer-installed packages can become stale if the developer does
not pull updates. The disclosure recommends that each package
include a version string and that the AI tool surface it; commercial
extensions may include automatic update channels.

---

## 9. Conclusion

This disclosure establishes public prior art for **Bring-Your-Own-LLM
distribution of protocol-vendor developer capabilities** through
content packages installed into developer-owned AI tool
subscriptions. The architectural inversion of the hosted-AI cost
model is the novel claim: protocol vendors with zero ongoing
inference budgets can offer sophisticated AI-assisted developer
experiences that scale freely with adoption.

The author publishes this disclosure under Apache 2.0 (the package
contents) and CC0 (this disclosure document itself) to keep the
pattern openly available to the open-protocol and open-standards
community and to prevent extraction of the architectural pattern by
patent claims from any third party.

---

## 10. References

- [PAD-003] Identity Sidecar Pattern (Gaddam, January 2026)
- [PAD-038] Decentralized Agent Capability Discovery Protocol (Gaddam, April 2026)
- [PAD-042] Standardized Metadata Schema for AI Agent Ledger Signatures (Gaddam, April 2026)
- [PAD-056] Capability-Bounded AI Assistant Output via Intent Allow-List (Gaddam, May 2026)
- [CLAUDE-SKILLS] Anthropic Claude Code Skills documentation
- [OPENAI-GPTS] OpenAI Custom GPT documentation
- [GEMINI-GEMS] Google Gemini Gems documentation
- [MCP] Model Context Protocol specification
- [VOUCH-SPEC] Vouch Protocol Specification, v0.1-draft
