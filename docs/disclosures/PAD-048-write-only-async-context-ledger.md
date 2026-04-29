# PAD-048: Write-Only Asynchronous Context Ledger for LLM Coding Assistants

**Identifier:** PAD-048
**Title:** Method for Defending Against LLM Context Dilution Using a Write-Only Asynchronous Filesystem Ledger and a Trust-Domain-Separated Compactor Daemon
**Publication Date:** April 29, 2026
**Prior Art Effective Date:** April 29, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / LLM Coding-Assistant Governance / IP Leak Prevention / Long-Session Policy Enforcement / Local-First Tooling
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-002 (Chain of Custody), PAD-010 (Semantic Consent Signing), PAD-017 (Cryptographic Proof of Reasoning), PAD-031 (Adversarial Provenance Honeypots), PAD-042 (Standardized Metadata Schema)

---

## 1. Abstract

A method and architecture for defending Large Language Model (LLM) coding assistants against **context dilution** over long autonomous sessions, in which security-critical constraints stated early in the session (for example, "do not exfiltrate proprietary algorithm names" or "keep cryptographic key material out of any push payload") are progressively forgotten, summarized away, or overwritten as the session's context window fills with subsequent code, reasoning, and tool output.

The method weaponizes the LLM's own filesystem write capability as a recording mechanism. Inline rule tags in user input or in source-code comments (for example, `<r>...</r>`) are bound, via a global workspace directive, to a per-rule write into an isolated, timestamped, immutable file in a hidden ledger directory (for example, `.vouch/ledger/`). The LLM acts as a write-only secretary: it records each declared rule into its own ledger file, then continues coding. A separate background daemon, the **Compactor**, operating in a distinct trust domain from the LLM, periodically concatenates the per-rule ledger files into a single deterministic policy artifact (`.vouchpolicy`) and prunes the temporary files.

Key innovations:

- **LLM-as-writer / Compactor-as-reader trust separation.** The LLM is permitted only to *create* ledger files. It cannot edit, merge, or delete them. The merge step is performed by a non-LLM deterministic process that reads the ledger and emits the consolidated policy.
- **Write-only resilience against hallucinated overwrites.** When a single master policy file is the editing target, an LLM under context dilution can hallucinate an updated version that silently drops rules from earlier in the session. By forbidding edits to a master file, and by making each rule its own immutable artifact, the system makes silent rule loss observable: a missing rule manifests as a missing file on disk, not as a stealth deletion buried in a diff.
- **Asynchronous, non-blocking recording.** The LLM does not pause to "evaluate" the rule. It records and continues. Policy enforcement is performed elsewhere (see PAD-049 and PAD-050), preserving the LLM's reasoning loop for the coding task.
- **Inline tag binding via prompt-template directive.** The mapping from a tag such as `<r>...</r>` to "write a new ledger file" is established once, at the prompt or workspace-instruction level (for example, in `CLAUDE.md`, `cursor.md`, or an equivalent assistant-specific configuration), rather than being repeated in every prompt. Subsequent appearances of the tag, anywhere in the session, are interpreted by the LLM as ledger-write directives without further explanation.
- **Survives context collapse.** Even when the LLM's working context is summarized or truncated mid-session, the rules remain on disk and remain visible to downstream enforcement layers.

---

## 2. Problem Statement

### 2.1 Context dilution in long LLM coding sessions

Modern LLM coding assistants (Claude Code, Cursor, GitHub Copilot Workspace, Continue.dev, Aider, and equivalents) operate over sessions in which the context window steadily accumulates source code, reasoning, tool output, error traces, and prior assistant responses. Even with multi-hundred-thousand-token context windows, three pressures degrade rule retention:

1. **Token-budget compression.** Many assistants automatically summarize older turns when approaching the context limit. Summaries are lossy, and operational rules ("do not push without my approval", "do not name proprietary algorithm `X` in any output") tend to be classified as housekeeping and dropped first.
2. **Attention dilution.** Even when a rule remains within the context window, its weight in the model's effective attention decreases as the surrounding context grows. A constraint asserted in turn 3 of a 200-turn session is statistically likely to be ignored at turn 199 even when textually present.
3. **Tool-output flooding.** A single failing test, a verbose stack trace, or a multi-megabyte tool output can displace dozens of earlier instruction turns from any practical accounting of "what the model is paying attention to."

### 2.2 Master-policy-file failure mode (hallucinated overwrites)

A naive defense is to ask the LLM to maintain a single master policy file that records the active rules: every time the user states a new rule, the LLM edits this file. This approach fails under context dilution. When the LLM is asked to rewrite or edit the master file late in the session, after the original rules have decayed from its working memory, it routinely:

- **Hallucinates an updated version** that omits rules from earlier in the session (because the model no longer remembers them).
- **Silently drops constraints** by phrasing the edit as a "consolidation" or "cleanup."
- **Reorders rules** in ways that change their effective scope.
- **Produces a fully-formed but incorrect file** that passes a casual read because it is internally consistent.

Existing diff-review tooling does not catch these failures reliably because the new master file appears coherent, and the human reviewer has typically also forgotten the early-session rules.

### 2.3 Append-only logs do not, by themselves, solve the problem

Append-only logs (Kafka, write-ahead logs, event sourcing) are well-known in distributed systems, but they assume a trusted writer with deterministic append semantics. An LLM is not such a writer. If the LLM is given a single append-only log file and asked to "add a line for the new rule," it is equally capable of hallucinating the contents of the appended line, of writing to the wrong line, or of summarizing prior lines as part of the append. The append-only property of the file format does not constrain a probabilistic writer that can issue arbitrary tool calls.

### 2.4 Prior assistant-context conventions are too coarse

Existing per-project assistant context conventions, such as `CLAUDE.md`, `.cursor/rules`, `Aider conventions`, and `Continue` system prompts, are static files authored by the developer outside the chat session. They are read into context at session start. They do not provide a mechanism for the developer to declare *new* rules *during* the session and have those rules survive context dilution.

### 2.5 No prior system combines (a) inline-tag rule declaration, (b) LLM-as-writer ledger recording, (c) immutable per-rule artifacts, and (d) deterministic compaction in a separate trust domain

The combination is novel. Each component has weak analogues elsewhere (event sourcing, audit logs, AI agent memory systems, RAG context buffers), but no prior system uses an LLM coding assistant's own write tool to record per-rule immutable artifacts that are subsequently reduced by a non-LLM compactor for downstream deterministic enforcement.

---

## 3. Solution (The Invention)

### 3.1 Inline rule tag protocol

The system defines a small grammar of inline rule tags that may appear in either user input or developer-authored source comments. The canonical tag is:

```
<r [scope=...] [expires=...] [severity=...]> rule body </r>
```

The tag body is a free-form natural-language statement of a security or operational constraint. The optional attributes are:

- `scope`: a path glob or AST selector indicating where the rule applies (default: workspace root).
- `expires`: a duration (`30m`, `2h`, `7d`) or absolute timestamp after which the rule is auto-removed (see PAD-053 for the ephemeral-rules embodiment).
- `severity`: one of `advisory`, `block`, `attest` (default: `block`).

A matching close tag delimits the rule body. Multiple rules in a single utterance are independent.

### 3.2 Workspace directive binding

A one-time directive in the assistant's per-project workspace instruction file (for example `CLAUDE.md`, `.cursor/rules`, `aider.conf.yml`, or equivalent) maps the tag to a tool action:

```
When you encounter a <r>...</r> tag in user input or in source comments,
extract the tag body and any attributes. Immediately call the file-write
tool to create a NEW file at:

    .vouch/ledger/rule_<unix_timestamp_ms>_<random_8>.json

with the following JSON content:

    {
      "id": "rule_<unix_timestamp_ms>_<random_8>",
      "declared_at": "<ISO-8601 timestamp>",
      "scope": "<scope or 'workspace'>",
      "expires": "<expires or null>",
      "severity": "<severity or 'block'>",
      "body": "<verbatim rule body>",
      "source": "<chat-turn-id or file:line>"
    }

DO NOT edit, merge, or delete any existing file in .vouch/ledger/.
DO NOT write a master policy file. DO NOT summarize the rule.
After the file is created, continue with the user's underlying request.
```

This binding is loaded into context once per session. From that point, every appearance of `<r>...</r>` is interpreted by the LLM as a ledger-write directive without further explanation in the prompt.

### 3.3 Write-only ledger architecture

The ledger directory `.vouch/ledger/` has the following constraints, enforced by a combination of (a) the workspace directive instructing the LLM, (b) optional filesystem permissions (the directory is writable but individual files become read-only after creation via a post-write `chmod 0444`), and (c) a filesystem watcher that alerts on any modification or deletion event for an existing ledger file.

- Each rule occupies its own file. File names include a millisecond timestamp and a random suffix to ensure uniqueness without coordination.
- Files are created once and never modified. Deletion is performed only by the Compactor (section 3.4), and only after the rule has been committed to the consolidated policy artifact.
- The directory is plain JSON files in a flat layout. No database, no index. Recovery is `cat .vouch/ledger/*.json | jq -s '.'`.

### 3.4 Compactor daemon (separate trust domain)

The Compactor is a small native process (Python, Go, or Node), running on the developer's machine, in a trust domain distinct from the LLM. It does not read or write the LLM's context. It does not call the LLM's API. It performs a single deterministic function:

```
Compactor loop (runs every N seconds, or on inotify/FSEvents trigger):

  1. List all *.json files in .vouch/ledger/.
  2. Parse each file. Reject malformed entries (log to .vouch/quarantine/).
  3. Apply ordering by declared_at timestamp (newest last).
  4. Apply scope-conflict resolution (last writer wins within identical scope).
  5. Drop entries whose expires field has passed.
  6. Emit the consolidated artifact .vouchpolicy as either:
       - JSON: an array of active rule objects, OR
       - .conf: a line-oriented format keyed by scope.
  7. After successful emission and fsync, delete the per-rule files
     that were folded in.
  8. Maintain a separate immutable archive .vouch/archive/<date>/
     containing a copy of each rule file before deletion, for audit.
```

Because the Compactor is not an LLM, its output is byte-deterministic given its input. This is the property that downstream enforcement relies on (PAD-049 for passive extraction, PAD-050 for egress interception, PAD-051 for stateless evaluation).

### 3.5 Resilience under context collapse

The defining property of the system is what happens when the LLM forgets the rules mid-session:

- **Without the ledger:** the rule exists only in the LLM's degrading context. When the LLM is asked at turn 199 to perform an action that would violate the rule, it has no record and no way to recover the rule. The action proceeds.
- **With the ledger:** the rule exists on disk in `.vouch/ledger/` (or in `.vouchpolicy` after compaction). Downstream enforcement layers (egress interception, pre-commit hooks, stateless bouncer) read from disk, not from the LLM's context. The LLM's forgetting is irrelevant. The rule survives.

This separation, between an LLM that records-and-forgets and a deterministic enforcement layer that reads-and-blocks, is the architectural keystone.

---

## 4. Prior Art Differentiation

| System | Domain | LLM-as-writer? | Write-only / immutable per-entry? | Separate-trust-domain compaction? | Survives LLM context collapse? |
|---|---|---|---|---|---|
| `CLAUDE.md`, `.cursor/rules` (workspace context files) | LLM coding assistants | No (developer-authored) | N/A | N/A | Static, but no in-session declarations |
| Append-only log file edited by the LLM | LLM tooling | Yes | No (single file, LLM can hallucinate) | No | No |
| Event sourcing (DDD pattern) | Distributed systems | N/A (trusted writer assumed) | Yes | Yes (separate read-model projector) | N/A (no LLM in the loop) |
| Database audit logs | Database systems | N/A | Yes | Often yes | N/A |
| AI agent long-term memory (MemGPT, Letta) | LLM agent frameworks | Yes | No (memory is summarized, edited) | No | Partial (summaries lossy) |
| RAG context buffers | LLM retrieval systems | No (data ingested separately) | Often immutable | N/A | Survives session, but not declarative-rule oriented |
| **This disclosure** | **LLM coding assistants** | **Yes** | **Yes (per-rule immutable file)** | **Yes (Compactor in separate trust domain)** | **Yes** |

Differentiating claims:

1. The combination of LLM-as-writer with per-rule immutable artifacts is novel. AI agent memory systems use LLMs as writers but assume mutability. Event sourcing uses immutable per-entry artifacts but assumes a trusted writer.
2. The deliberate non-use of a master policy file as the LLM's editing target, specifically to defeat hallucinated overwrites under context dilution, is novel.
3. The trust-domain separation between the LLM (writer) and the Compactor (reader / consolidator) is novel as a defense against LLM probabilistic editing failures, distinct from event-sourcing's trust-domain separation, which is an architectural convenience rather than a defense against the writer.
4. The inline-tag-to-ledger-write binding via a one-time workspace directive is novel as a user-interface affordance: it allows the developer to declare new rules in the natural flow of a coding conversation without breaking out into a separate policy-management interface.

---

## 5. Technical Implementation

### 5.1 Tag grammar and prompt-template binding

The recommended tag form is `<r>...</r>` with optional attributes. Alternative tag forms (`@vouch-rule`, `// vouch:`, `[[rule]]...[[/rule]]`) are functionally equivalent and are disclosed as embodiments. The binding directive is loaded into context via the assistant-specific workspace mechanism:

| Assistant | Workspace mechanism |
|---|---|
| Claude Code | `CLAUDE.md` at workspace root (or any ancestor directory) |
| Cursor | `.cursor/rules/*.mdc` |
| Aider | `aider.conf.yml` `read:` directive plus a conventions markdown file |
| Continue.dev | `~/.continue/config.json` `customCommands` and `systemMessage` |
| GitHub Copilot Chat | `.github/copilot-instructions.md` |
| Generic OpenAI / Anthropic API integrations | First-message system prompt |

The binding is conceptually identical across mechanisms.

### 5.2 Ledger filesystem layout

```
<workspace-root>/
  .vouch/
    ledger/
      rule_1714415123456_a8f3d1b2.json       (immutable; mode 0444 after write)
      rule_1714415241789_c2e9a410.json
      rule_1714415402111_71fa3c8d.json
    archive/
      2026-04-29/
        rule_1714400111000_<id>.json         (compacted-then-archived)
        rule_1714400222000_<id>.json
    quarantine/
      malformed_<timestamp>.json             (rejected by Compactor)
  .vouchpolicy                                (consolidated artifact)
```

The `.vouch/` directory should be added to `.gitignore` by default; the consolidated `.vouchpolicy` may or may not be checked in depending on whether the developer wants the policy to follow the repo (team use) or remain machine-local (single-developer use).

### 5.3 Compactor algorithm (reference)

```
def compact(ledger_dir, policy_path, archive_dir):
    files = sorted(glob(f"{ledger_dir}/rule_*.json"), key=parse_ts)
    rules = []
    for f in files:
        try:
            r = json.loads(read(f))
            if expired(r):
                continue
            rules.append(r)
        except Exception as e:
            move(f, quarantine_path(f, e))
    rules = resolve_scope_conflicts(rules)  # last-writer-wins per scope
    atomic_write(policy_path, serialize(rules))
    fsync(policy_path)
    for f in files:
        if was_folded_in(f, rules):
            move(f, archive_path(archive_dir, f))
```

The Compactor is small (under 200 lines in any host language). It has zero LLM dependency.

### 5.4 Recovery semantics

If the Compactor crashes between steps 6 and 7, the ledger files remain. On restart, the Compactor re-reads the ledger and re-emits the policy artifact. Idempotent.

If the LLM crashes mid-write (rare), a partial ledger file may exist. The Compactor parses it, fails, moves it to `quarantine/`, and proceeds with the rest. The user's chat session can re-state the rule on resumption.

If the workspace is cloned to a new machine, only `.vouchpolicy` (if checked in) survives. The per-rule ledger files are local-only working state.

### 5.5 Optional cryptographic anchoring

For high-assurance deployments, each ledger file may be signed by a per-developer Ed25519 key (or, in the W3C Verifiable Credentials embodiment, secured with an `eddsa-jcs-2022` or `hybrid-eddsa-mldsa44-jcs-2026` Data Integrity proof) at write time. The Compactor verifies signatures before folding entries into `.vouchpolicy`. This embodiment ties into PAD-001 (Cryptographic Agent Identity) and PAD-040 (Hybrid Composite Signature Same Canonical Bytes).

---

## 6. Claims Summary

The following aspects are disclosed as prior art and placed in the public domain:

1. A method in which an LLM coding assistant, upon encountering an inline rule tag in user input or in source-code comments, calls its own filesystem-write tool to create a new immutable per-rule artifact in a designated ledger directory, and then continues with the user's underlying coding request without enforcing the rule itself.

2. A workspace directive that maps an inline rule tag to a per-rule ledger-write action, loaded once into the LLM's context via an assistant-specific workspace instruction mechanism, such that the LLM interprets all subsequent appearances of the tag as ledger-write directives without further explanation in the prompt.

3. A write-only ledger architecture in which (a) per-rule artifacts are immutable after creation, (b) the LLM is permitted only to create new artifacts and not to edit, merge, or delete existing artifacts, and (c) consolidation of the ledger into a single policy artifact is performed by a separate non-LLM process.

4. A trust-domain separation in which the LLM acts as the writer of the ledger and a deterministic Compactor process acts as the reader and consolidator, such that the consolidated policy artifact is byte-deterministic given the ledger contents and is not subject to LLM probabilistic editing.

5. A method for defending against LLM context dilution and master-policy-file hallucinated-overwrite failure modes, by externalizing rule storage to immutable filesystem artifacts that survive LLM context summarization, truncation, or attention decay.

6. A method for cryptographically anchoring ledger entries via per-developer signing keys or W3C Data Integrity proofs, such that the Compactor can verify the authenticity of each ledger entry before folding it into the consolidated policy.

7. The combination of (1) through (5), or (1) through (6), as an integrated architecture for in-session policy declaration and persistence in LLM coding assistants.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch

---

## Notes on companion disclosures

This disclosure is the foundation layer for a small family of related defensive publications:

- PAD-049 (Decoupled Semantic Policy Extraction via Passive Source Monitoring) covers the source-comment embodiment where the rule is embedded in a code comment rather than in chat input.
- PAD-050 (Zero-Context Deterministic Egress Interception) covers the enforcement layer that consumes `.vouchpolicy` at `git push` time.
- PAD-051 (Parallel Intent Extraction via Local Shadow Models) covers the embodiment in which a small local language model performs the rule extraction in parallel with the primary coding assistant.
- PAD-052 (UI State Sniffing for Closed-Box AI Coding Tools) covers the embodiment for closed-source AI applications where API or CLI interception is unavailable.
- PAD-053 (Time-Bounded Ephemeral Rules) covers the `expires` attribute and the auto-decay semantics.
- PAD-054 (Filesystem-Hierarchy Policy Inheritance) covers cascading `.vouchpolicy` files across nested directories.
- PAD-055 (Cross-Session Policy Re-Anchoring via Pre-Flight Context Replay) covers anchoring across discontinuous LLM sessions.

The architectures in PADs 049 through 055 are distinct inventions; the present disclosure (PAD-048) is concerned solely with the in-session declaration and ledger-recording layer. Additional inventions in the same family that involve novel cryptographic or game-theoretic primitives are reserved and are not disclosed here.
