# PAD-049: Decoupled Semantic Policy Extraction via Passive Source Monitoring

**Identifier:** PAD-049
**Title:** Method for Extracting Operational Policy Rules from Source Code Comments via Passive File-System Monitoring with Intentional LLM Non-Enforcement
**Publication Date:** April 30, 2026
**Prior Art Effective Date:** April 30, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / LLM Coding-Assistant Governance / Source Annotation Parsing / Decoupled Enforcement Architecture
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-010 (Semantic Consent Signing), PAD-017 (Cryptographic Proof of Reasoning), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-050 (Zero-Context Deterministic Egress Interception)

---

## 1. Abstract

A method for declaring operational policy rules directly inside source code, by embedding a structured rule tag (for example `// <r> Block public egress for this function </r>`) within a comment on the targeted line, function, class, or file. The rule is **intentionally not enforced by the Large Language Model (LLM) that may be reading or editing the file**. Instead, an entirely separate file-system watcher process, running in a distinct trust domain, detects the file save event, parses the source either via Abstract Syntax Tree (AST) extraction or by regular-expression scan, lifts the rule body into the structured policy artifact (`.vouchpolicy` or the per-rule ledger of PAD-048), and propagates the rule to deterministic enforcement layers (PAD-050, PAD-052).

The architectural keystone is **deliberate LLM non-enforcement**. The LLM treats the comment as ordinary passive context, identical to any other comment in the file. It does not pause to evaluate the rule. It does not attempt to honor the rule in subsequent code generation. It does not summarize the rule into its working memory. The rule is enforced exclusively by the deterministic out-of-band watcher, which does not consume any LLM context or attention budget.

Key innovations:

- **Comment-as-Trojan-horse for policy declaration.** The rule lives in the source code where the rule applies, naturally co-located with the code it governs, without requiring the developer to maintain a separate policy file or remember to declare rules in a chat session.
- **Intentional LLM passivity as a security property.** Most prior systems that embed instructions in code comments (Doxygen, JSDoc, attribute annotations, type hints) expect the consumer of the comment to be a downstream tool. This system extends the pattern: the LLM is also a consumer of the comment, but is specifically directed (by workspace instruction or by lack of contrary directive) to ignore the rule body. Enforcement responsibility is moved off the LLM entirely.
- **AST-aware scope inference.** When the rule appears inside a function, class, or file, the watcher attaches the rule's scope to the enclosing AST node automatically, so that downstream enforcement can match diffs against the correct scope.
- **Idempotent re-extraction.** Modifying or deleting the comment in source produces a corresponding update or removal in the policy artifact on the next save event, without requiring any rule-management UI.

---

## 2. Problem Statement

### 2.1 Inline chat-tag declaration is rule-by-rule and forgets scope

PAD-048 establishes the in-session declaration model in which the developer states a rule via a chat tag like `<r>...</r>`. This is excellent for global rules ("never include AWS keys in any push") but loses precision for rules that should attach to a specific function, class, or module ("the body of `compute_proprietary_score()` must never appear in any external output").

Stating the per-function rule in chat requires the developer to also explain the scope ("by the way, this rule applies only to the `compute_proprietary_score` function in `scoring/internal.py`"). The ceremony makes precise scoping painful, and the rule then exists at chat-distance from the code it governs, which makes it easy to lose during refactoring.

### 2.2 Forcing the LLM to enforce inline rules adds context burden and reasoning load

A naive solution is to put the rule in the source comment and instruct the LLM to honor it. This fails for the same reasons as PAD-048's master-policy-file approach: as the session grows, the LLM's attention to the rule decays, and at the moment of a relevant action (function rewrite, refactor, push), the LLM may have forgotten the rule even though it remains in the file.

Worse, asking the LLM to enforce the rule couples the rule's effectiveness to the LLM's probabilistic judgment, which is exactly what defensible policy enforcement is supposed to avoid.

### 2.3 Existing inline-annotation systems do not generalize to LLM coding assistants

Prior systems that embed structured information in source comments include:

- Doxygen and JSDoc (documentation extraction)
- ESLint disable directives (`// eslint-disable-next-line`)
- TypeScript pragma comments (`// @ts-ignore`)
- Type-hint comments (Python pre-PEP-484, mypy `# type:`)
- Static-analysis directives (`// NOSONAR`)
- License headers (SPDX `// SPDX-License-Identifier:`)

All of these are addressed to specific deterministic downstream tools (the doc generator, the linter, the type checker). None of them establish an architecture in which an LLM is *also* a consumer of the comment but is *specifically directed to ignore* the directive while a separate watcher enforces it. The novel piece is the dual-consumer model with asymmetric responsibilities.

### 2.4 No prior system extracts policy from source comments via passive file-system watching for the purpose of governing an LLM coding assistant's external actions

The combination, source comment + passive watcher + intentional LLM passivity + deterministic enforcement at egress, has not been previously deployed.

---

## 3. Solution (The Invention)

### 3.1 Source comment grammar

The system supports the same `<r>...</r>` tag form as PAD-048, embedded inside any single-line or block comment recognized by the file's language. Examples across common languages:

```
# Python
def compute_proprietary_score(data):
    # <r scope=function severity=block>Body must not appear in any external output</r>
    ...

// JavaScript / TypeScript
class InternalScorer {
    // <r scope=class>Class implementation is proprietary; never push to public</r>
    score(data) { ... }
}

/* C / C++ / Java
 * <r scope=file>Entire file is internal; do not include in any push</r>
 */

# Bash / shell
# <r scope=function>Never log the contents of $SECRET_PATH</r>
fetch_secret() { ... }
```

The optional attributes (`scope`, `expires`, `severity`) follow the PAD-048 grammar.

### 3.2 Passive file-system watcher

A small native daemon watches the workspace root via `inotify` (Linux/WSL), `FSEvents` (macOS), or `ReadDirectoryChangesW` (Windows). On each `IN_CLOSE_WRITE` (or platform equivalent), the daemon:

1. Identifies the file's language by extension or shebang.
2. Selects an extraction strategy: AST-aware if a parser is available for that language, otherwise regex.
3. Locates all `<r>...</r>` tags inside comments.
4. Computes the AST scope for each tag (enclosing function, class, file).
5. Emits a per-rule ledger entry into `.vouch/ledger/` (in the PAD-048 format), tagged with `source: file:line` for traceability.

The daemon is deliberately small (under 500 lines in any host language) and contains no LLM dependency. Its output is byte-deterministic given the source file contents.

### 3.3 AST-aware scope inference

The preferred extraction strategy uses a real parser for the file's language, so that a tag inside a function comment correctly inherits the function's scope:

```
# Python: tree-sitter-python or libcst
# JavaScript: tree-sitter-javascript or @babel/parser
# Go: golang.org/x/tools/go/ast
# Rust: syn
# C/C++: tree-sitter-c
```

The watcher walks the AST, locates the comment node by source range, and attributes the rule to the smallest enclosing function, method, or class declaration. If no enclosing declaration exists, the rule scopes to the file.

### 3.4 Regex fallback for unknown languages

When no AST parser is available (rare languages, configuration files, mixed-content documents), the watcher falls back to regex extraction. The fallback grammar requires the developer to state the scope explicitly via the `scope=` attribute, since the watcher cannot infer it. Rules without explicit scope in fallback mode default to file scope.

### 3.5 Decoupled trust domain

The watcher does not communicate with the LLM. It does not write to the LLM's context. It does not call any LLM API. Its only outputs are filesystem writes to `.vouch/ledger/` (consumed by the PAD-048 Compactor). This guarantees that the watcher's behavior is a pure function of the source files on disk and cannot be manipulated by a context-collapsed or adversarial LLM.

### 3.6 Idempotent re-extraction

When a file is modified, the watcher re-extracts all rules from the file and synchronizes the ledger:

- New rules in the file produce new ledger entries.
- Removed rules in the file produce ledger-removal events (the watcher writes a `tombstone_<rule_id>.json` entry, which the Compactor consumes by removing the corresponding rule from `.vouchpolicy`).
- Modified rules produce a removal of the prior version and an insertion of the new version.

The system is therefore a pure read-and-emit pipeline with no hidden state.

---

## 4. Prior Art Differentiation

| System | Domain | Source-comment based? | LLM is also a consumer? | LLM intentionally passive? | Deterministic out-of-band extraction? |
|---|---|---|---|---|---|
| Doxygen / JSDoc | Documentation generation | Yes | No (pre-LLM) | N/A | Yes |
| ESLint disable directives | Linter control | Yes | No | N/A | Yes (lint engine) |
| TypeScript pragmas | Type-checker control | Yes | No | N/A | Yes |
| Static-analysis annotations (`NOSONAR`, etc.) | Static analyzer control | Yes | No | N/A | Yes |
| GitHub Copilot inline comments | LLM context only | Yes | Yes (LLM is the only consumer) | No (LLM is the enforcer) | No (no out-of-band layer) |
| `CLAUDE.md` / `cursor.md` workspace files | LLM context only | No (separate file) | Yes (LLM only) | No | No |
| **This disclosure** | **LLM coding assistant governance** | **Yes** | **Yes** | **Yes (deliberate)** | **Yes** |

Differentiating claims:

1. The dual-consumer model in which both an LLM and a deterministic watcher read the same source comment, with explicitly asymmetric responsibilities (LLM ignores; watcher enforces), is novel.
2. The use of source comments as a Trojan horse for system-level security policy, where the policy is enforced by an out-of-band layer the LLM cannot affect, is novel.
3. The combination of (a) AST-aware scope inference, (b) inline rule grammar, and (c) intentional LLM non-enforcement, applied to the LLM-coding-assistant domain, is not present in any prior system.

---

## 5. Technical Implementation

### 5.1 Comment grammar variants

The canonical tag form is `<r>...</r>`. The system also accepts equivalent forms for environments where angle brackets in comments are awkward:

```
@vouch-rule[scope=function,severity=block] Body must not appear in any external output
[[vouch:rule scope=class]] Class implementation is proprietary
```

All variants produce identical ledger entries.

### 5.2 Watcher implementation (reference)

```python
def on_save(filepath):
    lang = detect_language(filepath)
    src = read(filepath)
    if has_ast_parser(lang):
        rules = extract_via_ast(src, lang)
    else:
        rules = extract_via_regex(src)
    current = load_ledger_entries_for_file(filepath)
    diff = compute_rule_diff(current, rules)
    for r in diff.added:
        write_ledger_entry(r)
    for r in diff.removed:
        write_tombstone(r)
    for r in diff.modified:
        write_tombstone(r.old)
        write_ledger_entry(r.new)
```

### 5.3 Per-language extractors

For each supported language, the extractor is a small adapter (under 100 lines) on top of the language's AST parser:

```
extractors/
  python.py      (libcst)
  typescript.ts  (typescript compiler API)
  go.go          (go/ast)
  rust.rs        (syn)
  generic.py     (regex fallback)
```

### 5.4 Conflict resolution with chat-declared rules

Source-derived rules and chat-derived rules co-exist in the same `.vouchpolicy`. Conflicts (two rules with overlapping scope and contradictory severity) are resolved by:

1. Most specific scope wins (function > class > file > workspace).
2. At equal specificity, most recent declaration wins.
3. Both rules are retained in the audit archive for traceability.

### 5.5 Performance

The watcher's CPU and I/O cost is negligible relative to the developer's editor (a single file save triggers a parser invocation, which is millisecond-scale). The watcher does not reparse files that have not changed.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A method for declaring operational policy rules inside source code comments using a structured tag grammar, where the rule is **intentionally not enforced by the Large Language Model** that reads or edits the file, and where enforcement is performed exclusively by a separate file-system watcher operating in a distinct trust domain.

2. A passive file-system watcher that detects source file save events, identifies the file's language, applies AST-aware extraction or regex fallback to locate rule tags, and emits structured ledger entries for downstream deterministic enforcement, without invoking any LLM.

3. An AST-aware scope inference mechanism that attributes each extracted rule to its smallest enclosing function, class, or file, so that downstream enforcement layers can match diffs against the correct scope.

4. A dual-consumer architecture in which both an LLM coding assistant and a deterministic policy-extraction watcher read the same source comments with explicitly asymmetric responsibilities, and in which the LLM's non-enforcement is established by workspace directive or by absence of any directive instructing enforcement.

5. An idempotent re-extraction mechanism in which adding, modifying, or removing a rule tag in source code produces corresponding additions, modifications, or tombstones in the policy ledger on the next file save event, without any rule-management user interface.

6. The combination of (1) through (5) as an integrated method for source-code-resident operational policy declaration in LLM coding assistant workflows.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
