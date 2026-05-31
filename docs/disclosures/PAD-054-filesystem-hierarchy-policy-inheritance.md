# PAD-054: Filesystem-Hierarchy Policy Inheritance for LLM Coding Assistant Workspaces

**Identifier:** PAD-054  
**Title:** Method for Cascading Operational Policy Across Nested Directory Hierarchies in LLM Coding Assistant Workspaces with Override Semantics, Union Semantics, and Explicit Inheritance Blocking  
**Publication Date:** April 30, 2026  
**Prior Art Effective Date:** April 30, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / LLM Coding-Assistant Governance / Monorepo Tooling / Policy Composition / Filesystem-Hierarchy Semantics  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-022 (Swarm Limits Protocol), PAD-038 (Agent Capability Discovery), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-049 (Decoupled Semantic Policy Extraction), PAD-050 (Zero-Context Deterministic Egress Interception)  

---

## 1. Abstract

A method for distributing operational policy across a developer's workspace by placing `.vouchpolicy` (and the per-rule ledger directory `.vouch/ledger/`) in any directory at any depth within the project tree, with cascade semantics that mirror the well-understood inheritance behavior of `.gitignore` and `.editorconfig`, but with explicit support for **rule union**, **scope-aware override**, and **inheritance blocking** directives. The method enables monorepos and nested-project layouts to express policy that varies by sub-project ("the `internal/` directory has stricter pushrules than `public/`"), while still allowing workspace-wide rules ("never push AWS keys, anywhere") to apply uniformly.

The keystone property is **predictable composition**. When a developer (or an LLM coding assistant) takes an action inside a sub-directory, the egress enforcement layer (PAD-050) collects rules from the sub-directory's `.vouchpolicy`, walks up the directory tree collecting parent `.vouchpolicy` files, applies a deterministic merge algorithm, and produces a single effective policy for that location. The merge is byte-deterministic given the same set of files; identical inputs always produce identical effective policy.

Key innovations:

- **Hierarchical placement.** Any directory may host its own `.vouchpolicy` and `.vouch/ledger/`, not only the workspace root.
- **Union by default.** A rule defined at any ancestor applies at the descendant, so workspace-wide rules do not need to be repeated.
- **Override by scope identity.** When two rules from different levels share the same scope-identity tuple (`scope`, `target`), the closer rule wins (descendant overrides ancestor), as in `.editorconfig`'s "child wins" semantics.
- **Explicit inheritance blocking.** A directive `vouch:inherit none` in a `.vouchpolicy` halts ancestor traversal at that level, for the rare case where a sub-project must be quarantined from the parent's policy.
- **Reverse traversal optimization.** The egress hook caches resolved policy per directory and invalidates caches on filesystem changes, so policy resolution is constant-time after the first lookup.

---

## 2. Problem Statement

### 2.1 Monorepos contain heterogeneous sub-projects with heterogeneous policy needs

A typical monorepo has structure like:

```
my-monorepo/
  public-library/        (will be open-sourced; lax rules)
  internal-services/     (proprietary; strict rules)
    payments/            (PCI scope; strictest)
    notifications/       (less sensitive)
  experiments/           (throwaway; near-zero rules)
  vendor/                (third-party code; do-not-touch rules)
```

A single workspace-root `.vouchpolicy` cannot express this. Either it is too strict (blocks legitimate work in `public-library/` and `experiments/`) or too lax (allows leaks from `internal-services/payments/`).

### 2.2 Workspace-wide rules need to apply uniformly without duplication

A rule like "never push any file containing an AWS Access Key ID pattern" should apply at every depth. Requiring the developer to copy this rule into every sub-project's `.vouchpolicy` is error-prone and creates drift over time.

### 2.3 Sub-project quarantine is occasionally necessary

A vendored third-party directory (`vendor/` or `node_modules/`) may need policy that is incompatible with the parent's rules, and the developer may want explicit quarantine semantics: "this sub-tree has its own world; do not apply parent rules here."

### 2.4 Existing static-config inheritance models do not generalize

`.gitignore`, `.editorconfig`, `tsconfig.json` (with `extends`), and similar tools each have their own inheritance semantics, but none of them are designed for the composition needs of LLM-coding-assistant policy:

- `.gitignore` only adds; it cannot un-ignore from a sub-directory unless the parent already un-ignored.
- `.editorconfig` has explicit `root = true` to halt ancestor traversal but does not support per-rule override identity.
- `tsconfig.json extends` has explicit inheritance but is a single-file inherit, not a tree cascade.

A purpose-built inheritance model is needed, drawing on the strengths of these prior systems but tuned for policy composition.

---

## 3. Solution (The Invention)

### 3.1 Hierarchical placement

Any directory may host:

```
<dir>/
  .vouchpolicy             (compacted rules effective at and below this directory)
  .vouch/
    ledger/                (per-rule entries; consumed by Compactor)
    archive/
    quarantine/
```

The Compactor at each level is the same binary; it operates on the local `.vouch/ledger/` and emits the local `.vouchpolicy`. There is no per-level Compactor configuration.

### 3.2 Cascade lookup algorithm

When a rule is needed for an operation at path `P`:

```
1. Initialize effective_policy as empty.
2. Set current = directory of P.
3. Loop:
   a. If current/.vouchpolicy exists:
        Parse it. Apply merge (section 3.3) into effective_policy.
        If the file declares "vouch:inherit none", break.
   b. If current is the filesystem root (or the workspace root marker), break.
   c. current = parent(current).
4. Return effective_policy.
```

The traversal proceeds from the action's directory upward to the workspace root (or until an inheritance-blocking directive is encountered).

### 3.3 Merge algorithm: union by default, override by scope identity

When merging a parent policy into the effective policy (which may already contain descendant rules), the algorithm:

1. **Union:** Every rule in the parent is added to the effective policy, unless an existing rule has the same scope-identity tuple.
2. **Override:** Two rules with the same `(scope, target)` tuple are considered identity-conflicting. The descendant rule wins; the parent rule is recorded in the audit channel (`.vouch/merge-audit.log`) but does not affect enforcement.
3. **Severity merge:** When two rules from different levels target overlapping scopes but not identical scope-identity, the more restrictive severity applies. Order: `block > attest > advisory`.

Identity tuple format:

```
(scope, target) = (
    "function" | "class" | "file" | "directory" | "workspace" | "global",
    <fully qualified path or identifier>
)
```

### 3.4 Inheritance blocking directive

A `.vouchpolicy` file may begin with:

```yaml
vouch:
  inherit: none
```

This halts the cascade traversal at this level. Any `.vouchpolicy` at higher ancestor levels does not contribute. This is intended for vendored directories or explicitly quarantined sub-trees.

A weaker form:

```yaml
vouch:
  inherit: explicit
  inherit_from:
    - "rule_id_1"
    - "rule_id_2"
```

allows the developer to specify which parent rules to inherit, ignoring the rest.

### 3.5 Egress-hook resolution

The pre-push hook (PAD-050) resolves effective policy as follows:

1. For each file in the diff, compute its absolute path.
2. Run the cascade lookup (3.2) for each file, producing the effective policy at that file's location.
3. Evaluate the file's diff against that effective policy.
4. The push is allowed only if every file's diff passes its respective effective policy.

This ensures that a single push touching files in different sub-trees is evaluated against the correct policy for each.

### 3.6 Caching

Resolved effective policies are cached in `.vouch/cache/effective_<dir_hash>.json`, keyed by the directory and a hash of all `.vouchpolicy` files in the cascade. The cache is invalidated whenever any `.vouchpolicy` in the cascade changes. Cache validity is verified at start of each cascade lookup.

---

## 4. Prior Art Differentiation

| System | Hierarchical placement? | Union by default? | Scope-identity override? | Explicit inheritance blocking? | Domain |
|---|---|---|---|---|---|
| `.gitignore` | Yes | Yes (additive) | No (cannot override parent ignores from child) | No (only via `!` un-ignore) | Generic VCS |
| `.editorconfig` | Yes | Yes | Yes (last-match wins, per-key) | Yes (`root = true`) | Editor settings |
| `tsconfig.json extends` | No (single-file inherit) | Yes | Per-key | N/A | TypeScript config |
| `package.json` workspaces | No | N/A (per-package configs) | N/A | N/A | npm tooling |
| OPA/Rego policy bundles | No (flat policy directory) | Yes | Per-rule | No | Generic policy |
| AWS IAM policy hierarchy | Yes (via SCP and resource policies) | Yes | Yes | Partial | Cloud IAM |
| **This disclosure** | **Yes** | **Yes** | **Yes (by scope-identity tuple)** | **Yes (explicit directive)** | **LLM coding assistants** |

Differentiating claims:

1. The combination of hierarchical placement, default union semantics, scope-identity-based override semantics, and explicit inheritance-blocking directive, applied to the LLM coding assistant policy domain, is novel.
2. The scope-identity tuple as the override key (rather than rule-name or full-rule equality) supports natural policy composition because it lets a sub-project tighten or relax a single targeted rule without affecting the parent's other rules at the same scope.
3. The integration with the egress hook of PAD-050, in which per-file effective policy is computed for every file in a diff, ensures correct enforcement even when a single push spans heterogeneous sub-trees.

---

## 5. Technical Implementation

### 5.1 `.vouchpolicy` file format with inheritance directives

```yaml
vouch:
  version: 1
  inherit: union           # or "none" or "explicit"
  # inherit_from: [...]    # only used when inherit: explicit

rules:
  - id: rule-001
    scope: { kind: directory, target: ./payments }
    severity: block
    body: "Block any push touching payments/ during regulatory freeze"
    expires: "2026-05-15T00:00:00Z"
  - id: rule-002
    scope: { kind: file, target: ./README.md }
    severity: advisory
    body: "Pushes to README require sign-off"
```

### 5.2 Workspace-root marker

To avoid traversing past the developer's intended workspace boundary, the cascade lookup stops at any directory containing a workspace-root marker:

```
.git/                          (standard)
.vouch/workspace-root           (explicit Amnesia marker)
package.json with "vouch.root: true"  (npm-aware)
```

The first marker encountered terminates traversal even if `vouch:inherit` is not set to `none`.

### 5.3 Merge audit log

Each merge operation that resolves a conflict via override is logged:

```
.vouch/merge-audit.log:
{"ts":"...","at":"./internal/payments","child_rule":"rule-payments-block","overridden_parent":"rule-workspace-block","kept":"child"}
```

This preserves the audit property: any auditor can reconstruct exactly which rule fired at which level for any past action.

### 5.4 Performance

For a workspace with N levels of `.vouchpolicy` files in the cascade and M rules per file, cascade lookup is O(N * M) without cache. With cache (which is the common case), it is O(1). Filesystem watcher invalidates the cache on change, so the cache is never stale.

### 5.5 IDE integration

When a developer-IDE integration is present, the IDE may surface the effective policy for the currently-edited file in a side panel ("Active rules at this location"). This is read-only display; rule modification still goes through the standard chat-tag, source-comment, or proxy channels of PAD-048 / PAD-049 / PAD-051.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A method for placing `.vouchpolicy` and `.vouch/ledger/` directories at arbitrary depth in a workspace, with each level operating an independent Compactor on its local ledger and emitting its local compacted policy artifact.

2. A cascade lookup algorithm that, for any operation at any path, walks the directory tree from the operation's location upward to a workspace-root marker, collecting and merging `.vouchpolicy` files along the path to produce the effective policy for that location.

3. A merge algorithm with union semantics by default, scope-identity-based override (descendant wins for same `(scope, target)` tuple), and severity merge by maximum restrictiveness across overlapping non-identical scopes.

4. An explicit inheritance-blocking directive (`vouch:inherit: none`) that halts cascade traversal at a given level, enabling vendored or quarantined sub-trees to be insulated from ancestor policy.

5. An integration with the pre-push egress hook in which per-file effective policy is computed independently for every file in a diff, so that a multi-file push spanning heterogeneous sub-trees is evaluated against the correct policy at each file's location.

6. A merge audit log that records every override decision with timestamp, location, child rule, parent rule, and outcome, enabling reconstruction of which rule fired at which cascade level for any past push.

7. A workspace-root marker mechanism that terminates cascade traversal at the developer-intended workspace boundary, supporting `.git/`, an explicit Amnesia marker, or an `npm` package-level marker.

8. The combination of (1) through (7) as an integrated hierarchical policy composition architecture for LLM coding assistant workspaces.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
