# PAD-055: Cross-Session Policy Re-Anchoring via Pre-Flight Context Replay for LLM Coding Assistants

**Identifier:** PAD-055
**Title:** Method for Re-Establishing Operational Policy Across Discontinuous LLM Coding Assistant Sessions via Pre-Flight Injection of Compacted Policy as a System-Priority Context Message
**Publication Date:** April 30, 2026
**Prior Art Effective Date:** April 30, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / LLM Coding-Assistant Governance / Session Continuity / Pre-Flight Context Injection / Policy Persistence
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-016 (Dynamic Credential Renewal), PAD-020 (Ratchet Lock Protocol), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-049 (Decoupled Semantic Policy Extraction), PAD-053 (Time-Bounded Ephemeral Rules)

---

## 1. Abstract

A method for closing the "new session resets the rules" gap in LLM coding assistant workflows. Even when in-session policy capture (PAD-048), source-comment policy (PAD-049), and parallel-extraction (PAD-051) are all functioning, a developer who closes their assistant client and opens a new session typically begins with an empty context window. The rules persisted on disk are still enforced by the deterministic egress layer (PAD-050), but the LLM driving the new session is not aware of them and will routinely propose actions that the egress layer will silently block, creating a frustrating "every push fails for unexplained reasons" experience.

The method addresses this by **re-anchoring policy at session start** through a transparent pre-flight context injection. When the developer's assistant client begins a new session, a small wrapper (the same proxy of PAD-051, or a thin assistant-specific shim) reads the current `.vouchpolicy` from disk, compacts it into a token-efficient summary, and injects the summary as a high-priority system message into the session's initial context. The LLM begins the session already aware of the active rules and reasons about its proposed actions accordingly, producing fewer silently-blocked pushes.

Key innovations:

- **Pre-flight injection.** The injection happens before the developer's first prompt, as part of the session bootstrap, rather than mid-conversation where it would compete with the developer's intent.
- **Token-efficient compaction.** A summary representation of the policy is generated specifically for context injection, avoiding the overhead of dumping the full ledger or all archived rules.
- **Survival of session discontinuity.** Rules persist across application restarts, machine reboots, branch switches, and developer hand-offs.
- **Defends against "new session resets the rules" attacks.** A bad-faith user (or an LLM agent operating on behalf of one) cannot circumvent rules by opening a new session, because the new session re-anchors to the persisted policy.
- **Optional opt-out per session.** A developer who genuinely wants a clean-slate session for legitimate reasons can opt out for a single session via a side-channel command, with that opt-out logged.

---

## 2. Problem Statement

### 2.1 New session = blank slate for the LLM

When a developer opens a fresh chat in their AI coding assistant, the LLM's context starts empty (or with whatever is in the workspace context file). Rules declared in a prior session, even rules that are still active and enforceable on disk, are not present in the LLM's working memory.

### 2.2 The disk policy is enforced, but the LLM does not know about it

The egress layer (PAD-050) reads `.vouchpolicy` from disk and enforces it deterministically. So pushes that violate persisted rules are silently blocked. But the LLM, having not seen the rules, has no way to know what is forbidden and may repeatedly propose blocked actions, leading to the developer experience of "every push fails for some unclear reason."

The block is correct (the rule still applies); the failure mode is the missed opportunity to inform the LLM and let it propose actions that would actually succeed.

### 2.3 Re-asking the developer to re-declare every rule each session is broken UX

A naive solution is to require the developer to re-declare any persistent rules at session start. This is the wrong design: the rules are persisted on disk for a reason (they apply across time), and the developer should not be punished for closing their laptop.

### 2.4 "New session" is a circumvention vector if not handled

A bad-faith user (or a manipulated LLM agent acting on a user's behalf) can attempt to bypass restrictive rules by simply opening a new session. The egress layer still enforces the rules, but the developer's mental model may incorrectly suggest that "fresh session = fresh rules," leading to operator confusion and trust degradation. The method must close this circumvention vector explicitly.

### 2.5 No prior system performs deterministic pre-flight injection of compacted persistent policy into LLM coding sessions

The combination, persistent policy + token-efficient compaction + automatic session-start re-anchoring + per-session opt-out + audit logging, is novel.

---

## 3. Solution (The Invention)

### 3.1 Pre-flight injection mechanism

When a session begins, the wrapper performs:

1. Detect new-session signal (assistant client opens, first API request, or explicit `amnesia session start` command).
2. Read the current `.vouchpolicy` from disk (and any inherited `.vouchpolicy` files per PAD-054).
3. Compact the active rule set into a structured summary (section 3.2).
4. Construct a high-priority system message containing the summary.
5. Inject the system message as the first item in the new session's context (or prepended to the existing system prompt if one is present).
6. Log the injection event to `.vouch/session-anchors.log`.

The developer's first user prompt is processed by the LLM with the policy already in context.

### 3.2 Token-efficient compaction

The compactor produces a compact summary keyed for in-context efficiency:

```
Active operational rules (standard, machine-binding):

1. [block] Never push files containing AWS_ACCESS_KEY_ID patterns. (workspace)
2. [block] internal/payments/ is in regulatory freeze; no pushes until 2026-05-15. (directory: internal/payments)
3. [attest] All pushes to refs/heads/main require attached attestation. (workspace)
4. [advisory] Prefer feature branches over main commits. (workspace)
5. [block] compute_proprietary_score() body must not appear in any external output. (function: compute_proprietary_score in scoring/internal.py)

Source: .vouchpolicy at 2026-04-30T08:34:12Z
Total active rules: 5
Total archived expired: 12 (see .vouch/archive/expired/)

These rules are enforced deterministically at egress. You should propose
actions consistent with them; actions that violate them will be blocked
without further user dialogue.
```

The summary is generated by a small deterministic script (no LLM call). Each rule is one line. The total token cost is approximately 30-50 tokens per rule, and most workspaces have under 50 active rules, putting the total injection cost at well under 2,500 tokens.

### 3.3 Injection target: priority message slot

The wrapper places the summary at the **highest-priority** position the assistant supports:

| Assistant | Highest-priority position |
|---|---|
| Anthropic Messages API | First message in `system` array |
| OpenAI Chat Completions | `system` role message at index 0 |
| Aider | First user message after system prompt (Aider does not expose system slot to users) |
| Cursor | Workspace `.cursor/rules/*.mdc` reload + chat-message header |
| Claude Code | `CLAUDE.md` reload + project-instructions reset |

The wrapper detects which assistant is in use (via the API endpoint pattern, the model identifier, or an explicit configuration) and injects accordingly.

### 3.4 Per-session opt-out

A developer who genuinely needs a clean-slate session (e.g., to test a tool's behavior without policy interference, or to write code that would be incorrectly flagged by a stale rule) can opt out:

```
amnesia session-start --no-anchor --reason "Testing isolated build"
```

The wrapper:

1. Skips the policy injection for this session.
2. Logs the opt-out to `.vouch/session-anchors.log` with the reason text.
3. Marks the session as un-anchored in the egress hook's session tag (so that the hook can apply stricter scrutiny if configured).

The egress layer (PAD-050) still enforces all rules regardless of opt-out. Opt-out only affects whether the LLM is informed at session start; it does not affect what is actually permitted.

### 3.5 Audit log

Every session anchor (or skipped anchor) is logged:

```json
{
 "ts": "2026-04-30T08:34:12Z",
 "session_id": "sess-...",
 "assistant": "claude-code",
 "anchored": true,
 "rule_count": 5,
 "compacted_token_estimate": 312,
 "policy_hash": "sha256-..."
}
```

The `policy_hash` is the SHA-256 of the active `.vouchpolicy` at injection time, enabling auditors to verify which exact policy was anchored into which session.

### 3.6 Combination with cross-session ephemeral rules

Rules with `expires=end-of-session` (PAD-053) are NOT injected at the start of a new session, because they expired at the end of the prior session. Rules with absolute or duration-based expiry that have not yet elapsed ARE injected, with their remaining lifetime communicated in the summary:

```
2. [block] internal/payments/ in regulatory freeze; no pushes (expires in 14d 6h).
```

---

## 4. Prior Art Differentiation

| System | Policy persisted across sessions? | Auto re-injected at session start? | Token-efficient compaction? | Per-session opt-out with audit? | Defends against new-session circumvention? |
|---|---|---|---|---|---|
| `CLAUDE.md`, `.cursor/rules` (static workspace files) | Yes | Yes (read at session start by assistant) | No (full file is loaded) | No (manual edit only) | No |
| AI agent long-term memory (MemGPT, Letta) | Yes | Yes (memory recall) | Variable | No | Partially (memory may be stale) |
| LangChain conversation memory | Yes (within app) | Yes (within app) | Variable | No | No (cross-app) |
| Retrieval-Augmented Generation systems | Yes | Yes (per-query retrieval) | Variable | No | No (RAG is per-query, not session-anchor) |
| Pre-commit hook configurations (Husky, etc.) | Yes (on disk) | N/A (no LLM in loop) | N/A | N/A | N/A |
| **This disclosure** | **Yes** | **Yes (deterministic, scripted)** | **Yes** | **Yes (with audit log)** | **Yes (explicit defense)** |

Differentiating claims:

1. The combination of (a) persistent policy on disk, (b) deterministic non-LLM compaction at session start, (c) injection at the highest-priority context slot the assistant supports, (d) per-session audit-logged opt-out, and (e) explicit framing as a defense against new-session circumvention, applied to LLM coding assistants, is novel.
2. The token-efficient compaction strategy (one-line summary per rule, scope-tagged) targets LLM-coding-assistant context-window economy and is not present in generic AI-memory systems that re-inject full memory state.
3. The audit log including a hash of the exact policy injected, plus the assistant identification and session ID, provides a verifiable record for compliance use cases that requires no LLM in the audit loop.

---

## 5. Technical Implementation

### 5.1 Session detection

For assistants with explicit session boundaries (the conversation API has a `session_id` or thread concept), the wrapper detects new-session signals from the API. For assistants without explicit sessions, the wrapper uses heuristics:

- A request with no prior history in the current process / proxy connection.
- A configurable idle period since the last request (default 15 minutes).
- An explicit `amnesia session start` command.

### 5.2 Compactor algorithm

```python
def compact_for_anchor(policy):
  lines = []
  for r in policy.active_rules:
    scope = format_scope(r.scope)
    sev = f"[{r.severity}]"
    body = r.body
    expiry = format_remaining_lifetime(r) if r.expires else None
    line = f"{sev} {body} ({scope})"
    if expiry:
      line += f" (expires in {expiry})"
    lines.append(line)
  return PREAMBLE + "\n".join(f"{i+1}. {l}" for i, l in enumerate(lines)) + POSTAMBLE
```

### 5.3 Assistant-specific injection

The wrapper maintains an injection adapter per assistant. For Anthropic:

```typescript
function injectAnthropic(request, summary) {
 if (Array.isArray(request.system)) {
  request.system = [{
   type: "text",
   text: summary,
   cache_control: { type: "ephemeral" }
  }, ...request.system];
 } else {
  request.system = `${summary}\n\n---\n\n${request.system ?? ""}`;
 }
 return request;
}
```

For OpenAI:

```typescript
function injectOpenAI(request, summary) {
 request.messages = [
  { role: "system", content: summary },
  ...request.messages
 ];
 return request;
}
```

The `cache_control: ephemeral` hint (Anthropic) signals that the policy summary is suitable for prompt caching, reducing token cost on subsequent requests in the same session.

### 5.4 Failure modes

If the wrapper cannot inject (assistant is offline, configuration is missing, the API does not support the system slot the wrapper expects), it logs the failure and proceeds without anchoring. The egress layer (PAD-050) still enforces all rules. The result is the legacy "new session is uninformed" behavior, with a logged warning.

### 5.5 Performance

The compaction is deterministic, runs in milliseconds for any reasonable rule count, and is performed once per session (not per request). Anthropic prompt caching reduces the steady-state token cost to near-zero for subsequent requests.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A method for re-anchoring operational policy at the start of each LLM coding assistant session by detecting a new-session signal, reading the current persisted policy from disk, generating a token-efficient compacted summary, and injecting the summary as a high-priority system context message before the developer's first prompt is processed.

2. A token-efficient compaction strategy in which the active policy is rendered as a structured one-line-per-rule summary with scope tags, severity tags, and remaining-lifetime annotations, optimized for LLM context economy and produced deterministically without any LLM call.

3. An assistant-specific injection adapter library that selects the highest-priority context slot supported by the target assistant (system message array, system role message, workspace context file reload, or equivalent) and injects the summary at that slot.

4. A per-session opt-out mechanism in which the developer can request an un-anchored session via a side-channel command, with the opt-out logged including the developer's stated reason, and with the egress enforcement layer optionally applying stricter scrutiny to un-anchored sessions.

5. An audit log of session-anchor events including timestamp, session identifier, assistant identification, anchor decision, active-rule count, compacted token estimate, and a SHA-256 hash of the exact policy injected, enabling reconstruction of which rules informed which session.

6. The framing of the method as an explicit defense against circumvention attacks where a bad-faith user or manipulated LLM agent attempts to bypass persistent rules by opening a new session.

7. The combination of (1) through (6), composed with the persistent policy mechanisms of PAD-048, the source-comment policy of PAD-049, the egress enforcement of PAD-050, and the ephemeral-rule lifetime semantics of PAD-053.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
