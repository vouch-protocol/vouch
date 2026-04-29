# PAD-053: Time-Bounded Ephemeral Rules with Auto-Expiry for LLM Coding Assistant Sessions

**Identifier:** PAD-053
**Title:** Method for Declaring Time-Bounded Ephemeral Operational Rules in LLM Coding Assistant Sessions with Deterministic Auto-Expiry, Optional Severity Escalation, and Audit Trail of Expiry Events
**Publication Date:** April 30, 2026
**Prior Art Effective Date:** April 30, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / LLM Coding-Assistant Governance / Policy Lifetime Management / Mode Switching / Audit Trail
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-016 (Dynamic Credential Renewal), PAD-032 (Cryptographic Mortality Protocol), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-049 (Decoupled Semantic Policy Extraction), PAD-050 (Zero-Context Deterministic Egress Interception)

---

## 1. Abstract

A method for declaring **time-bounded ephemeral rules** in an LLM coding assistant session, by extending the rule-tag grammar of PAD-048 with an `expires` attribute that specifies a duration (`30m`, `2h`, `7d`) or an absolute timestamp after which the rule is deterministically removed from active policy by the Compactor. The method enables developers to switch between "strict mode" (heavy rule enforcement during production-impacting work) and "exploration mode" (relaxed enforcement during prototyping and debugging) without manually deleting rules afterwards.

In addition to simple removal, the method supports **severity escalation on near-expiry** (a `block`-severity rule converts to `attest` in its final 10% of lifetime, surfacing to the developer that it is about to lapse) and a **complete audit trail of expiry events** (every expired rule is preserved in `.vouch/archive/expired/` with the original declaration and the expiry timestamp, so that downstream auditors can reconstruct the policy in effect at any past moment).

Key innovations:

- **Grammar-level expiry attribute.** The expiry is part of the rule declaration, not a separate management action. The rule and its lifetime are co-declared.
- **Deterministic auto-decay.** The Compactor (PAD-048) enforces expiry. No LLM is involved. A rule declared with `expires=2h` is observably gone two hours later, regardless of session state, machine reboots, or LLM context.
- **Severity escalation.** Optional pre-expiry escalation gives the developer warning that a rule they relied on is about to lapse, preventing surprise relaxation.
- **Audit-grade archive.** Expired rules are preserved, not deleted, so that "what policy was in effect when this push happened?" is always answerable.
- **Compositionality with mode-switching.** A developer can declare a batch of strict rules with `expires=8h` at the start of a workday and rely on auto-decay at end of day, without an explicit cleanup step.

---

## 2. Problem Statement

### 2.1 Strict permanent rules block legitimate exploration

A rule like "block any push touching the credentials module" is appropriate during production-impacting work but obstructive during a two-hour session refactoring credential handling. Developers in the latter scenario either:

- Disable Amnesia entirely (loses all protection).
- Manually edit `.vouchpolicy` to remove the rule (loses audit trail, requires manual restoration later).
- Ignore the silent block when it fires (degrades the system's value).

None of these are good outcomes.

### 2.2 Manual rule cleanup is forgotten

Developers who declare temporary rules ("for the next hour, do not push to main") routinely forget to remove them when the temporary condition ends. The rule then persists indefinitely, accumulates ambient drag on subsequent sessions, and erodes confidence in the system.

### 2.3 No standard exists for rule lifetime in LLM coding workflows

Existing AI-assistant context conventions (`CLAUDE.md`, `.cursor/rules`, system prompts) treat rules as static. There is no first-class notion of "this rule is valid only for the next two hours" with deterministic enforcement of the lifetime.

### 2.4 Rules that silently lapse can be more dangerous than rules that persist

If a developer relied on a rule (`block pushes to main`) and the rule silently expired without warning, the developer's mental model of system safety becomes wrong. The system needs to either:

- Be very loud about expiry (which is what the audit archive provides).
- Escalate severity in advance of expiry to give the developer a chance to renew (which is what severity escalation provides).

Neither is currently standard.

---

## 3. Solution (The Invention)

### 3.1 Expiry attribute grammar

The rule tag is extended with an `expires` attribute:

```
<r expires="2h"> Block public pushes during this debugging window </r>
<r expires="2026-05-01T09:00:00Z"> No production deployments before 9am UTC </r>
<r expires="end-of-session"> Treat this prototype directory as throwaway </r>
```

Acceptable expiry forms:

| Form | Meaning |
|---|---|
| `<duration>` | Relative to declaration time: `15m`, `1h`, `2h`, `8h`, `1d`, `7d` |
| `<ISO-8601 timestamp>` | Absolute expiry instant |
| `end-of-session` | Removed when the next session-end signal is observed |
| `end-of-day` | Removed at local midnight |
| `next-push` | Removed after the next successful `git push` |
| `never` | Default; equivalent to omitting the attribute |

### 3.2 Compactor expiry enforcement

The Compactor (PAD-048) examines the `expires` field of each ledger entry on every compaction pass. A rule whose expiry is in the past is:

1. Removed from the active `.vouchpolicy` artifact.
2. Moved to `.vouch/archive/expired/<date>/rule_<id>.json` with the original declaration intact.
3. Logged to `.vouch/expiry-events.log` with the expiry timestamp.

The Compactor's pass period (default 30 seconds, configurable down to 5 seconds) bounds the latency between expiry and removal.

### 3.3 Severity escalation on near-expiry

Rules declared with `severity=block` and an `expires` attribute may opt in to severity escalation:

```
<r expires="2h" escalate="true"> Block pushes to main </r>
```

When the rule has less than 10% of its lifetime remaining (or less than 5 minutes for any rule with lifetime under 50 minutes), the Compactor downgrades its severity from `block` to `attest`. The next push that would have been blocked instead generates an attestation describing the impending expiry, surfacing to the developer that the rule is about to lapse.

The developer can:

- Renew the rule (`<r expires="2h" renew="true"> ... </r>` extends the existing rule rather than creating a new one).
- Promote it to permanent (`<r expires="never"> ... </r>` overrides the prior declaration).
- Allow expiry.

### 3.4 Expiry audit trail

Every expiry event is preserved:

```
.vouch/archive/expired/
  2026-04-30/
    rule_1714400111000_a8f3d1b2.json     (original declaration)
    rule_1714400222000_c2e9a410.json
.vouch/expiry-events.log
```

The expiry log entries are line-oriented JSON:

```json
{"id":"rule_1714400111000_a8f3d1b2","declared_at":"2026-04-30T08:00:00Z","expired_at":"2026-04-30T10:00:00Z","reason":"duration_2h","escalated":true,"renewed":false}
```

This enables a downstream auditor to answer "what rules were active when this push occurred at 09:47 UTC on 2026-04-30?" by replaying ledger declarations and expiry events up to that timestamp.

### 3.5 Composition with cross-session re-anchoring

Rules with `expires=end-of-session` are removed at session end and are NOT re-injected by the cross-session re-anchoring mechanism of PAD-055. Rules with absolute expiry timestamps may persist across sessions, with their lifetime continuing to count down even when no session is active. The Compactor's enforcement is independent of session state.

---

## 4. Prior Art Differentiation

| System | Time-bounded rules? | Deterministic auto-decay? | Severity escalation on near-expiry? | Audit archive of expired rules? | LLM coding assistant domain? |
|---|---|---|---|---|---|
| Cron jobs | Yes (scheduled actions, not rules) | Yes | No | Sometimes | No |
| Feature flags with TTL (LaunchDarkly, Unleash) | Yes | Yes | Sometimes | Yes | No |
| Firewall rules with TTL (iptables `--rsource`, AWS WAF) | Yes | Yes | No | Sometimes | No |
| Calendar reminders | Yes | Yes | No | Yes | No |
| `CLAUDE.md` / `.cursor/rules` | No | N/A | N/A | N/A | Yes |
| **This disclosure** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |

Differentiating claims:

1. The combination of grammar-level expiry declaration, deterministic Compactor-enforced auto-decay, optional severity escalation in the final lifetime window, and complete audit archive of expired rules, applied to the LLM coding assistant policy domain, is novel.
2. The use of severity escalation (block to attest) as a near-expiry warning, designed to prevent silent lapse from changing the developer's effective policy mental model, is a deployable safety pattern not present in prior temporal-policy systems.
3. The integration with the chat-tag declaration (PAD-048), source-comment declaration (PAD-049), and cross-session re-anchoring (PAD-055) mechanisms, all sharing a single `expires` attribute semantics, is novel as an integrated lifetime-management architecture for LLM-coding-assistant policy.

---

## 5. Technical Implementation

### 5.1 Compactor extension

The Compactor's existing entry processing (PAD-048 section 3.4) gains an expiry filter:

```python
def is_active(rule, now):
    if rule.expires is None or rule.expires == "never":
        return True
    expiry_ts = parse_expiry(rule.expires, rule.declared_at, now)
    return now < expiry_ts

def expiry_remaining(rule, now):
    expiry_ts = parse_expiry(rule.expires, rule.declared_at, now)
    return max(0, expiry_ts - now)

def is_near_expiry(rule, now):
    if not rule.escalate:
        return False
    total = parse_expiry(rule.expires, rule.declared_at, now) - rule.declared_at
    remaining = expiry_remaining(rule, now)
    return remaining < max(total * 0.1, timedelta(minutes=5))
```

### 5.2 Renewal semantics

A renewal declaration:

```
<r expires="2h" renew="true" body="Block pushes to main">
```

is matched against existing rules by body equivalence (case-insensitive, whitespace-normalized). When matched, the existing rule's `expires` field is updated, its declaration timestamp is preserved, and a renewal event is logged. When no match exists, the renewal directive is treated as a fresh declaration.

### 5.3 Session boundaries

The session boundary (`end-of-session`, `end-of-day`) is observed via:

- Explicit signals from the assistant client (when supported).
- Heuristic: no LLM API traffic for a configurable idle period (default 15 minutes).
- User command: `amnesia session end`.

### 5.4 Push-bound expiry

`expires="next-push"` rules are observed by the egress hook of PAD-050. After a successful push, the hook signals the Compactor to expire any `next-push` rules that were active at decision time.

### 5.5 Performance

Expiry processing is O(N) per Compactor pass, where N is the number of active rules. For workspaces with thousands of rules, the per-pass cost is sub-millisecond.

---

## 6. Claims Summary

The following aspects are disclosed as prior art:

1. A method for declaring time-bounded operational rules in LLM coding assistant sessions via a grammar-level `expires` attribute supporting relative durations, absolute timestamps, session-relative bounds, push-bound lifetime, and named end-of-day or end-of-session anchors.

2. Deterministic Compactor-enforced auto-decay in which expired rules are removed from the active policy artifact, archived with their original declaration, and logged with an expiry-event record, on a configurable polling interval.

3. Optional severity escalation in which a rule declared with `severity=block` and the `escalate=true` directive automatically downgrades to `severity=attest` in the final 10% of its lifetime (or final 5 minutes for short-lifetime rules), surfacing impending expiry to the developer through the egress attestation channel.

4. A complete audit archive in which every expired rule is preserved with its original declaration and expiry timestamp, enabling reconstruction of the policy in effect at any historical moment for downstream audit purposes.

5. Renewal semantics in which a re-declaration of an existing rule (matched by body equivalence) extends the rule's lifetime in place rather than creating a duplicate, preserving the original declaration timestamp and logging the renewal event.

6. The combination of (1) through (5), composed with the chat-tag declaration of PAD-048, the source-comment declaration of PAD-049, the egress enforcement of PAD-050, and the cross-session re-anchoring of PAD-055, into a unified lifetime-management architecture.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
