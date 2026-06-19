# PAD-060: Single-Use Audited Override of a Deterministic Egress Block

**Identifier:** PAD-060  
**Title:** Method for One-Time Time-Bounded Override of a Deterministic Egress-Time Policy Block, with Cryptographically Auditable Override Event and Structural Prevention of Repeated Re-Use  
**Publication Date:** May 14, 2026  
**Prior Art Effective Date:** May 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / LLM Coding-Assistant Governance / Policy Override Mechanisms / Cryptographic Audit Trail / Exception Handling Patterns  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-002 (Chain of Custody), PAD-010 (Semantic Consent Signing), PAD-048 (Write-Only Asynchronous Context Ledger), PAD-050 (Zero-Context Deterministic Egress Interception), PAD-053 (Time-Bounded Ephemeral Rules), PAD-059 (Vouch-Amnesia Attestation Bridge)  

---

## 1. Abstract

A method for permitting a developer to override a single specific deterministic-policy block at egress time, with a structural guarantee that the override applies only once, applies only to the specific commit range and rule that produced the block, expires within a short bounded window, and produces a separately-signed cryptographic record of the override event that is verifiable by a third party.

The method addresses a recurring failure mode of egress-time policy systems: legitimate exceptions exist (a rule was overly broad, the developer has obtained out-of-band human approval, the block is a false positive on a specific known-safe file), and existing override mechanisms either (a) require disabling the rule globally and re-enabling it later, which is forgotten, or (b) require an environment variable or commented-out line that persists silently and continues to permit future overrides, or (c) require routing through a second human reviewer, which is impractical for many developer workflows.

Key innovations:

- **One-shot consumption.** The override is consumed when the pre-push hook reads it during the *next* push attempt. After consumption, it is deleted by the hook itself. A second push within the same time window will block again.
- **Scope binding.** The override is bound to (a) the specific rule ID that produced the block, (b) the specific commit range being pushed, and (c) optionally the specific file paths that matched the rule. An override granted for rule R against commit range C1..C2 does not apply to rule S or to commit range C3..C4.
- **Time bound.** The override expires after a short, configurable duration (default 5 minutes). The developer must invoke `approve-once`, then push within the window. A forgotten override does not silently persist.
- **Cryptographic audit record.** The override itself is signed as a separate W3C Verifiable Credential by the developer's DID, with the rule ID, commit range, override timestamp, and override reason (free-form text) as fields. This credential is consumed by the pre-push hook and embedded by reference into the resulting egress-decision credential (PAD-059), producing a verifiable two-credential chain.
- **Structural prevention of repeated re-use.** Because the override is a one-shot file that is deleted on consumption, the developer cannot grant themselves recurring exceptions by leaving an override file in place. Each push requires a fresh override invocation, each of which produces its own signed audit credential. Pattern-of-abuse becomes immediately visible in the audit log.

---

## 2. Problem Statement

### 2.1 Hard blocks without escape valves are abandoned by developers

A pre-push policy that blocks a push and provides no override mechanism is, in practice, removed or disabled by the first developer who encounters a legitimate edge case. Empirical observation: any deterministic-policy system without an override escape valve has a usage half-life of two weeks among developers who must ship code under time pressure.

The systemic problem is not that developers are malicious. The systemic problem is that no rule set perfectly captures every legitimate edge case, and a system that punishes the developer for the rule-author's incompleteness is uninstalled.

### 2.2 Environment-variable overrides persist silently and permit recurring abuse

A common existing pattern is to permit override via an environment variable: `AMNESIA_BYPASS=1 git push`. This pattern has three failure modes:

1. **The variable persists.** Once exported in a shell, it remains exported for the remainder of the shell session. Subsequent unrelated pushes from the same shell are silently un-policed.
2. **The variable is exported in `~/.bashrc` once and forgotten.** A developer who hits the override pattern once and chooses to "make it permanent" is one shell-rc edit away from disabling the policy entirely.
3. **The audit trail is weak.** Environment variables are not signed, are not bound to a specific commit range, and are not bound to a specific rule. The audit log can record "AMNESIA_BYPASS was set during this push," but cannot prove who set it or for what reason.

### 2.3 Comment-out-the-rule overrides have the same persistence failure

An alternate pattern: have the developer edit the policy file to comment out the specific rule, push, then uncomment. In practice, the uncomment step is forgotten. Rules accumulate as commented-out lines over weeks until the policy file is largely permissive.

### 2.4 Second-reviewer overrides do not scale to developer workflows

A robust override pattern from the security-engineering literature requires a second human reviewer to approve the override. For deployment pipelines and production-release gates, this is appropriate. For developer push-time decisions made many times per day, requiring a second reviewer for every false-positive is impractical and pushes developers to (i) batch overrides into larger pushes (which weakens the audit trail) or (ii) bypass the system entirely via one of the patterns above.

### 2.5 Time-limited overrides without scope binding still allow over-broad abuse

A naive improvement is to make the override time-limited: `amnesia override --duration 1h`. This addresses the persistence problem but not the scope problem. A one-hour blanket override permits the developer to push *anything* during that hour, not just the specific edge case they encountered. If the developer encounters a separate unrelated rule trigger during the same hour, that trigger is also suppressed.

### 2.6 No prior system combines one-shot consumption, scope binding, time bounding, AND cryptographic audit

The combination is novel. Each component has weak analogues elsewhere (one-time tokens, scoped capability tokens, time-bounded credentials, signed audit logs), but no prior system applies all four to the specific problem of pre-push egress-time policy override in an AI coding assistant workspace.

---

## 3. Solution (The Invention)

### 3.1 The override CLI invocation

The developer invokes the override after seeing a blocked push:

```
$ git push origin main
error: pre-push hook rejected: rule rule_1714400111000_a8f3d1b2
       severity=block matched file payments/legacy_pricing.py
       (rule body: "Do not push files in payments/ during the regulatory freeze")

$ amnesia approve-once --rule rule_1714400111000_a8f3d1b2 \
                       --reason "Senior counsel approved push of legacy_pricing.py
                                 deletion for ticket REGFREEZE-42, recorded in
                                 Slack #regulatory-compliance 2026-05-14 03:18 UTC"
$ git push origin main
... push proceeds ...
```

### 3.2 What `approve-once` does

The invocation produces three artifacts:

1. **An override credential** at `.vouch/overrides/<override-uuid>.json`. This is a W3C Verifiable Credential signed by the developer's DID. Its `credentialSubject` is:

   ```json
   {
     "type": "AmnesiaOverride",
     "override_id": "<uuid>",
     "rule_id": "rule_1714400111000_a8f3d1b2",
     "scope_restrictions": {
       "max_commit_count": 1,
       "file_path_patterns": null,
       "expires_at": "<ISO-8601 UTC>"
     },
     "reason": "Senior counsel approved push of legacy_pricing.py ...",
     "approver_did": "did:web:dev-machine-alice.example.com"
   }
   ```

2. **A pending-override pointer file** at `.vouch/overrides/PENDING-<rule-id>.txt` whose contents are the `override-uuid`. This pointer is what the pre-push hook reads on the next push.

3. **An audit log entry** appended to `.vouch/audit/overrides.log` (plain-text JSON lines for fast scanning; the canonical record remains the signed credential file).

### 3.3 Pre-push hook consumption

On the next push attempt:

1. The hook runs the deterministic evaluator (PAD-050). The evaluator produces an `EgressDecision`.
2. If `decision == "block"` AND a matching pending-override pointer exists for the blocked rule, the hook:
   - Reads the override credential by UUID.
   - **Verifies the override credential's signature** against the developer's DID.
   - **Checks expiry.** If `now > expires_at`, the override is rejected. The override pointer is deleted. The push is blocked.
   - **Checks scope.** The commit count must be ≤ `max_commit_count`. If `file_path_patterns` is non-null, every matched file path under the blocked rule must be in the pattern list.
   - If all checks pass, the hook treats the rule as `attest` instead of `block` for THIS push only.
   - **Deletes the pending-override pointer file** (`PENDING-<rule-id>.txt`). The override is now consumed.
3. The hook produces an `EgressDecision` with `human_override` populated, including the override credential URN.
4. The egress-decision credential (PAD-059) is signed and embeds the override credential by reference, producing a verifiable two-credential chain.

### 3.4 Why deletion of the pointer matters

If the pointer file is NOT deleted after consumption, a second push within the override's time window would consume the same override again, granting two pushes for one human approval. The deletion enforces one-shot consumption structurally rather than via convention. A developer who needs two pushes must invoke `approve-once` twice, producing two separate signed override credentials in the audit log, each individually scrutinizable.

The override credential file itself is NOT deleted, only the pending-override pointer. The credential remains in `.vouch/overrides/<uuid>.json` as the cryptographic audit record. Deletion is logically equivalent to "marking the credential as consumed."

### 3.5 Why scope binding matters

Without scope binding, a one-time override for rule R unlocks the entire policy file for the duration. A developer who genuinely needs to override rule R but inadvertently also triggers rule S during the same push would have rule S silently suppressed without an audit trail. With scope binding (the override applies ONLY to the specific rule ID), the second rule trigger still blocks, the developer must invoke `approve-once` for rule S separately, and the audit log shows two distinct override credentials with two distinct human reasons.

### 3.6 The `--reason` field is structurally required

The CLI tool refuses to produce an override credential if `--reason` is empty or below a minimum character length (default 20 characters). The reason is free-form text but must be non-trivially populated. This forces the developer to articulate the override justification at the moment of invocation, when the context is fresh, rather than retrofitting a reason after the fact when the context has decayed. The reason field is included in the signed credential, so a later auditor sees the developer's contemporaneous justification.

### 3.7 Integration with delegation chains

If the override is being granted on behalf of a separate human approver (e.g., the developer's manager approved over Slack), the override credential supports an optional `delegation_chain` field referencing PAD-002. The chain captures: the manager's DID, the manager's signed approval to the developer (which itself is a separate Verifiable Credential the developer obtained out of band), the developer's own signed override that consumes the approval. The full chain is then audit-verifiable: who approved, who consumed the approval, when, against which rule, for which commit range.

### 3.8 Pattern-of-abuse detection

Because every override produces a separately-signed credential in `.vouch/audit/overrides.log`, automated tooling can scan the log for patterns:

- Developer A invoked `approve-once` more than 10 times in the past 7 days → flag for review.
- Rule R has been overridden by 80% of pushes that triggered it → the rule is overly broad and should be revised.
- Developer B's reason fields share substring "TODO fix this properly" → systematic deferral, escalate.

The structural one-shot consumption produces high-fidelity data for these analyses. With persistent-environment-variable overrides, this analysis is impossible.

---

## 4. Prior Art Differentiation

### 4.1 Environment-variable bypass flags (Git, npm, others)

Most policy enforcement tools support some form of `--force` or `BYPASS=1` flag. These flags:

- Are not signed.
- Persist for the lifetime of the shell session or the user's `~/.bashrc`.
- Are not scope-bound (a single flag suppresses all policy).
- Produce no separately-stored audit credential.

The combination of one-shot consumption, scope binding, time bounding, and cryptographic signing is not present in any environment-variable mechanism.

### 4.2 Comment-out-the-rule patterns

Manually editing the policy file to comment out a specific rule, pushing, and uncommenting is in widespread informal use. It has the same persistence failure mode (the uncomment step is forgotten) and no audit trail beyond the git history of the policy file itself, which is editable and re-editable.

### 4.3 Pull-request-based override workflows

For deployment gates, the standard pattern is "create a PR to disable the rule, get it reviewed, push, create another PR to re-enable." This works for slow-changing deployment policy but is operationally too heavy for per-push developer-level decisions. It also does not bind the override to a specific commit range; the rule is disabled globally for the duration between the two PRs.

### 4.4 One-time tokens (TOTP, single-use passwords, capability tokens)

Single-use tokens are a well-known cryptographic primitive (TOTP RFC 6238, capability-based security literature dating to the 1960s). Existing one-time-token systems target authentication, not policy override. The novelty here is the **application of one-shot semantics to the specific case of pre-push egress-time policy override**, combined with scope binding to a specific rule + commit range.

### 4.5 Signed audit logs (Sigstore, in-toto)

Sigstore and in-toto sign artifacts and attestations. They do not provide a one-shot override mechanism with scope binding to a specific policy rule. The signing primitive itself is well-known; the application to single-use scope-bound policy override is novel.

### 4.6 Time-limited credentials (OAuth bearer tokens with short TTL, AWS STS temporary credentials)

Time-bounding is a standard property of access credentials. None of the existing time-bounded-credential systems target the specific use case of "override a pre-push policy block one time within a short window." The application is novel, and the combination with scope binding and structural one-shot consumption is novel.

### 4.7 The combination is novel

No prior system combines (a) one-shot consumption enforced by deletion of a pending-override pointer, (b) scope binding to a specific rule ID and commit range, (c) time bounding via expiry within the credential subject, (d) cryptographic audit via a separately-signed Verifiable Credential, (e) structurally-required non-trivial reason text, (f) optional delegation-chain integration for out-of-band approvals, AND (g) deterministic verification by replaying the consumed override against the egress-decision credential. This disclosure establishes prior art on the combination.

---

## 5. Technical Implementation

### 5.1 Reference implementation locations

- **CLI tool:** `amnesia approve-once` subcommand. Source location depends on which Amnesia distribution ships first (Python CLI under `amnesia/python/cli/approve_once.py` is the planned reference; the npm-published Amnesia distribution will mirror).
- **Pre-push hook integration:** the existing pre-push hook from PAD-050 is extended with a "check for pending override" step before the final block/allow decision.
- **Verification library:** a standalone library function `verify_override_credential(credential: dict, current_time: datetime, rule_id: str, commit_range: dict) -> VerificationResult` that performs the four-step verification (signature, expiry, scope, single-use).
- **Audit log scanner:** a reference implementation of the pattern-of-abuse detection at `amnesia audit scan-overrides`.

### 5.2 Override credential format

The override credential follows W3C VC 2.0 with a Vouch-specific `AmnesiaOverride` type. Minimum fields are listed in §3.2. The credential is signed using the same Data Integrity cryptosuites as the egress-decision credential (PAD-059): `eddsa-jcs-2022` by default, `hybrid-eddsa-mldsa44-jcs-2026` for post-quantum-ready deployments.

### 5.3 The pending-override pointer

The pointer is a tiny text file (a single line containing the override UUID). It exists for one reason: to make the "is there a pending override for rule R?" check a single filesystem lookup at `.vouch/overrides/PENDING-<rule-id>.txt`, without requiring the pre-push hook to scan all override credentials. The pointer's presence is the signal; the credential is the audit record.

### 5.4 Atomicity of consumption

The pre-push hook performs the consumption atomically: read the pointer, verify the credential, delete the pointer file. If the verification fails, the pointer is not deleted (the developer's `approve-once` did not produce a valid credential, perhaps because the system clock is wrong; the developer can re-invoke). If verification succeeds, the pointer is deleted before the push proceeds, so even if the push is aborted by a different rule, the override is consumed.

This "consumed even if push aborts" semantics is deliberate: the override represents human intent, not human ability. The human approved the override; if the push aborts for an unrelated reason, the human must re-evaluate and re-approve.

### 5.5 Clock-skew tolerance

The expiry check uses the developer machine's local clock. Clock skew is a concern. Default expiry is 5 minutes (generous enough to tolerate reasonable skew). The credential can be signed with an additional `not_before` field that gives a 30-second grace window in case the developer's clock is slightly ahead.

For high-stakes deployments, the expiry check can be hardened by including a recent TLS handshake timestamp from a known-trusted host in the credential, providing a cross-check against local clock manipulation. This is optional and disabled by default to keep `approve-once` working offline.

---

## 6. Claims Summary

This defensive publication establishes prior art on the following methods, alone or in combination:

1. **A pre-push policy override mechanism with one-shot consumption** enforced by deletion of a pending-override pointer file by the consuming pre-push hook.

2. **Scope binding of the override to a specific policy rule identifier and a specific commit range**, such that the override applies only to the bound rule and bound range and does not suppress other rules or other ranges.

3. **A time-bounded override credential** with an `expires_at` field whose value is bound inside the cryptographic envelope and verified by the consuming pre-push hook against the local clock.

4. **A separately-signed cryptographic override credential** in W3C VC format with `AmnesiaOverride` type, embedded by reference inside the resulting egress-decision credential (PAD-059) to produce a verifiable two-credential chain.

5. **Structurally-required non-trivial reason text** within the override credential, enforced by minimum-length validation at credential-issuance time.

6. **Integration of out-of-band human approval via delegation chains** (PAD-002), in which a manager's separately-signed approval is consumed by the developer's override credential and the chain is auditable end-to-end.

7. **Pattern-of-abuse detection over the audit log of consumed overrides**, including per-developer frequency analysis, per-rule override-ratio analysis, and reason-field clustering.

8. **Atomic consumption-on-verification** semantics in which the override pointer is deleted before the push proceeds, ensuring that even an aborted push consumes the override.

---

## Prior Art Declaration

This disclosure is published under the Apache License 2.0 to establish prior art and prevent the patenting of these methods by any party. The methods described are intended for free, open use. The author retains no proprietary claim and explicitly waives any future patent rights arising from the disclosed methods.

The disclosure is timestamped at the publication date in the document header. It is published to the public Git repository at [github.com/vouch-protocol/vouch](https://github.com/vouch-protocol/vouch) and accessible to any third party performing prior-art search.

## Notes on companion disclosures

PAD-060 is consumed by PAD-059. Where PAD-059 describes the cryptographic anchoring of a deterministic egress decision, PAD-060 describes the specific override mechanism that produces the `human_override` field referenced inside that egress decision. The two disclosures are designed to be filed together as a coherent pair, but each is independently novel and independently patentable; both have been published as defensive disclosures to ensure neither can be claimed by a third party.

A future disclosure (PAD-061, not yet drafted) will cover the cross-vendor directive-file portability pattern for AI coding assistants. That disclosure is held pending the publication of additional per-vendor directive-file conventions, which would strengthen the cross-vendor pattern's defensible novelty.
