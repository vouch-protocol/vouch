# Vouch Protocol CG Report, v1.7 DRAFT, delegation and related section deltas

**Status:** v1.7 WORKING DRAFT. NOT published. NOT for the current CCG review.
**Baseline:** v1.6.2 (`docs/specs/w3c-cg-report.md`) remains the version under CCG review and MUST NOT be edited for this change. This document holds the v1.7 replacement text for the affected sections only; every other section of v1.6.2 is inherited unchanged.
**Changes carried in this draft:**
- CH-001 (delegation redesign: replace the fixed depth limit with a non-expansion rule), sections 9, 17, Appendix C.4.
- CH-002 (state why the protocol is scoped to AI agents), section 1.3.
- CH-004 (define the delegation validation rejection-code vocabulary), sections 9.3, 17.2.
- CH-005 (pin Merkle-root domain separation for `actionMerkleRoot`), section 11.3.
- CH-006 (specify credential-id replay handling and a `nonce_replay` code), sections 5.3, 12.2.

**Review status:** CH-001's non-expansion rule, the verifier cost budgets, and the three edge policies (acceptable narrowing, chain termination, and revocation cascade) are settled following review by Alan Karp and Manu Sporny on PR #42, and the code landed on `main` via PR #363. CH-002 was committed to Amir Hameed Mir on public-credentials. CH-004, CH-005, and CH-006 arose from the Paper 1 (arXiv) versus spec consistency review; the CH-004 codes are pinned to the shared reference validator that landed with CH-001.
**Style:** RFC 2119 keywords. W3C and ZCAP references are permitted in this specification (it is a standards document); this allowance does not extend to the public FAQ, Help, and KB.

---

## 1.3 Scope: why AI agents (v1.7 delta, CH-002)

Add the following to section 1.3.

> This specification scopes its mechanisms to AI agents as a deliberate threat-model choice, not because of any technical boundary. The underlying primitives, delegation, heartbeat renewal, and continuous state verifiability, apply equally to human actors, service accounts, and other non-AI workloads. Nothing in the cryptography or the mechanisms restricts them to AI.
>
> The scope is AI agents for two reasons:
>
> 1. The defaults are tuned to how AI agents fail. Heartbeat lifetimes are short because AI failure modes are fast: prompt injection, a swapped model, behavioral drift mid-session. For a steady service account, that renewal cadence would be unnecessary overhead. The mechanism is the same; only the setting differs.
>
> 2. A few mechanisms are AI-specific in motivation: keeping signing keys out of the model's context window, binding identity to model weights to detect a swap, and canary checks that distinguish a dead or hijacked agent from one that is merely idle. These are AI-relevant, but they sit alongside the general primitives rather than restricting them.
>
> Applying these primitives to humans or service accounts would call for a separate profile with re-tuned defaults. That profile is reasonable future work and would be a separate sibling specification, not a widening of this one's scope.

---

## 5.3 The id property and replay protection (v1.7 delta, CH-006)

Section 5.3 makes `id` OPTIONAL. Replay protection (Section 12.2) is keyed on `id`, so add the following qualification to the Required Properties note and table row for `id`:

- The `id` property remains OPTIONAL in general, per VC 2.0. However, a verifier detects a replayed credential by remembering ids it has already seen, so any credential that may be persisted, replayed, or correlated across audit logs MUST carry an `id` (a `urn:uuid` value is RECOMMENDED). A verifier enforcing replay protection MUST reject a credential that arrives without an `id` under that policy, rather than admit a credential it cannot replay-protect. Ephemeral, fire-and-forget credentials that are never persisted MAY still omit `id`, accepting that they cannot be replay-protected by id.

---

## 9. Delegation Chains (v1.7)

### 9.1 Overview

In multi-agent systems, a root principal may delegate authority through a chain of agents. The Vouch Protocol supports cryptographic delegation chains that preserve accountability at each hop. Delegation in Vouch follows the object-capability tradition: authority originates at a root principal, and at each link it is either restated unchanged or attenuated (narrowed), and never broadened. No delegate can grant more than it holds.

The semantics align conceptually with W3C Authorization Capabilities (ZCAP-LD) [ZCAP-LD] and the broader object-capability tradition, including the restate-or-attenuate model used by UCAN. Vouch aligns with that model but does NOT take a normative dependency on the ZCAP-LD document, whose draft is not currently maintained; ZCAP-LD is tracked informatively (Appendix A). Two design distinctions remain:

- **No JSON-LD requirement**: Delegation links use the same JCS-canonicalized JSON form as the surrounding credential, avoiding JSON-LD canonicalization.
- **Explicit resource binding**: Each delegation link MUST carry a `resource` field, ensuring that capabilities are bound to specific URIs rather than abstract action names.

### 9.2 Delegation Link Structure

Each link in a delegation chain expresses a capability across up to six dimensions: action, target, resource, time, rate, and policy. The first three are carried in `intent`, time in `validFrom`/`validUntil`, and the optional `rate` and `policy` fields carry the remaining two.

```json
{
  "issuer": "did:web:alice.example.com",
  "subject": "did:web:travel-agent.example.com",
  "intent": {
    "action": "plan_trip",
    "target": "destination:Paris",
    "resource": "https://travel-api.example.com/v1/bookings"
  },
  "validFrom": "2026-04-26T09:00:00Z",
  "validUntil": "2026-04-26T11:00:00Z",
  "rate": { "limit": 100, "window": "PT1H" },
  "policy": { "minHeartbeatAgeSeconds": 300 },
  "proof": { "...DataIntegrityProof..." }
}
```

| Field | Required | Description |
|---|---|---|
| `issuer` | REQUIRED | DID of the delegator |
| `subject` | REQUIRED | DID of the delegate (recipient of authority) |
| `intent` | REQUIRED | Authorized scope: `action`, `target`, and required `resource` |
| `validFrom`, `validUntil` | REQUIRED | Temporal bounds (the time dimension) |
| `rate` | OPTIONAL | Rate ceiling for the delegated capability (the rate dimension) |
| `policy` | OPTIONAL | Additional conditions, for example a minimum heartbeat freshness (the policy dimension) |
| `proof` | REQUIRED | Data Integrity proof signed by the `issuer` |

A dimension that is absent on a link is treated as inherited unchanged from the parent; it cannot be widened by omission.

### 9.3 Chain Validation

To verify a delegation chain, the verifier:

1. Validates the outermost Vouch Credential signature.
2. Walks the chain from the last link to the first.
3. For each link, verifies that `subject` matches the `issuer` of the next link.
4. Verifies the root `issuer` is a trusted principal.
5. Verifies the **non-expansion rule** for each adjacent (parent, child) pair: the child capability MUST NOT be broader than its parent on any of {action, target, resource, time, rate, policy}. A child MAY restate any dimension unchanged or attenuate (narrow) it. Restating every dimension, that is re-delegating the same authority without narrowing, is valid and is often the intended behavior. Per dimension, "not broader" is defined as:
   - **action**: child actions are a subset of, or equal to, the parent's actions.
   - **target**: child targets are a subset of, or equal to, the parent's targets.
   - **resource**: child `intent.resource` is a sub-resource of, or equal to, the parent's.
   - **time**: child `[validFrom, validUntil]` is within, or equal to, the parent's interval.
   - **rate**: child `rate.limit` per window is less than or equal to the parent's.
   - **policy**: child policy is equal to or stricter than the parent's.
6. A chain is rejected with `scope_exceeds_parent`, naming the offending dimension (for example `resource`), if any child is broader than its parent on any dimension.

Whether a particular narrowing is *acceptable* is not a protocol concern. The system where the capability is invoked is the authority on whether a delegated scope is acceptable, in both directions: a scope that is too broad for that system's rules, or a narrowing that is not sufficient for them. A verifier MAY enforce stricter local policy through an OPTIONAL narrowing hook. This protocol requires only that no link broadens its parent.

#### 9.3.1 Rejection codes (v1.7 delta, CH-004)

A verifier that rejects a delegation chain MUST report a machine-readable code, so that verifiers and conformance tests share exact strings. Earlier drafts named only `scope_exceeds_parent`; the full vocabulary is:

| Code | Reported when |
|---|---|
| `link_signature_invalid` | a link's Data Integrity `proof` fails to verify (Section 9.3 step 1) |
| `subject_issuer_mismatch` | a link's `subject` does not equal the next link's `issuer` (Section 9.3 step 3) |
| `untrusted_principal` | the root `issuer` is not a trusted principal (Section 9.3 step 4) |
| `scope_exceeds_parent` | a child broadens its parent on some dimension; the response names the offending dimension, one of action, target, resource, time, rate, or policy (Section 9.3 steps 5 to 6) |
| `outside_validity_window` | a link is evaluated outside its own `[validFrom, validUntil]` interval at verification time |
| `delegation_revoked` | a link is revoked; the chain and all authority below it are rejected (Section 9.6) |
| `verifier_budget_exceeded` | the chain exceeds a verifier-local cost budget (depth, total time, or cumulative TTL); the response names the limit reached (Section 9.4) |
| `malformed_delegation` | a link is structurally invalid: a required field is missing, or a timestamp or duration is unparseable |

These are the codes emitted by the shared reference validator (`validate_delegation_chain`) and are pinned by the interop vectors in Appendix C.4. Two codes from earlier drafts are intentionally absent. `chain_depth_exceeded` is removed with the depth limit (CH-001); its role is taken by `verifier_budget_exceeded`. A general `temporal_bounds_exceeded` is realized more precisely as two codes: `scope_exceeds_parent` (dimension `time`) for a child that widens its parent's interval, and `outside_validity_window` for a link evaluated outside its own bounds.

### 9.4 Chain Growth and Verifier Cost Budgets

There is no fixed maximum chain depth. The non-expansion rule (Section 9.3, step 5) is the control on authority: because no link can broaden its parent, authority along a chain can only stay equal or shrink, and can never grow without bound.

Earlier revisions (through v1.6.2) required a fixed maximum depth (RECOMMENDED 5 hops). That control is removed: at the limit, an agent that still needs to hand a slice of its authority to another agent cannot delegate, so it proxies the other agent's requests or shares its credentials, both of which grant broader authority and destroy the audit trail.

Cost control moves to the verifier. A verifier MAY cap the work it will spend validating a chain, by depth, total verification time, or cumulative validity (TTL) across the chain. This is the verifier's local, configurable choice and is NOT a protocol-level requirement. When a verifier rejects a chain for exceeding its budget, it MUST report `verifier_budget_exceeded` and the specific limit reached, so the delegating agent narrows earlier rather than routing around the limit. See [[PAD-022](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-022-swarm-limits-protocol.md)] for multi-agent delegation graphs beyond simple linear chains.

### 9.5 Non-expansion (normative)

Delegation links MUST NOT broaden the parent's authority on any dimension. A link MAY restate a capability unchanged or attenuate (narrow) it. This non-expansion property is the normative basis for Section 9.3 step 5, and follows the object-capability tradition of restate-or-attenuate, consistent with UCAN and W3C ZCAP-LD.

### 9.6 Chain-Cascade Revocation

When any link in a delegation chain is revoked, whether through the credential-level BitstringStatusList (`credentialStatus`) or the DID-level `vouch.revocation` registry, every delegation downstream of that link becomes invalid. A verifier that encounters a revoked link MUST reject the chain and all authority derived below that link, reporting `delegation_revoked`.

Key rotation is NOT treated as a cascade trigger. Delegation links SHOULD be issued to a key scoped to the delegation rather than to the issuer's long-lived authentication key, so that routine key rotation does not invalidate active chains. An issuer that prefers bulk revocability MAY instead issue to a long-lived key, accepting that revoking that key invalidates every delegation signed with it.

---

## 11.3 Heartbeat Request: actionMerkleRoot construction (v1.7 delta, CH-005)

Section 11.3 shows an `actionMerkleRoot` field but does not pin how the tree is built. Without a fixed construction the root is open to the classical Merkle second-preimage attack, in which a leaf value and an internal node hash to the same digest. Add the following normative construction:

- `actionMerkleRoot` MUST be computed with RFC 6962 domain separation. Each leaf is hashed as `SHA-256(0x00 || leaf-data)` and each internal node as `SHA-256(0x01 || left-child || right-child)`. The single domain-separator byte, `0x00` for leaves and `0x01` for internal nodes, prevents a leaf from being reinterpreted as an internal node and closes the second-preimage attack. An odd node at any level is promoted unchanged to the next level (it is not duplicated). An empty action set is represented by `SHA-256("")`, the RFC 6962 empty-tree root. The value is serialized as `sha256:<hex>` as shown in the example.

---

## 12.2 Tampering: replay protection and the nonce_replay code (v1.7 delta, CH-006)

Section 12.2 describes a recently-seen-id cache but names no rejection code. Replace the mitigation for the row "Attacker replays an unmodified credential to the same resource within its validity window," which read "Vouch Credentials carry `validFrom` and `validUntil` (default 300 s window) and a RECOMMENDED `id`. Verifiers SHOULD maintain a cache of recently seen credential ids to detect replay attempts within the validity window. The cache MUST persist across verifier restarts to maintain the guarantee during operator-initiated downtime," with:

- Vouch Credentials carry `validFrom` and `validUntil` (default 300 s window). Where replay protection is required, a credential MUST carry an `id` (Section 5.3). A verifier enforcing replay protection MUST maintain a store of credential ids seen within the validity window and MUST reject a credential whose `id` is already present, reporting `nonce_replay`. The store MUST persist across verifier restarts so the guarantee holds through operator-initiated downtime. A credential that arrives without an `id` under a policy that requires replay protection MUST be rejected rather than admitted as unprotectable.

---

## 17. Conformance Levels (v1.7 deltas)

### 17.1 Level 1 (L1): Credential

A conformant L1 verifier that accepts a delegation chain MUST enforce the non-expansion rule (Section 9.3, step 5). Non-expansion is a core validity property of any presented chain, so v1.7 places the check at L1: any verifier that accepts a chain enforces it, even at L1.

### 17.2 Level 2 (L2): Sidecar + Delegation + Revocation

Replace the v1.6.2 delegation bullet, which read "Support delegation chains per Section 9, including the resource-narrowing rule and the depth limit of five links," with:

- Support delegation chains per Section 9, including the non-expansion rule (no link broader than its parent on any of action/target/resource/time/rate/policy; restate or attenuate) and verifier-side cost budgets. There is no fixed depth limit.
- Report every delegation-chain rejection using the machine-readable codes of Section 9.3.1 (CH-004).
- Enforce replay resistance per Section 12.2, rejecting a replayed credential id with `nonce_replay` (CH-006). This replaces the v1.6.2 bullet "Enforce replay resistance through a recently-seen credential id cache per Section 12.2."

---

## Appendix C.4 Delegation chain vectors (v1.7 delta)

Replace the v1.6.2 vector description, which read "Linear chains of depth 1, 3, and 5 with valid and invalid resource-narrowing examples," with:

- Chains demonstrating valid attenuation on each dimension (action, target, resource, time, rate, policy), a valid restatement (re-delegation with unchanged scope), invalid widening on each dimension, and a chain rejected by a verifier cost budget. All three reference implementations (Python, TypeScript, Go) MUST produce identical accept/reject decisions and identical rejection reasons for every vector. The shared, machine-readable vectors are published at `test-vectors/delegation-attenuation/vector.json`, and the Python, TypeScript, and Go SDKs each run them (a module-level runner and a verifier-wiring runner) so that any divergence fails a build.

---

## Carry-over note

When v1.7 is finalized: fold these sections (1.3, 5.3, 9, 11.3, 12.2, 17, Appendix C.4) into a complete v1.7 document, bump the version, the dated this-version URL, and the revision line as was done for v1.6.2; re-run the no-em-dash check; and notify the reviewers whose feedback was acted on (Alan Karp and Manu Sporny for CH-001, Amir Hameed Mir for CH-002) citing the section. The delegation edge policies (acceptable narrowing, termination, revocation cascade) were resolved on PR #42 by Alan Karp and Manu Sporny. CH-004, CH-005, and CH-006 came from the Paper 1 versus spec consistency review; when finalizing, re-check that Paper 1's error-code table, Merkle domain-separation text, and replay defense still match sections 9.3.1, 11.3, and 12.2 here (Paper 1 predates the removal of `chain_depth_exceeded`).
