# Vouch Protocol CG Report, v1.7 DRAFT, Section 9 (Delegation) and related conformance

**Status:** v1.7 WORKING DRAFT. NOT published. NOT for the current CCG review.
**Baseline:** v1.6.2 (`docs/specs/w3c-cg-report.md`) remains the version under CCG review and MUST NOT be edited for this change. This document holds the v1.7 replacement text for the affected sections only; every other section of v1.6.2 is inherited unchanged.
**Change:** CH-001 in `docs/specs/v1.7-changelog-tracker.md`. Rationale and section plan in `docs/specs/list-response-alan-karp-delegation.md`.
**Settled vs pending:** the core attenuation rule and verifier cost budgets are settled and written normatively below. Three edge policies are still pending Alan Karp's input and are marked with EDITOR'S NOTE; they MUST NOT be frozen as final wording until he responds.
**Style:** no em-dashes. RFC 2119 keywords. W3C and ZCAP references are permitted in this specification (it is a standards document); this rule does not apply to the public FAQ, Help, and KB.

---

## 9. Delegation Chains (v1.7)

### 9.1 Overview

In multi-agent systems, a root principal may delegate authority through a chain of agents. The Vouch Protocol supports cryptographic delegation chains that preserve accountability at each hop. Delegation in Vouch is a capability-attenuation model in the object-capability tradition: authority originates at a root principal and is strictly narrowed at each link, and no delegate can grant more than it holds.

The semantics align conceptually with W3C Authorization Capabilities (ZCAP-LD) [ZCAP-LD] and the broader object-capability security tradition. Vouch aligns with that model but does NOT take a normative dependency on the ZCAP-LD document, whose draft is not currently maintained; ZCAP-LD is tracked informatively (Appendix A). Two design distinctions remain:

- **No JSON-LD requirement**: Delegation links use the same JCS-canonicalized JSON form as the surrounding credential, avoiding JSON-LD canonicalization.
- **Explicit resource binding**: Each delegation link MUST carry a `resource` field, ensuring that capabilities are bound to specific URIs rather than abstract action names.

### 9.2 Delegation Link Structure

Each link in a delegation chain expresses a capability across up to six attenuation dimensions: action, target, resource, time, rate, and policy. The first three are carried in `intent`, time in `validFrom`/`validUntil`, and the optional `rate` and `policy` fields carry the remaining two.

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
5. Verifies the **capability-attenuation rule** for each adjacent (parent, child) pair: the child capability MUST be a proper subset of the parent across at least one of {action, target, resource, time, rate, policy}, and MUST NOT be broader on any dimension. Per-dimension subset is defined as:
   - **action**: child actions are a subset of parent actions.
   - **target**: child targets are a subset of parent targets.
   - **resource**: child `intent.resource` is a sub-resource of, or equal to, the parent's (the existing resource-narrowing rule).
   - **time**: child `[validFrom, validUntil]` is within the parent's interval (the existing temporal-narrowing rule).
   - **rate**: child `rate.limit` per window is less than or equal to the parent's.
   - **policy**: child policy is equal to or stricter than the parent's.
6. A chain is rejected with `capability_not_attenuated` if any child fails the rule, or `resource_not_narrowed` for the resource-specific case.

EDITOR'S NOTE (pending Alan Karp, CH-001 open question 1): the rule above accepts a proper subset on any single dimension. Whether a trivial narrowing (for example rate 100 to 99 with everything else unchanged) should count, or whether meaningful narrowing on action/target/resource should be required, is left to verifier policy via an OPTIONAL stricter-narrowing hook. Do not finalize this wording until Alan responds.

EDITOR'S NOTE (pending Alan Karp, CH-001 open question 2): the chain terminates naturally when no dimension can narrow further (for example read-only, single object, single use). Whether to spell out the leaf/termination condition explicitly, or leave it to fall out of the subset rule, is open.

### 9.4 Capability Attenuation and Verifier Cost Budgets

There is no fixed maximum chain depth. The capability-attenuation rule (Section 9.3, step 5) is the control: because each link must be strictly smaller than its parent, a chain cannot grow without bound in authority and ends when nothing remains to narrow.

Earlier revisions (through v1.6.2) required a fixed maximum depth (RECOMMENDED 5 hops). That control is removed: at the limit, an agent that still needs to hand a narrower slice of its authority to another agent cannot delegate, so it proxies the other agent's requests or shares its credentials, both of which grant broader authority and destroy the audit trail.

Cost control moves to the verifier. A verifier MAY cap the work it will spend validating a chain, by depth, total verification time, or cumulative validity (TTL) across the chain. This is the verifier's local, configurable choice and is NOT a protocol-level requirement. When a verifier rejects a chain for exceeding its budget, it MUST report `verifier_budget_exceeded` and the specific limit reached, so the delegating agent narrows earlier rather than routing around the limit. See [[PAD-022](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-022-swarm-limits-protocol.md)] for multi-agent delegation graphs beyond simple linear chains.

### 9.5 Inverse Capability Pattern (normative)

Delegation links MUST only narrow, never broaden, the parent's authority. This is the capability-attenuation property and is the normative basis for Section 9.3 step 5. Implementations follow the Inverse Capability Pattern described in [[PAD-021](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-021-inverse-capability-protocol.md)], which is promoted from RECOMMENDED (v1.6.2) to the normative basis of the attenuation rule in this revision.

### 9.6 Chain-Cascade Revocation (OPEN, not yet specified)

EDITOR'S NOTE (CH-003, pending Alan Karp and capability-literature review): Vouch already provides credential-level revocation (BitstringStatusList), DID-level revocation (`vouch.revocation` registry), and key rotation. What is not yet specified is the cascade: if a mid-chain link is revoked or its issuer's key is rotated, whether validation MUST invalidate everything downstream of it. Implementations SHOULD expose an extension point for cascade behavior but MUST NOT assume a final rule until this section is completed. Do not freeze normative wording here yet.

---

## 17. Conformance Levels (v1.7 deltas)

### 17.1 Level 1 (L1): Credential

EDITOR'S NOTE (CH-001): the capability-attenuation check is a core validity property of any presented chain. v1.7 moves the attenuation check into L1 so that any conformant verifier that accepts a chain enforces it, even at L1. Confirm placement against the L1/L2 split before publishing.

### 17.2 Level 2 (L2): Sidecar + Delegation + Revocation

Replace the v1.6.2 delegation bullet, which read "Support delegation chains per Section 9, including the resource-narrowing rule and the depth limit of five links," with:

- Support delegation chains per Section 9, including the capability-attenuation rule (proper subset across action/target/resource/time/rate/policy, broader on none) and verifier-side cost budgets. There is no fixed depth limit.

---

## Appendix C.4 Delegation chain vectors (v1.7 delta)

Replace the v1.6.2 vector description, which read "Linear chains of depth 1, 3, and 5 with valid and invalid resource-narrowing examples," with:

- Chains demonstrating valid attenuation on each dimension (action, target, resource, time, rate, policy), invalid widening on each dimension, a chain that terminates at a natural leaf, and a chain rejected by a verifier cost budget. All three reference implementations (Python, TypeScript, Go) MUST produce identical accept/reject decisions and identical rejection reasons for every vector. The shared, machine-readable vectors are published at `test-vectors/delegation-attenuation/vector.json`, and the Python, TypeScript, and Go SDKs each run them (a module-level runner and a verifier-wiring runner) so that any divergence fails a build.

---

## Carry-over note

When v1.7 is finalized: fold these sections into a complete v1.7 document, bump the version, the dated this-version URL, and the revision line as was done for v1.6.2; resolve every EDITOR'S NOTE; re-run the no-em-dash check; and notify the reviewers whose feedback was acted on (Alan, Amir) citing the section.
