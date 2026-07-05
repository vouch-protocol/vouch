# PAD-086: Deterministic Executable Caveats Embedded in Object-Capability Delegation Chains for Autonomous Agents

**Identifier:** PAD-086
**Title:** Method for Embedding Deterministic, Fuel-Bounded Executable Caveats in Attenuatable Object-Capability Delegation Chains, Such That Every Downstream Verifier Must Evaluate Each Accumulated Caveat Against a Proposed Action and No Descendant May Remove an Ancestor's Caveat
**Publication Date:** July 5, 2026
**Prior Art Effective Date:** July 5, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Agent Authorization / Object Capabilities / Delegation / Policy Enforcement / Verifiable Credentials
**Author:** Ramprasad Anandam Gaddam
**License:** Apache 2.0
**Related:** PAD-002 (Chain of Custody Delegation), PAD-010 (Semantic Consent Signing), PAD-012 (Executable Usage Covenants in Media), PAD-056 (Allow-List Bounded Signing), PAD-066 (Physical Capability Scope Attenuation), PAD-085 (Two-Phase Deliberated Execution)

---

## 1. Abstract

A method for attaching **deterministic executable caveats** to the links of an
attenuatable object-capability delegation chain used by autonomous agents. A
caveat is a sandboxed, fuel-bounded predicate (for example a WebAssembly module)
that receives a defined context describing a proposed action and returns allow or
deny. Caveats **accumulate down the chain**: each delegated link may add caveats,
but a link's caveat set always includes every ancestor's caveats, and no
descendant can remove or weaken an ancestor's caveat because the caveat set is
part of the signed link. At verification time, a verifier presented with a
proposed action MUST evaluate every accumulated caveat and reject the action if
any denies, in addition to the existing static attenuation checks (action,
target, resource, time, rate, policy).

This turns the delegation envelope from a set of static narrowing fields into
live, portable, conditional authority that travels with the capability. It lets a
grantor express conditions that no static field can, such as "only during a
declared incident," "only if the invoice references an approved purchase order,"
or "never two disbursements to the same payee within one hour," while preserving
the object-capability guarantees that delegation only ever attenuates and that
verification is offline and byte-identical across implementations.

Determinism is mandatory: the caveat runtime has no clock, no randomness, no
network or filesystem, a pinned numeric profile, and a fuel limit, so the same
(caveat, context) pair yields the same result on every verifier, and evaluation
cost is bounded by verifier-side budgets.

---

## 2. Problem Statement

### 2.1 Static attenuation cannot express conditional authority

An attenuatable delegation model narrows authority along fixed axes: which
action, which target, which resource, valid-from and valid-until, a rate ceiling,
a policy label. Real grants are conditional in ways these axes cannot capture.
"You may approve refunds, but only for orders that shipped, and never above the
customer's lifetime spend" is not expressible as a narrowing of static fields. A
grantor forced to choose between granting too much or nothing at all will grant
too much, and the confused-deputy and over-privilege failures follow.

### 2.2 Out-of-band policy defeats offline verifiability and portability

The usual workaround is to keep the real policy in a central service the verifier
calls at check time. This defeats the two properties that make object-capability
delegation valuable: a capability should be verifiable offline by any
counterparty, and it should be portable across services without a shared policy
backend. It also reintroduces a trusted third party and a runtime dependency in
the hot path of every authorization.

### 2.3 Attached policy that a holder can drop is not enforcement

If conditional policy is attached to a capability but a downstream holder can
strip it before re-delegating or presenting the capability, the condition is
advisory, not enforced. Any conditional-authority mechanism for delegation must
guarantee that conditions can only be added down a chain and never removed, and
that a verifier is obligated to evaluate them rather than free to ignore them.

### 2.4 Non-deterministic policy code breaks cross-verifier agreement

If the attached policy can read a clock, draw randomness, perform I/O, or depend
on platform-specific floating point, two honest verifiers can reach different
decisions on the same capability and action. For a credential meant to verify
byte-identically across independent language implementations, policy evaluation
must be perfectly deterministic and its cost must be bounded so a malicious caveat
cannot mount a denial-of-service against the verifier.

---

## 3. The Novel Mechanism

### 3.1 Caveat structure on a delegation link

Each delegation link may carry a `caveats` array. Each caveat pins the exact
module to run and the shape of the context it will receive:

```json
{
  "delegation": {
    "parent": "urn:vouch:cap:...",
    "attenuation": { "action": "refund", "target": "store:eu", "resource": "usd:<=200" },
    "caveats": [
      {
        "id": "cav-shipped-only",
        "runtime": "wasm-caveat-1",
        "moduleHash": { "algorithm": "sha-256", "digest": "u<multibase>" },
        "contextSchema": "u<multibase-of-schema>",
        "fuelLimit": 2000000,
        "onDeny": "caveat_denied:shipped-only"
      }
    ]
  }
}
```

The `caveats` array is inside the signed link, so it is covered by the link's
Data Integrity proof.

### 3.2 Accumulation and non-removal

The effective caveat set of a link is the union of its own caveats and the
effective caveat set of its parent. A builder may add caveats when delegating; it
cannot emit a link whose effective set omits any ancestor caveat. Because each
ancestor link is itself signed and referenced, a verifier reconstructs the full
accumulated set from the chain and detects any attempt to present a chain with a
missing ancestor caveat as a broken or non-attenuating chain (reusing the
attenuation verifier's `capability_not_attenuated` machinery).

### 3.3 Deterministic caveat runtime

A conforming caveat runtime guarantees:

- No ambient authority: no clock, no randomness, no network, no filesystem, no
  environment. All inputs arrive in the context object.
- A pinned numeric profile (no nondeterministic floating point; integer and
  fixed-point only, or a specified deterministic float mode).
- A fuel meter: execution halts at `fuelLimit`, and halting counts as deny with
  reason `caveat_fuel_exhausted`.
- Module identity pinned by `moduleHash`; a verifier that lacks the module or
  computes a different hash rejects with `caveat_module_unavailable`.

The context object is assembled by the verifier from the proposed action, the
delegation chain, and any verifier-supplied evidence declared in `contextSchema`
(for example an incident flag or a set of approved purchase-order ids). The
caveat sees only what the schema admits, so the facts it can consider, and
therefore its limits, are explicit.

### 3.4 Verifier obligation and budgets

A verifier evaluating a proposed action against a capability MUST:

1. Perform the existing static attenuation checks (action, target, resource,
   time, rate, policy).
2. Assemble the context per each caveat's `contextSchema`.
3. Evaluate every caveat in the effective set; if any returns deny or exhausts
   fuel, reject the action with that caveat's `onDeny` reason.
4. Enforce a verifier-side budget (total fuel across all caveats, maximum caveat
   count) and emit `verifier_budget_exceeded` if exceeded, consistent with the
   optional budget model used for chain depth and verification time.

### 3.5 Structured reasons

`caveat_denied:<id>`, `caveat_fuel_exhausted`, `caveat_module_unavailable`,
`caveat_context_unsatisfiable`, `verifier_budget_exceeded`. These compose with
the delegation attenuation reasons and the deliberation reasons of PAD-085.

### 3.6 Standard caveat library

A small set of audited, widely-useful caveats is provided so most grantors never
write custom modules: time-of-day and calendar windows, per-window rate and count
ceilings, value ceilings and running-total ceilings, membership tests against a
context-supplied allow list, and an incident-flag gate. Custom caveats are the
escape hatch, not the common path.

---

## 4. Prior Art Differentiation

Caveats on capabilities are not new. Macaroons (Birgisson et al., 2014)
introduced caveats; Biscuit tokens carry offline-attenuable Datalog caveats;
ZCAP-LD (Authorization Capabilities for Linked Data) carries JSON caveats on
delegatable capabilities. This disclosure does not claim caveats-on-capabilities
in general. What is differentiated is the specific composition:

- **Versus Macaroons and Biscuit.** Macaroon caveats are predicates over request
  context, typically first-party string predicates or third-party discharge;
  Biscuit uses a Datalog engine. This method uses a general deterministic,
  fuel-bounded WebAssembly predicate with a pinned numeric profile and a
  verifier-assembled typed context, so arbitrary conditional logic is expressible
  while cross-verifier byte-identical agreement and denial-of-service-bounded cost
  are guaranteed. Neither Macaroons nor Biscuit target multi-language
  byte-identical Verifiable Credential verification or an explicit fuel and budget
  cost model as the design center.
- **Versus ZCAP-LD caveats.** ZCAP-LD caveats are declarative data interpreted by
  an invoker-specific handler; there is no standard executable evaluation model
  and no guarantee two verifiers evaluate a caveat identically. This method pins
  the module by hash and mandates a deterministic runtime and universal verifier
  obligation, so evaluation is portable and reproducible rather than
  handler-defined.
- **Versus PAD-012 (executable covenants in media).** PAD-012 embeds executable
  usage policy in a C2PA media manifest to govern downstream use of content. This
  method embeds executable caveats in an object-capability delegation chain to
  govern an agent's authority to act, with down-chain accumulation, non-removal,
  and mandatory verifier evaluation as first-class properties absent from the
  media-covenant setting.
- **Versus PAD-056 (allow-list bounded signing) and static policy labels.** Those
  bound authority to an enumerated set fixed at configuration time. This method
  evaluates a predicate over runtime action context, so authority can be
  conditional on facts not known at grant time.
- **Versus calling a policy service (OPA/Rego, XACML PDP) at check time.** Those
  require an online trusted decision point and a shared policy backend. This method
  keeps evaluation offline and self-contained in the capability, preserving
  object-capability portability and removing the runtime trusted third party.
- **Object-capability lineage.** Consistent with the delegation layer being
  object capabilities (zcaps) rather than claim-style Verifiable Credentials, this
  method places conditional authority in the capability itself and preserves the
  invariant that delegation only ever attenuates: a caveat can only further
  restrict, never broaden.

---

## 5. Technical Implementation

The method is realized alongside the protocol's existing capability-attenuation
verification, adding a `caveats` extension evaluated by a conforming WebAssembly
caveat runtime with a pinned numeric profile, together with a standard caveat
library and shared cross-language interop vectors that prove byte-identical
allow/deny across the language implementations. Caveat modules are pinned by
SHA-256; the context is JCS-canonical. The signed link, including its caveat set,
uses the shared `eddsa-jcs-2022` Data Integrity path, so the accumulated caveats
verify offline with no runtime policy service.

---

## 6. Claims Summary

1. A method for attaching to a link of an attenuatable object-capability
   delegation chain one or more caveats, each being a deterministic fuel-bounded
   executable predicate pinned by a hash of its module, such that a verifier
   evaluating a proposed action against the capability must evaluate every caveat
   and reject the action if any denies.
2. The method of claim 1 wherein the effective caveat set of a link is the union
   of its own caveats and its parent's effective set, and the set is part of the
   signed link, so a descendant can add but never remove or weaken an ancestor's
   caveat.
3. The method of claim 1 wherein the caveat runtime has no clock, randomness, or
   input-output beyond a verifier-assembled typed context and a pinned numeric
   profile, so the same caveat and context yield an identical result on every
   independent verifier implementation.
4. The method of claim 1 wherein each caveat carries a fuel limit and the verifier
   enforces a total budget across caveats, and fuel exhaustion or budget excess is
   treated as denial with a named reason, bounding verifier cost against a
   malicious caveat.
5. The method of claim 1 wherein the context supplied to a caveat is constrained
   by a schema declared on the caveat, so the facts a caveat can consider are
   explicit and signed.
6. The method of claim 1 wherein a library of audited standard caveats (time
   windows, rate and count ceilings, value and running-total ceilings, allow-list
   membership, incident gate) is provided so conditional authority is expressible
   without authoring custom modules.
7. The method of claim 1 wherein the caveats compose with static attenuation
   checks and with a two-phase deliberated-execution control, and the capability
   verifies offline without a runtime policy service.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem.
