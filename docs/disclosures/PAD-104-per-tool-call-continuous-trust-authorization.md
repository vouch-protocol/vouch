# PAD-104: Per-Tool-Call Continuous-Trust Authorization with Resource-Bound Delegation

**Identifier:** PAD-104  
**Title:** Method for Authorizing an Individual Agent Tool Call on the Conjunction of Credential Validity, Delegation-Chain Attenuation, Time-Decaying Trust, and Exact-Resource Binding  
**Publication Date:** July 12, 2026  
**Prior Art Effective Date:** July 12, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / Agent Authorization / Tool-Call Governance / Confused-Deputy Prevention / Continuous Trust  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-016 (Dynamic Credential Renewal), PAD-021 (Inverse Capability Protocol), PAD-039 (Deterministic Multi-Party Trust State)  

---

## 1. Abstract

A method for authorizing a single agent tool call (for example a Model Context
Protocol tool invocation) by evaluating, at the moment of the call, the logical
conjunction of four independent conditions, and refusing the call unless all hold:

1. **Credential validity.** The caller presents a Verifiable Credential whose
   Data Integrity proof, temporal window, and required resource binding verify.
2. **Delegation-chain attenuation.** Every link in the credential's delegation
   chain is a proper subset of its parent, so a sub-agent cannot exceed what it
   was delegated.
3. **Current time-decayed trust.** An accompanying SessionVoucher's trust value
   is recomputed at call time under an exponential decay function and compared
   against a per-operation threshold (high, medium, or low stakes).
4. **Exact-resource binding.** The credential's declared `intent.resource` is
   identical to the concrete resource the tool call is about to touch.

Key innovations:

- **Trust as a continuous, per-call quantity.** Unlike a static bearer token
  checked once at session start, trust is recomputed for every individual tool
  call as a decaying value, so a call made late in a session can be refused even
  though the same session's first call was allowed.
- **Conjunctive gate at the tool boundary.** The four conditions are evaluated
  together, at the tool-execution boundary, as a single accept/reject decision,
  rather than as separate checks at separate layers.
- **Resource binding as confused-deputy proof.** Binding the credential to the
  exact resource the call touches turns a generic capability into a
  single-resource capability, so a prompt injection cannot redirect an
  authorized agent to a different resource.

---

## 2. Problem Statement

### 2.1 Session-level authorization is too coarse for autonomous agents

Agent frameworks authorize a session once (an API key, an OAuth token) and then
trust every subsequent tool call for the session's life. An agent that turns
malicious or is hijacked mid-session keeps its authorization. There is no
standard mechanism that re-decides authorization per individual tool call as a
function of how much time and how many actions have elapsed.

### 2.2 The confused-deputy problem at the tool boundary

A tool call carries a verb and a target, but the agent that issues it may have
been redirected by untrusted input (a prompt injection) to call the same tool
against a different, attacker-chosen resource. A capability that says "this agent
may POST" does not constrain where it POSTs.

### 2.3 Delegation chains are verified for structure but not fused with trust

Existing delegation models verify that a chain attenuates, and separate systems
track reputation or liveness, but no method fuses chain attenuation, a live
decaying-trust value, and an exact-resource binding into one per-call decision.

---

## 3. Solution (The Invention)

The verifier exposes a single operation, `verify_tool_call(credential, ...)`,
invoked at the tool boundary before the tool executes. It accepts the caller's
credential, an optional SessionVoucher, the concrete resource the call will
touch, and an operation stakes level, and returns one boolean decision plus a
structured reason set.

The decision is the conjunction:

```
ok = credential_valid
     AND delegation_chain_attenuates
     AND (required_resource is None OR intent.resource == required_resource)
     AND (threshold is None OR trust(now) >= threshold)
```

where:

- `credential_valid` is the eddsa-jcs-2022 proof verification plus temporal and
  required-resource-binding checks.
- `delegation_chain_attenuates` applies the capability-attenuation rule to every
  link (each link a proper subset of its parent across at least one dimension and
  broader on none).
- `trust(now) = initialTrust * exp(-decayLambda * (now - validFrom))`, recomputed
  at the instant of the call, with the threshold drawn from the operation's
  stakes band (for example >= 0.9 for high stakes, >= 0.75 for medium, >= 0.5 for
  low).

Because the trust term is evaluated at call time, the same credential and voucher
yield accept earlier in a session and reject later, with no re-issuance. Because
the resource term requires byte-equality between the granted resource and the
invoked resource, a redirected call to a different resource fails even though the
signature and trust are valid.

A decorator form (`requires_vouch`) wraps a tool handler so an unverified call
never reaches the handler, and the same engine is reused across transports (the
MCP integration and the Agent2Agent integration both call it).

---

## 4. Prior Art Differentiation

- **OAuth / API keys / JWT bearer tokens.** Authorize a session or a request
  window statically; they do not recompute a decaying trust value per call, do
  not fuse delegation attenuation, and do not bind to an exact resource.
- **PAD-016 (Dynamic Credential Renewal).** Establishes continuous trust and
  trust entropy at the credential-renewal layer (the SessionVoucher). The present
  method consumes that decaying trust at the per-tool-call decision point and
  fuses it with delegation attenuation and exact-resource binding, which PAD-016
  does not address.
- **PAD-021 (Inverse Capability).** Governs how much autonomy a capable agent
  gets; it does not define the per-call conjunctive gate or the confused-deputy
  resource binding.
- **Capability systems (object capabilities, macaroons).** Attenuate authority
  but do not incorporate a time-decaying trust scalar evaluated at use time.

---

## 5. Technical Implementation

A reference implementation exposes `verify_tool_call` and a `requires_vouch`
decorator. Inputs: the credential (object or JSON), an optional issuer public key
or DID-resolution flag, an optional SessionVoucher, a `required_resource`, an
optional `required_action`, and a stakes selector or explicit `min_trust`.

Processing:

1. Verify the credential proof (offline against a supplied key, or by resolving
   the issuer DID).
2. Run the delegation-chain attenuation check over `credentialSubject.delegationChain`.
3. If `required_resource` is set, compare it to `credentialSubject.intent.resource`.
4. If a SessionVoucher is present and a threshold is set, compute
   `trust(now)` and compare; also confirm the voucher's subject matches the
   credential subject.
5. Return `ok` as the conjunction plus per-condition reasons.

The same call is exposed inside an MCP server as an open tool and inside an
Agent2Agent integration, so the per-call gate runs at whichever boundary the
deployment uses.

---

## 6. Claims Summary

1. A method for authorizing an individual agent tool call by evaluating, at the
   moment of the call, the conjunction of credential validity, delegation-chain
   attenuation, a time-decayed trust value, and an exact-resource binding, and
   refusing the call unless all conditions hold.
2. The method of claim 1 wherein the trust value is recomputed per call under an
   exponential decay so the same credential yields accept earlier and reject
   later within one session without re-issuance.
3. The method of claim 1 wherein the resource binding requires equality between
   the credential's declared resource and the concrete resource the call will
   touch, preventing a redirected (confused-deputy) call.
4. The method of claim 1 wherein the per-operation trust threshold is selected
   from a stakes band so higher-impact operations demand higher current trust.
5. The method of claim 1 implemented as a handler decorator so an unverified call
   never reaches the tool, and reused across Model Context Protocol and
   Agent2Agent transports.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods described are released under Apache 2.0 and may be
freely implemented. Publication is intended to prevent the patenting of these
methods by any party and to keep them available to the open Vouch Protocol
ecosystem.
