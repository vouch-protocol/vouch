# PAD-063: Live Trust-Standing Propagation Across Agent-to-Agent Calls

**Identifier:** PAD-063  
**Title:** Method for Carrying and Evaluating a Caller Agent's Live Time-Decayed Trust Standing, Identity, and Delegation Chain Across a Cross-Domain Agent-to-Agent Protocol Call  
**Publication Date:** July 12, 2026  
**Prior Art Effective Date:** July 12, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / Multi-Agent Systems / Agent-to-Agent Interoperability / Continuous Trust / Cross-Domain Authorization  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody), PAD-016 (Dynamic Credential Renewal), PAD-104 (Per-Tool-Call Continuous-Trust Authorization)  

---

## 1. Abstract

A method by which a calling agent, when invoking another agent over an
agent-to-agent (A2A) protocol, carries in the call's transport metadata not only
a verifiable identity credential and its delegation chain but a **live trust
standing**: a SessionVoucher whose time-decaying trust value the callee evaluates
**at the moment the call is received**. The callee thereby decides whether to
cooperate based on the caller's current trust, not merely on whether the caller
once held a valid credential.

Key innovations:

- **Trust value travels with the call, evaluated on receipt.** The caller's
  decaying trust is transmitted (as the voucher parameters) and recomputed by the
  callee at receive time, so a caller whose trust has decayed is refused even with
  a structurally valid identity.
- **Namespaced extension carrier.** The identity, chain, and voucher travel in the
  A2A message metadata under a single extension URI, so they coexist with other
  A2A extensions without collision.
- **Capability-card advertisement of a trust requirement.** The callee's agent
  card advertises that it requires a Vouch identity, so the requirement is
  discoverable before the first call.
- **Chain-attenuated cross-domain trust.** The delegation chain accompanies the
  call so the callee can see the full "on behalf of" lineage back to the human or
  root agent, across trust domains.

---

## 2. Problem Statement

### 2.1 A2A calls authenticate the channel, not the live standing of the caller

Agent interoperability protocols establish that a message came from some agent,
but the receiving agent has no standard way to learn the caller's current trust
standing (how recently the caller was attested, how much its trust has decayed)
or the chain of authority on whose behalf the caller acts.

### 2.2 Static credentials do not capture mid-session degradation

A caller may hold a valid identity credential yet have stopped heartbeating or
have drifted from its declared intent. Without a live, decaying trust signal
carried into the call, the callee cannot distinguish a freshly attested caller
from a stale one.

### 2.3 Cross-domain cooperation lacks a portable trust artifact

When two agents belong to different operators, the callee cannot evaluate the
caller's home-domain trust unless that trust is presented in a verifiable,
self-contained form at call time.

---

## 3. Solution (The Invention)

The calling agent attaches, to the A2A message metadata under the extension URI
`https://vouch-protocol.com/ext/a2a/v1`, a block carrying:

- a signed Vouch identity credential (with its delegation chain), and
- an optional SessionVoucher carrying `initialTrust`, `decayLambda`, and
  `validFrom`.

On receipt, the callee:

1. extracts the block from the message (or from the `message/send` params),
2. verifies the credential proof and delegation-chain attenuation,
3. recomputes the caller's trust `trust(now) = initialTrust * exp(-decayLambda *
   (now - validFrom))` at receive time and compares it to the callee's threshold
   for the requested operation, and
4. binds the credential to the exact skill or endpoint being invoked
   (confused-deputy guard).

The callee advertises the requirement by adding a Vouch extension entry to its
agent card's `capabilities.extensions`, optionally marked required, so a caller
discovers the need for a Vouch identity before calling. A handler decorator
refuses any incoming call whose carried trust standing fails verification.

---

## 4. Prior Art Differentiation

- **mTLS / signed requests / API gateways.** Authenticate the channel or the
  sender but do not carry a decaying trust scalar evaluated on receipt, nor the
  delegation lineage.
- **A2A base protocols.** Provide message and task structures and agent cards but
  do not define carrying or evaluating a live, time-decayed trust standing or a
  delegation chain in the message metadata.
- **PAD-016 / PAD-104.** Establish continuous trust at the credential layer and at
  the single-tool-call layer respectively. The present method extends the live
  trust evaluation to the cross-agent A2A boundary, with a namespaced carrier and
  agent-card advertisement, which neither addresses.

---

## 5. Technical Implementation

A reference integration provides: `build_vouch_extension` (the agent-card entry),
`attach_identity` (embed the credential and voucher in a message's metadata under
the extension URI without mutating the input), `extract_identity` (read the block
from a message, a params object, or raw metadata), `verify_incoming` (extract and
run the conjunctive per-call verification, including the receive-time trust
recomputation), and a `requires_vouch_a2a` handler decorator. The verification
reuses the same engine as the per-tool-call gate (PAD-104), so the trust
recomputation and resource binding are identical across MCP and A2A.

---

## 6. Claims Summary

1. A method for carrying, in the metadata of an agent-to-agent protocol call, a
   caller agent's verifiable identity, delegation chain, and a SessionVoucher
   describing a time-decaying trust value, and evaluating that trust at the moment
   the call is received to decide whether to cooperate.
2. The method of claim 1 wherein the carried artifacts reside under a single
   extension URI in the message metadata so as to coexist with other extensions.
3. The method of claim 1 wherein the receiving agent advertises a requirement for
   such an identity in its capability card prior to the first call.
4. The method of claim 1 wherein the delegation chain conveys the cross-domain
   "on behalf of" lineage and the receiving agent binds the credential to the
   exact skill or endpoint invoked.
5. The method of claim 1 wherein the receive-time trust evaluation refuses a
   caller whose trust has decayed below a per-operation threshold despite a
   structurally valid identity.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented. Publication is intended to prevent patenting by any party and to keep
the methods available to the open Vouch Protocol ecosystem.
