# PAD-112: Conditional Dead-Man Revocation for Disconnected Nodes via Pre-Signed Self-Revoking Credentials

**Identifier:** PAD-112  
**Title:** Method by Which an Authority Pre-Signs a Conditional Revocation Shipped Ahead of Time So a Disconnected Node Self-Revokes Its Own Credential Offline When a Renewal Condition Is Not Met by a Named Epoch  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Revocation / Offline Verification / Delay-Tolerant Networking  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-016 (Heartbeat Protocol), PAD-032 (Cryptographic Mortality Protocol)  

---

## 1. Abstract

A method by which an authority, while in contact, hands a node a *pre-signed
conditional revocation* — a signed instruction that takes effect automatically if a
renewal condition is not satisfied by a named network epoch — so a compromised or
lost node can be revoked *without* the authority ever regaining contact. The
condition, the deadline epoch, and the authority's signature travel with the node.
A verifier (including the node itself) honors the conditional revocation once the
deadline passes unmet, closing the gap in which a node that goes dark cannot be
reached by a conventional revocation list.

Key innovations:

- **Revocation that fires on the absence of renewal, offline.** The authority's
  decision is pre-committed and self-executing at the edge, so it does not require a
  live channel at the moment revocation must take effect.
- **Consequence-appropriate deadlines.** The renewal deadline is set when the grant
  is issued and can be tuned to the node's risk, so a high-value node fails safe
  quickly and a low-risk one persists longer.
- **Verifier-enforced, not self-policed only.** Any verifier holding the conditional
  revocation enforces it against the node, so a compromised node cannot evade its own
  dead-man switch merely by ignoring it.

---

## 2. Problem Statement

### 2.1 A node that goes dark cannot be reached by a revocation list

If a node is captured or lost while out of contact, the authority may never regain a
channel to publish a revocation. The node retains a valid, unexpired credential
indefinitely.

### 2.2 Short expiries are a blunt instrument

Simply issuing very short-lived credentials forces frequent renewal contact that a
delay-tolerant node cannot make, and still does not let the authority express "revoke
if a specific condition fails," only "expire on a fixed clock."

### 2.3 Self-revocation alone is not trustworthy

A node instructed to revoke itself under a condition may be compromised and simply
decline to. The mechanism must be enforceable by others, not only by the subject.

---

## 3. Solution (The Invention)

At issuance the authority signs a conditional revocation bound to the node's
credential: a predicate (for example, "unless a renewal token carrying epoch ≥ E is
presented") and a deadline epoch, all signed. The conditional revocation is
distributed with the node and, where applicable, to the peers it will interact with.

Once the deadline epoch has passed (as established by the monotonic network-epoch
mechanism, PAD-107) without the renewal condition being satisfied, the conditional
revocation becomes active: the node's own verifier treats its credential as revoked,
and any peer holding the conditional revocation likewise refuses the node. Renewal is
an ordinary in-contact operation (a fresh session voucher / heartbeat, PAD-016) that
carries an epoch at or beyond the deadline, which cancels the pending revocation and
sets the next deadline.

Because the authority's signature is pre-committed, no live authority is needed for
the revocation to take effect; because peers enforce it, a compromised node cannot
suppress its own dead-man switch. Whole-identity escalation, if required, still routes
through the standard registry (PAD-032).

---

## 4. Prior Art Differentiation

Credential expiry, renewal/heartbeat schemes, and dead-man switches are prior art.
This disclosure does **not** claim expiry or renewal generally. What is differentiated
is:

- **A pre-signed, conditionally-triggered revocation that fires on the absence of a
  renewal at the edge**, distinct from a fixed expiry (which cannot express a
  condition) and from a live-published revocation (which requires a channel that the
  dark node denies).
- **Deadline expressed in monotonic network epochs**, so the trigger is well-defined
  on a node whose wall-clock cannot be trusted (composing PAD-107).
- **Third-party enforceability**, so the switch is honored by peers and does not
  depend on the possibly-compromised subject cooperating.

Certificate expiry and OCSP produce time-bounded or live-checked status; neither
carries a pre-signed conditional revocation that a disconnected verifier activates on
the failure of a renewal condition at a named epoch.

---

## 5. Technical Implementation

A reference design defines a conditional-revocation record (target credential, renewal
predicate, deadline epoch, authority signature) attached to or distributed alongside a
credential, and a verifier check that activates the revocation once the current epoch
exceeds the deadline with no satisfying renewal seen. Renewal reuses the session-
voucher/heartbeat path (PAD-016); epoch ordering reuses PAD-107; whole-identity
escalation reuses PAD-032. The open layer is the conditional-revocation format and the
activation predicate.

---

## 6. Claims Summary

1. A method wherein an authority pre-signs, while in contact, a conditional revocation
   of a node's credential that becomes active if a renewal condition is not satisfied
   by a named epoch, and the node self-revokes offline when the condition fails.
2. The method of claim 1 wherein the deadline is expressed in a monotonic network-
   epoch counter so the trigger is well-defined without a trusted wall-clock.
3. The method of claim 1 wherein a peer holding the conditional revocation also refuses
   the node once the deadline passes unmet, so a compromised node cannot suppress its
   own dead-man switch.
4. The method of claim 1 wherein an in-contact renewal carrying an epoch at or beyond
   the deadline cancels the pending revocation and sets the next deadline.
5. The method of claim 1 wherein the renewal deadline is chosen per node according to
   its risk, and whole-identity escalation routes through a separate revocation
   registry.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
