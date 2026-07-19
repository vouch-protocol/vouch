# PAD-107: Presenter-Side Proof of Freshness Bound to Monotonic Delay-Tolerant Network Epochs

**Identifier:** PAD-107  
**Title:** Method for a Disconnected Verifier to Require a Presenter to Prove Recent Contact With a Trusted Relay via a Short-Lived Token Bound to a Monotonic Network-Epoch Counter, With the Acceptable Epoch Gap Scaled to the Action's Consequence  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Freshness / Anti-Replay / Delay-Tolerant Networking / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-016 (Heartbeat Protocol), PAD-039 (Deterministic Multi-Party Trust State)  

---

## 1. Abstract

A method by which a disconnected verifier requires the *presenter* of a credential
to prove it has been in recent contact with the trusted network, without either
party reaching a live authority at decision time. A relay designated as a freshness
anchor issues the presenter a short-lived token bound to a monotonically increasing
network-epoch counter. At authorization time the verifier admits the presenter only
if the token is currently valid and its epoch is within a consequence-scoped
distance of the verifier's own last-known epoch. Because freshness is measured in
network epochs advanced by relays rather than in wall-clock time, the mechanism
resists the clock drift that afflicts a node that has been out of contact for a long
period.

Key innovations:

- **Presenter-side proof of liveness, complementary to verifier-side staleness.** A
  companion to bounding the verifier's own revocation view (PAD-106): here the
  presenter must demonstrate recent network contact, closing the case of a valid,
  unexpired credential held by a node that has been unaccountable for a long time.
- **Freshness measured in monotonic network epochs, not wall-clock.** A relay-
  advanced epoch counter provides an adversary-resistant ordering that does not
  depend on synchronized time, so a disconnected node with a drifted clock can still
  be held to a recency requirement.
- **Consequence-scoped epoch gap.** The maximum acceptable distance between the
  presenter's proven epoch and the verifier's epoch is a function of the action's
  consequence, so a low-consequence action tolerates a larger gap than an
  irreversible one.

---

## 2. Problem Statement

### 2.1 A valid credential says nothing about recent contact

A presenter may hold a perfectly valid, unexpired credential while having been out
of contact — and therefore unaccountable and unpatched against revocation — for a
long time. Verifier-side staleness bounding limits how old the *verifier's*
revocation view may be, but does not require the *presenter* to have checked in.

### 2.2 Wall-clock freshness fails on disconnected nodes

A node out of contact for weeks or months cannot be assumed to hold accurate time;
its clock may have drifted or been reset. A freshness requirement expressed in
wall-clock seconds is therefore unreliable exactly where it is most needed.

### 2.3 Recency requirements must scale to consequence

Demanding very recent contact for every action is impractical in a delay-tolerant
setting where contact windows are rare. The recency bar should be strict for
consequential actions and lenient for trivial ones.

---

## 3. Solution (The Invention)

A relay designated by the authority as a freshness anchor issues a presenter a
short-lived freshness token — a signed credential whose subject is the presenter's
identifier and which carries a monotonically increasing network-epoch value and an
anti-replay nonce — during a contact window. Relays advance the epoch counter, so
the epoch provides a network-wide ordering independent of any node's clock.

At authorization time the verifier requires the presenter to show a freshness token
whose signature and window verify, and whose epoch is within a consequence-scoped
maximum gap of the verifier's own last-known epoch:

    epoch_gap = verifier_epoch − token.epoch
    admit if token valid AND epoch_gap ≤ max_epoch_gap[consequence_tier]

A complete disconnected authorization applies this presenter-side requirement
together with the verifier-side bounded-staleness gate (PAD-106) and the
unconditional revocation-bit check: a known revocation always denies, the verifier's
revocation snapshot must be fresh enough for the tier, and the presenter must carry a
recent-enough freshness token. The freshness token reuses the existing renewable
session-voucher construction (PAD-016), issued by a delay-tolerant relay rather than
an always-connected validator, with recency expressed in epochs.

---

## 4. Prior Art Differentiation

Short-lived tokens, session renewal, nonces, and monotonic counters are established
prior art, including this project's own heartbeat/session-voucher work (PAD-016).
This disclosure does **not** claim those. What is differentiated is:

- **Recency bound to a network-epoch counter rather than wall-clock time**, to
  survive clock drift on long-disconnected nodes.
- **A presenter-side proof-of-contact requirement enforced by a disconnected
  verifier**, as the dual of verifier-side staleness bounding, with both applied
  together in one authorization decision.
- **A consequence-scoped acceptable epoch gap**, so the recency bar tracks the
  action's consequence rather than a single fixed interval.

Distance-bounding and freshness-nonce protocols establish proximity or liveness at a
single moment against a connected counterpart; they do not provide a carried,
relay-issued, epoch-ordered proof of *recent network contact* that a fully
disconnected verifier evaluates against its own epoch with a consequence-scaled
tolerance.

---

## 5. Technical Implementation

A reference design issues a freshness token as a signed session-voucher-shaped
credential carrying an epoch and nonce, and a verifier-side check that combines
token validity, epoch-gap tolerance per consequence tier, and the PAD-106 staleness
gate. Epoch advancement is a relay responsibility; the open layer is the token
format and the verifier decision. Rollback is bounded by refusing a token whose
epoch precedes the newest already seen for that presenter.

---

## 6. Claims Summary

1. A method by which a disconnected verifier admits a presenter only if the presenter
   shows a valid, short-lived token, issued by a trusted relay, that binds the
   presenter's identifier to a monotonically increasing network-epoch value.
2. The method of claim 1 wherein the verifier admits the presenter only if the
   difference between the verifier's last-known epoch and the token's epoch is within
   a maximum configured for the consequence tier of the requested action.
3. The method of claim 1 wherein recency is measured in relay-advanced network epochs
   rather than wall-clock time, so the requirement holds on a node whose clock has
   drifted or reset.
4. The method of claim 1 applied together with a verifier-side revocation-snapshot
   staleness gate and an unconditional revocation-status check in a single
   authorization decision.
5. The method of claim 1 wherein the token reuses a renewable session-voucher
   construction issued by a delay-tolerant relay, and rollback is bounded by
   rejecting a token whose epoch precedes the newest previously observed.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
