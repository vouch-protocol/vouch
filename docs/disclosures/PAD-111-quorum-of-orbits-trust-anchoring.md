# PAD-111: Quorum-of-Orbits Trust Anchoring — Accepting a Trust-State Update Only on Corroboration by Independent-Failure-Domain Anchors

**Identifier:** PAD-111  
**Title:** Method by Which a Disconnected Mobile Node Accepts a Trust-State Update — Revocation Deltas, New Anchors, or Freshness Advances — Only When Corroborated by a Threshold of Anchors Drawn From Distinct Independent Failure Domains, With Monotonic-Epoch Rollback Resistance  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Trust Distribution / Delay-Tolerant Networking / Byzantine Resistance / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-110 (Swarm-Consensus Revocation), PAD-046 (Algorithm Quorum via Cryptosuite Diversity), PAD-039 (Deterministic Multi-Party Trust State)  

---

## 1. Abstract

A method by which a moving node in a delay-tolerant network updates its local trust
state — the set of trusted issuer anchors, revocation deltas, and freshness epoch —
only when the update is corroborated by a threshold of relays drawn from **distinct,
independent failure domains** (different orbits, different operators, different
administrative authorities). During a brief line-of-sight pass a node may reach one
relay; naively trusting it lets a single captured or spoofed relay inject a false
revocation, retract a real one, or advance a false freshness epoch. This disclosure
requires that a trust-state change be admitted only when M of N corroborating
attestations, from anchors in distinct failure domains, agree on the same change,
and it orders all changes by a monotonic epoch so a captured relay cannot roll the
node back to a stale state.

Key innovations:

- **Diversity-of-failure-domain quorum, not just count.** Corroboration must come from
  anchors in *distinct* independent domains (orbit/operator/authority), so
  compromising one relay, one operator, or one orbital plane is insufficient to move a
  node's trust state.
- **Applied to trust-state distribution at a disconnected mobile node.** The quorum
  governs the *acceptance of sync itself* — anchors, revocation deltas, freshness —
  during intermittent contact, not a single credential verification.
- **Monotonic-epoch rollback resistance.** Every trust-state update carries a
  monotonic epoch; a node refuses any update whose epoch precedes its current state,
  so a captured relay cannot replay an older, more permissive trust state.

---

## 2. Problem Statement

### 2.1 A single contact is a single point of failure

A disconnected node that updates its trusted anchors or revocation state from whatever
relay it can reach during a pass is at the mercy of that relay. A captured, spoofed,
or faulty relay can inject a false revocation (denial of service against an honest
peer), suppress a real revocation (keeping a compromised peer trusted), or lie about
the current freshness epoch.

### 2.2 Counting corroborators is not enough

Requiring several corroborating attestations helps only if they fail independently.
Several relays in the same orbit, operated by the same entity, or signed under the
same compromised authority are one failure, not many.

### 2.3 Rollback is a subtle attack

Even authentic, previously-valid trust states are dangerous if replayed: an adversary
can feed a node an older state that predates a revocation, making a since-revoked peer
appear valid again.

---

## 3. Solution (The Invention)

A trust-state update (an added or removed anchor, a revocation delta, a freshness-epoch
advance) is packaged as a signed, epoch-stamped change. A node admits the change only
when it holds corroborating attestations for the *same* change from at least a
threshold M of N anchors, where the corroborating anchors must belong to **distinct
declared failure domains** — different orbital planes, different operators, or
different administrative authorities — so that no single compromised domain can reach
the threshold alone.

Every change carries a monotonic epoch. A node applies a change only if its epoch is
greater than or equal to the node's current trust-state epoch for that scope, and it
records the new epoch, so a later replay of an older state is rejected. Corroboration
may be collected across multiple passes and relays: the node accumulates distinct-
domain attestations for a pending change until the threshold is met, then applies it.

The failure-domain labels are themselves part of the anchors' issued identity, so a
verifier can confirm that the corroborating set genuinely spans distinct domains and
is not one domain wearing several hats. The mechanism composes with bounded-staleness
revocation (PAD-106): the freshness epoch it advances is exactly the input that gate
consumes, and with swarm-consensus quarantine (PAD-110): a locally-generated
quarantine can be corroborated up to a durable revocation through the same diversity
quorum.

---

## 4. Prior Art Differentiation

Threshold trust, multi-signature, quorum systems, and this project's algorithm-quorum
(PAD-046) and multi-party trust state (PAD-039) are prior art. This disclosure does
**not** claim quorum verification in general. What is differentiated is:

- **A quorum defined over distinct, declared independent failure domains** (orbit /
  operator / authority), so diversity of failure — not mere count — is the security
  property, applied to the *distribution* of trust state.
- **Governing acceptance of a trust-state sync at a disconnected, mobile node** during
  intermittent contact, rather than verifying a single credential or aggregating a
  single decision (PAD-046 concerns cryptosuite diversity for one signature; PAD-039
  concerns deterministic shared state, not adversarial sync acceptance).
- **Monotonic-epoch rollback resistance on trust-state updates**, so authentic-but-
  stale states cannot be replayed to re-trust a revoked party.

Multi-source verification and quorum trust anchors in PKI assume connected verifiers
and do not define a distinct-failure-domain quorum for accepting revocation and anchor
updates at an intermittently-connected mobile node with rollback resistance.

---

## 5. Technical Implementation

A reference design defines a trust-state change record (scope, change, epoch, issuing
anchor with its declared failure-domain label), an accumulator that admits a change on
M-of-N distinct-domain corroboration, and a per-scope epoch high-water mark that
rejects regressions. Anchor identities and their domain labels reuse the recognized-
issuer authority layer; the advanced freshness epoch feeds PAD-106/PAD-107. Relay
operation and orbital assignment are deployment concerns; the open layer is the change
record, the distinct-domain quorum rule, and the monotonic-epoch acceptance test.

---

## 6. Claims Summary

1. A method by which a disconnected mobile node accepts a trust-state update — an
   anchor change, a revocation delta, or a freshness-epoch advance — only when
   corroborated by at least a threshold of anchors belonging to distinct declared
   independent failure domains.
2. The method of claim 1 wherein the distinct failure domains are distinct orbits,
   distinct operators, or distinct administrative authorities, so that compromising a
   single domain cannot reach the threshold.
3. The method of claim 1 wherein each trust-state update carries a monotonic epoch and
   the node rejects any update whose epoch precedes its current state for that scope,
   preventing rollback to a more permissive stale state.
4. The method of claim 1 wherein corroborating attestations for the same change are
   accumulated across multiple contact passes and relays until the distinct-domain
   threshold is met.
5. The method of claim 1 wherein the anchors' declared failure-domain labels are part
   of their issued identity, so a verifier confirms the corroborating set genuinely
   spans distinct domains.
6. The method of claim 1 wherein the advanced freshness epoch feeds a consequence-
   scaled staleness gate, and a locally-generated peer quarantine is corroborated to a
   durable revocation through the same distinct-domain quorum.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
