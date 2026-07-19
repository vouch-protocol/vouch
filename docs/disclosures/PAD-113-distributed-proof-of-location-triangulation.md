# PAD-113: Distributed Proof of Location via Multi-Verifier Range Triangulation Bound to a Verifiable Credential

**Identifier:** PAD-113  
**Title:** Method by Which Multiple Independent Verifiers Each Measure a Range to a Node and Jointly Attest, as a Signed Credential, That the Node Occupied a Claimed Position, So That Location Itself Becomes Cryptographically Provable Offline  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Proof of Location / Anti-Spoofing / Offline Verification / Robotics  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-108 (Channel-Geometry Proof of Presence), PAD-015 (Ambient Witness Protocol), PAD-110 (Swarm-Consensus Revocation), PAD-111 (Quorum-of-Orbits Trust Anchoring)  

---

## 1. Abstract

A method by which several independent verifiers, each measuring its own range to a
node, jointly produce a signed attestation that the node occupied a claimed position
at a given moment. Where single-verifier channel geometry (PAD-108) proves a node is
consistent with *one* observer's measurement, triangulation from a threshold of
independent observers over-determines the position and makes a false location claim
require the simultaneous collusion of multiple observers. The result is a portable,
offline-verifiable proof of location: a credential that a third party can check
without trusting any single measurer and without a live positioning service.

Key innovations:

- **Location as a jointly-attested, signed credential.** A threshold of independent
  range measurements is combined into one signed proof-of-location that binds the
  node's identity to a position, verifiable offline by anyone.
- **Over-determination resists spoofing.** Because independent observers'
  measurements must be mutually consistent with a single position, a spoofer must
  defeat several observers at once, not one.
- **No live positioning infrastructure.** The proof is produced and verified among
  the participating nodes at the edge, so it works where GNSS is denied, spoofed, or
  absent (subsea, underground, contested, cislunar).

---

## 2. Problem Statement

### 2.1 Self-reported position is forgeable

A node can assert any position in a signed message. Single-observer geometry checks
tie a claim to one measurement, which a well-placed spoofer can satisfy.

### 2.2 GNSS is not always available or trustworthy

At the disconnected edge, satellite positioning may be denied, jammed, spoofed, or
physically unavailable, so a node cannot simply present a GNSS fix as proof.

### 2.3 A verifier needs portable, independent evidence

A relying party that was not present needs to check *where a node was* after the fact,
without trusting the node and without a live service.

---

## 3. Solution (The Invention)

At a given moment, a threshold M of N independent verifiers each measure a range to the
target node (by time-of-flight or two-way ranging on their respective links) and each
sign a range observation binding the target's identity, the measuring verifier's own
attested position, the measured range, a shared nonce, and the epoch. A combiner (any
participant) checks that the observations are mutually consistent with a single
position for the target — i.e., the position that best fits all ranges lies within
tolerance of every observation — and issues a `ProofOfLocationCredential` binding the
target identity, the solved position, the contributing observers, and the epoch.

A later verifier checks each observer's signature and attested position, recomputes the
position fit, and confirms at least the threshold of independent observers agree within
tolerance. Because independent observers must all be consistent with one position, a
false claim requires colluding observers to reach the threshold; a single spoofed or
faulty observer is outvoted by the fit. The mechanism composes with single-observer
presence (PAD-108) as the per-observer measurement, and with the distinct-failure-
domain requirement (PAD-111) so the observers span independent domains.

---

## 4. Prior Art Differentiation

Multilateration, TDOA/TOA positioning, and secure distance-bounding are established
prior art. This disclosure does **not** claim triangulation or ranging themselves.
What is differentiated is:

- **Binding a multi-observer triangulation into a signed, portable proof-of-location
  Verifiable Credential** tied to a decentralized identity, verifiable offline by a
  non-present third party.
- **A threshold-of-independent-observers trust model for the position claim**, so
  spoofing requires multi-observer collusion rather than defeating one measurement.
- **Operation without live positioning infrastructure**, among edge nodes in
  GNSS-denied settings, composing per-observer channel geometry (PAD-108) and
  independent-failure-domain observers (PAD-111).

Positioning systems output a fix consumed by a connected application; they do not
produce a self-contained, identity-bound, threshold-attested proof-of-location
credential a disconnected verifier checks after the fact.

---

## 5. Technical Implementation

A reference design defines a signed range-observation record (target, observer,
observer position, measured range, nonce, epoch), a position-fit combiner that admits
a proof only when a threshold of mutually-consistent independent observations agree,
and a `ProofOfLocationCredential` carrying the solved position and contributors.
Per-observer measurement reuses PAD-108; observer independence reuses PAD-111. Range
acquisition is platform-specific; the open layer is the observation and proof formats
and the consistency/threshold predicate.

---

## 6. Claims Summary

1. A method by which a threshold of independent verifiers each sign a measured range to
   a node and a combiner issues a signed credential attesting the node's position only
   when the observations are mutually consistent with a single position within
   tolerance.
2. The method of claim 1 wherein a later verifier confirms the position offline by
   recomputing the fit over the signed observations and requiring at least the
   threshold of independent observers to agree.
3. The method of claim 1 wherein a false position claim requires collusion of at least
   the threshold of observers, so a single spoofed or faulty observer does not move the
   attested position.
4. The method of claim 1 wherein the observers are required to occupy distinct
   independent domains, and each observer's own position is itself attested.
5. The method of claim 1 operating with no live positioning infrastructure, among edge
   nodes in a satellite-navigation-denied environment.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
