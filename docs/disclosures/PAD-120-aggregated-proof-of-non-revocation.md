# PAD-120: Carried Aggregated Proof of Non-Revocation for Offline Presentation

**Identifier:** PAD-120  
**Title:** Method by Which a Node Carries and Presents a Compact Cryptographic Proof That Its Credential Was Not Revoked as of a Named Epoch, Verifiable Offline Without the Verifier Holding or Fetching a Full Status List  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Revocation / Offline Verification / Delay-Tolerant Networking  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-111 (Quorum-of-Orbits Trust Anchoring)  

---

## 1. Abstract

Bounded-staleness revocation (PAD-106) has the *verifier* judge the age of a status-list
snapshot it holds. This method instead lets the *presenter* carry a compact,
authority-issued proof that its own credential was not revoked as of a named epoch —
a short inclusion/exclusion witness against the authority's current revocation set —
so a verifier that holds *no* status list at all can still confirm non-revocation
offline. The witness is small (independent of the number of credentials in the set), is
bound to a monotonic epoch, and shifts the data burden from the verifier to the
presenter, which is the party that had contact.

Key innovations:

- **Presenter-carried non-revocation witness.** The node obtains, while in contact, a
  compact proof-of-non-revocation for its own credential and carries it, so a verifier
  needs neither a full status list nor a live fetch.
- **Epoch-bound freshness.** The witness names the epoch it is current as of, so it
  composes directly with consequence-scaled staleness (PAD-106): the verifier judges the
  witness's epoch age, not a whole list's.
- **Compact and burden-shifting.** The witness size is independent of the population, so
  it suits constrained links and moves the storage/transfer cost to the presenter.

---

## 2. Problem Statement

### 2.1 Carrying a full status list is expensive for the verifier

A verifier that must judge revocation offline needs the whole status list, which is
large to store and transfer and must be re-synced. A constrained verifier may not hold a
current one.

### 2.2 The presenter is the party that had contact

The node presenting a credential is often the one that most recently reached the
authority; it is better placed to carry evidence about its own status than to expect
every verifier to hold the whole population's status.

### 2.3 The evidence must be fresh and forgery-resistant

A carried non-revocation proof must be tied to a specific epoch and to the authority, so
it cannot be replayed to appear more current than it is.

---

## 3. Solution (The Invention)

The authority maintains its revocation set with an accumulator or authenticated set
structure and, on contact, issues each non-revoked node a compact witness proving its
credential's non-membership in the revoked set (or membership in the valid set) as of the
current epoch, signed and epoch-stamped. The node carries and presents this witness. A
verifier checks the authority's signature, checks the witness against the authority's
public accumulator value (which is small and slowly-changing, distributable via the
distinct-domain quorum of PAD-111), and judges the witness's epoch age under the
consequence-scaled staleness gate (PAD-106). The verifier holds no full status list. A
newer witness supersedes an older one (monotonic epoch), preventing a node from
presenting a stale witness as current.

---

## 4. Prior Art Differentiation

Cryptographic accumulators and non-membership witnesses for revocation are established
prior art (RSA and Merkle accumulators, CRLite-style structures). This disclosure does
**not** claim accumulators or witness-based revocation generally. What is differentiated
is:

- **Presenter-carried, epoch-bound non-revocation witnesses evaluated by a fully
  disconnected verifier that holds no status list**, in a delay-tolerant setting.
- **Direct composition with a consequence-scaled staleness gate** (PAD-106): the
  verifier judges the *witness's* epoch age against the action's consequence.
- **Distribution of the small accumulator value via a distinct-failure-domain quorum**
  (PAD-111) so a single relay cannot feed a false accumulator state.

Accumulator-based revocation in the literature assumes a verifier that fetches or holds
the current accumulator online; it does not define a presenter-carried, epoch-scoped,
consequence-gated non-revocation proof for a disconnected verifier holding nothing.

---

## 5. Technical Implementation

A reference design defines an authority-issued non-revocation witness (credential
reference, accumulator witness, epoch, signature), a verifier check against a
distributed accumulator value and the PAD-106 staleness gate, and a supersession rule on
epoch. The accumulator construction is standard; the open layer is the carried-witness
format, the epoch scoping, and the disconnected verifier predicate.

---

## 6. Claims Summary

1. A method by which a node carries an authority-issued compact witness proving its
   credential was not revoked as of a named epoch and presents it to a verifier that
   holds no status list.
2. The method of claim 1 wherein the verifier confirms non-revocation offline by checking
   the witness against a distributed authority accumulator value and the authority's
   signature.
3. The method of claim 1 wherein the verifier judges the witness's epoch age under a
   consequence-scaled staleness gate.
4. The method of claim 1 wherein a witness of a later epoch supersedes an earlier one, so
   a stale witness cannot be presented as current.
5. The method of claim 1 wherein the authority accumulator value is distributed via a
   quorum of anchors from distinct independent failure domains.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
