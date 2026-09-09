# PAD-134: Sealed Dissent Registration

**Identifier:** PAD-134  
**Title:** Method for Registering a Dated Sealed Safety Concern With an Independent Escrow, Where the Content Remains Undisclosed Until a Declared Release Condition Is Met and the Concern's Priority in Time Is Provable Against an Append-Only Log Without Revealing Its Subject, Its Author, or Its Existence to the Party It Concerns  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Escrowed Disclosure / Commitment Schemes / Accountability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-032 (Cryptographic Mortality Protocol), PAD-112 (Conditional Dead-Man Offline Revocation), PAD-131 (Immutable Red Line Commitment), PAD-135 (Simultaneous-Reveal Comparative Disclosure), PAD-017 (Cryptographic Proof of Reasoning)  

---

## 1. Abstract

A person who sees a problem early can either raise it at once, at whatever cost that
carries, or stay quiet and lose the ability to show later that they saw it at the time.
This method removes that choice. A concern is written, canonicalized, encrypted to a key
held by an independent escrow or split across a threshold of escrow holders, and its
commitment is appended to an append-only log. The log index and its signed tree head
establish when the concern was registered. Nothing about the content, the subject, or the
author is disclosed by the entry, which is a fixed-size digest indistinguishable from any
other.

Release occurs on a declared condition: the author opens it, a threshold of escrow holders
releases it, a time lock expires, or the author's liveness chain lapses. On release, the
revealed content is checked against the original commitment, so the concern that emerges is
provably the concern that was registered and not a later reconstruction. Priority in time
is therefore available to the author without exposure at the time of registration.

Multiple authors may register commitments over the same normalized concern digest.
Convergence among independent registrations is then detectable without any of them
identifying themselves or going first, which is the situation in which a single dissenting
account is easiest to discount and a corroborated one is hardest.

Key innovations:

- **Priority without exposure**, since the log entry establishes the date while revealing
  nothing about content, subject, or author.
- **Release by declared condition**, including a lapse in the author's own liveness, so
  registration survives the author's inability or unwillingness to act later.
- **Blind corroboration**, where independent registrations over the same normalized concern
  digest reveal convergence without requiring any author to disclose first.

---

## 2. Problem Statement

### 2.1 Raising a concern and preserving its date are the same act

Under current practice, the only way to establish that a concern was held at a particular
time is to express it publicly at that time, which imposes the full cost of disclosure at
the moment of least certainty.

### 2.2 A concern recalled later cannot be distinguished from one constructed later

An account offered after an outcome is known is unfalsifiable as to when it was formed, and
is discounted accordingly, including when it is accurate.

### 2.3 Internal channels are held by the party concerned

Where the record of a concern is kept by the organization the concern is about, the record's
availability, integrity, and existence are controlled by that organization.

### 2.4 A single account is easy to discount

Independent parties may each hold the same concern and each reasonably believe themselves
alone. Nothing lets them discover the convergence without one of them accepting the cost of
being first.

---

## 3. Solution (The Invention)

**Concern object.** The concern is expressed as a structured object: a normalized subject
descriptor, a free statement, optional evidence anchors binding named artifacts by digest,
and a declared release condition set. The object is canonicalized.

**Sealing.** The canonical object is encrypted to an escrow key, or to a set of escrow
holders under a threshold scheme so no single holder can open it. A commitment is computed
as the digest of the canonical object concatenated with a blinding value held by the
author.

**Registration.** The commitment is appended to an append-only log. The entry carries the
commitment and nothing else, so it discloses neither content nor subject nor author. Its
index and the enclosing signed tree head establish the registration's position in time.

**Liveness chain.** The author optionally maintains a commit and reveal liveness chain
associated with the registration. A lapse in the chain is one of the declared release
conditions, so an author who becomes unable to act does not thereby cause the concern to
be lost.

**Release.** On satisfaction of a declared condition, the sealed object is decrypted by the
escrow or reconstructed by a threshold of holders, and the author's blinding value is
supplied or recovered. A verifier recomputes the commitment from the revealed object and
blinding value, checks it against the logged entry, and confirms the entry's index against
the tree head, establishing that the revealed concern is the registered one and when it
was registered.

**Evidence anchoring.** Evidence anchors bind named artifacts by digest at registration
time, so a concern that refers to a specific artifact can be checked against that artifact
later, and a concern referring to an artifact that did not then exist is distinguishable.

**Blind corroboration.** A normalized subject descriptor is digested separately from the
free statement, and registrations may include this subject digest under a second blinding
scheme permitting equality testing among registrations without disclosure of the descriptor
itself. Independent registrations over the same subject are therefore countable, and the
count is available as a release condition, so a concern may be configured to open when a
threshold of independent parties has registered the same subject.

**Non-repudiation of the registry.** Because the log is append-only with signed tree heads
and consistency proofs, an entry cannot be removed or reordered after the fact, and a
registry showing different states to different observers is detectable by comparison of
tree heads.

---

## 4. Prior Art Differentiation

Commitment schemes, timestamping services, escrow, threshold decryption, dead-man switches,
and secure reporting channels are prior art. This disclosure does not claim them. What is
differentiated is:

- **Separating the establishment of a concern's date from its disclosure**, so priority in
  time is obtained at registration and exposure is deferred to a declared condition.
- **A registry entry that discloses neither content, subject, nor author**, so the existence
  of a concern about a particular party is itself not revealed by the registration.
- **Release on lapse of the author's own liveness chain**, so the registration outlives the
  author's capacity or willingness to act.
- **Blind corroboration over a separately blinded subject digest**, permitting convergence
  among independent registrations to be counted, and used as a release condition, without
  any author disclosing first.
- **Binding evidence anchors by digest at registration time**, so the concern's references
  are checkable against the artifacts as they then existed.

Secure reporting channels deliver a concern to a recipient and depend on that recipient.
Timestamping establishes that a document existed without providing sealed custody,
conditional release, or corroboration counting.

---

## 5. Technical Implementation

A reference implementation defines the canonical concern object and its evidence anchors,
sealing to an escrow or threshold holder set, commitment computation with a blinding value,
append-only registration and index-based priority, the author liveness chain and its lapse
condition, the release conditions and their evaluation, verification of a revealed concern
against its commitment and log entry, and the blinded subject digest supporting
corroboration counting, all over `eddsa-jcs-2022` Data Integrity proofs and JCS
canonicalization.

---

## 6. Claims Summary

1. A method in which a safety concern is canonicalized, sealed to an independent escrow, and
   registered by appending a blinded commitment to an append-only log, so its priority in
   time is established without disclosing its content, subject, or author.
2. The method of claim 1 wherein release of the sealed concern occurs on satisfaction of a
   declared condition comprising author release, threshold escrow release, expiry of a time
   lock, or lapse of the author's liveness chain.
3. The method of claim 2 wherein the author maintains a commitment and reveal liveness
   chain, and a lapse in that chain is itself a release condition.
4. The method of claim 1 wherein, on release, a verifier recomputes the commitment from the
   revealed object and blinding value and checks it against the logged entry, establishing
   that the revealed concern is the registered one.
5. The method of claim 1 wherein the concern carries evidence anchors binding named
   artifacts by digest at registration time.
6. The method of claim 1 wherein a normalized subject descriptor is separately blinded so
   that equality among independent registrations is testable without disclosing the
   descriptor.
7. The method of claim 6 wherein the count of independent registrations over the same
   subject is itself a declared release condition.
8. The method of claim 1 wherein the sealed object is split across a threshold of escrow
   holders so no single holder can open it.
9. The method of claim 1 wherein the append-only log's signed tree heads and consistency
   proofs make removal or reordering of a registration detectable, and divergent registry
   views detectable by comparison across observers.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
