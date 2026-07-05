# PAD-083: Physical Custody Handoff Chain Across Human and Robot Actors

**Identifier:** PAD-083  
**Title:** Method for a Cryptographic Custody Handoff Chain That Records Who Accepted Custody of a Physical Task or Object at Each Hop Across Human and Robot Actors, So a Physical-World Incident Traces to the Exact Hop  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Logistics / Chain of Custody  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-002 (Chain of Custody), PAD-064 (Hardware-Rooted Robot Identity)  

---

## 1. Abstract

A method for making the physical handoff of a task or object accountable across a
chain of actors that mixes people and robots. A custody handoff credential records
that a receiving actor accepted custody of a task or object from a releasing actor,
signed by the receiver, the party taking responsibility. Linking each handoff, so
each receiver becomes the next releaser, forms a chain a verifier walks to establish
who held the task, and a holder-at-time lookup returns who held it at any moment, so
a physical-world incident traces to the exact hop and the actor responsible.

Key innovations:

- **Receiver-signed custody transition for a physical task.** Each handoff is signed
  by the actor accepting custody, so the party taking responsibility attests its own
  acceptance, and the subject is a physical task or object rather than a document or
  a device.
- **Mixed human and robot actor chain.** Actors are Vouch identities that may be a
  person or a robot, so the chain of custody crosses the human-machine boundary
  within one verifiable structure.
- **Holder-at-time attribution.** Given the chain and a time, the method returns the
  actor holding the task then, so a loss, damage, or mis-delivery is attributed to a
  specific hop rather than the whole route.

---

## 2. Problem Statement

### 2.1 Shared physical workflows cross people and machines

In a warehouse, a clinic, or a delivery flow, a physical item passes from a person to
a robot to another robot to a person. When something goes wrong, there is no
cryptographic way to point at the exact hop and actor responsible.

### 2.2 A device custody chain does not cover a physical task

Existing custody chains track ownership of a device or a document over time. A
physical task or object passing between mixed human and robot actors, each accepting
responsibility at handoff, is not the same structure and is not covered.

---

## 3. Solution (The Invention)

`build_handoff(...)` issues a `CustodyHandoffCredential` whose subject carries the
task or object id, the releasing actor, the receiving actor, and an optional attested
condition, signed eddsa-jcs-2022 by the receiver. `verify_handoff(...)` checks the
proof and that the issuer is the receiving actor. `verify_handoff_chain(...)` walks
an ordered list of handoffs, confirms each verifies under its receiver's key and that
every link's receiver matches the next link's releaser, and returns the current
holder. `holder_at(...)` returns the actor holding the task at a given time. Actors
are Vouch identities that may be human or robot, so the chain crosses the
human-machine boundary. Because the credentials use the shared JCS plus
eddsa-jcs-2022 primitives, the same chain verifies across the language SDKs. This is
the open layer of signed credentials and chain verification; managed logistics
custody orchestration and fleet tracking are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, custody chains, and multi-party signing each exist as prior
art, including this project's own ownership custody work. This disclosure does
**not** claim those mechanisms in the abstract. What is differentiated is the
reduction to a physical task handoff across mixed actors:

- **A physical task or object as the subject of custody**, handed between actors,
  rather than a device's ownership over time.
- **A mixed human and robot actor chain**, each receiver signing its own acceptance,
  within one verifiable structure.
- **Holder-at-time attribution**, so a physical-world incident points at the specific
  hop and actor holding the task at the incident time.

---

## 5. Technical Implementation

A reference implementation provides `build_handoff`, `verify_handoff`,
`verify_handoff_chain`, and `holder_at`, using the shared Data Integrity primitives
so the same handoff chain verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for a cryptographic custody handoff chain in which each handoff credential
   records a receiving actor accepting custody of a physical task or object from a
   releasing actor and is signed by the receiver.
2. The method of claim 1 wherein the actors are identities that may be human or robot,
   so the chain of custody crosses the human-machine boundary.
3. The method of claim 1 wherein a verifier walks the chain, confirming each link's
   receiver matches the next link's releaser, and returns the current holder.
4. The method of claim 1 wherein a holder-at-time lookup returns the actor holding the
   task at a given time, so a physical-world incident traces to the exact hop.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same chain verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
