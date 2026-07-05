# PAD-084: Localizing a Physical State Change to a Custody Hop via Handoff Condition Attestation

**Identifier:** PAD-084  
**Title:** Method for Localizing a Physical State Change of a Task or Object to a Specific Custody Hop by Attesting a Condition at Each Handoff and Finding the Hop Where It Changed  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Logistics / Incident Attribution  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-083 (Physical Custody Handoff Chain), PAD-002 (Chain of Custody)  

---

## 1. Abstract

A method for pinpointing which actor was responsible for a physical change to a task
or object as it passes through a custody chain. Each custody handoff attests the
condition of the task or object as received. The method walks the chain, finds the
first hop where the attested condition differs from the previous one, and names the
actor who held the task while it changed, so damage, loss, or a quantity drop
localizes to a specific hop rather than the whole route.

Key innovations:

- **Condition attested at the point of acceptance.** The receiving actor records the
  condition of the task as it is received, so the condition is bound into the same
  signed handoff that transfers custody.
- **State-change localization to the responsible holder.** The first hop where the
  attested condition differs identifies the change, and the actor responsible is the
  one who held the task during it, namely the previous handoff's receiver.
- **Composition with the custody chain.** The same handoff credentials that establish
  who held the task carry the condition, so custody and condition are checked over one
  set of credentials.

---

## 2. Problem Statement

### 2.1 A physical change is hard to attribute across a route

When an item is damaged, lost, or short in transit across several actors, there is no
cryptographic way to say which hop it happened in, so responsibility falls on the
whole route or on a dispute.

### 2.2 A custody chain alone shows who held it, not when it changed

Knowing who held a task at each step does not by itself say where the state changed.
The condition needs to be recorded at each acceptance so a change can be located.

---

## 3. Solution (The Invention)

Each `CustodyHandoffCredential` optionally carries a `condition` the receiving actor
attests as it accepts custody (for example a status, a quantity, or a hash of an
inspection). `locate_condition_change(...)` walks the chain, comparing the attested
condition at each handoff to the previous one, and returns the first hop where it
differs together with the actor responsible, the previous handoff's receiver, who held
the task while the condition changed. Because the condition rides in the same signed
handoff that transfers custody, the localization is verifiable from the same
credentials that establish the chain. This is the open layer of software
localization over signed credentials; managed logistics custody orchestration and
automated liability handling are out of scope.

---

## 4. Prior Art Differentiation

Inspection records and interval comparisons each exist as prior art. This disclosure
does **not** claim recording an inspection or comparing values in the abstract. What
is differentiated is the localization of a physical state change to a custody hop:

- **Condition bound into the signed handoff** at the point of acceptance, so the
  attested state and the custody transfer are one credential.
- **Localization to the responsible holder**, identifying the hop where the condition
  changed and the actor who held the task during it.
- **Composition with the custody chain**, so who-held-it and where-it-changed are
  verified over one set of credentials.

---

## 5. Technical Implementation

A reference implementation provides `locate_condition_change` over the same
`CustodyHandoffCredential` set used by the custody chain, returning the responsible
holder and the from and to conditions.

---

## 6. Claims Summary

1. A method for localizing a physical state change of a task or object to a custody
   hop by attesting a condition at each handoff and finding the first hop where the
   attested condition differs from the previous one.
2. The method of claim 1 wherein the actor responsible for the change is the holder
   during it, namely the receiver of the handoff preceding the change.
3. The method of claim 1 wherein the condition is carried within the same signed
   handoff credential that transfers custody.
4. The method of claim 1 wherein the localization is verified over the same custody
   handoff credentials that establish who held the task.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
