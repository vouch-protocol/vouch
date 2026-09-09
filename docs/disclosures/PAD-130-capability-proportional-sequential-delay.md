# PAD-130: Capability-Proportional Sequential Delay

**Identifier:** PAD-130  
**Title:** Method for Enforcing a Minimum Wall-Clock Interval Before an Autonomous System May Be Advanced or Deployed, Where the Required Interval Scales With the Measured Capability Increment Over the Prior Reference Point and Is Evidenced by a Sequential Delay Function Seeded From a Shared Append-Only Log Root  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Rate Limiting / Verifiable Delay / Deployment Control  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-047 (VDF Rate-Limited Agent Actions), PAD-021 (Inverse Capability Protocol), PAD-127 (Pre-Registered Development Step), PAD-131 (Immutable Red Line Commitment), PAD-135 (Simultaneous-Reveal Comparative Disclosure)  

---

## 1. Abstract

Every rate limit that can be bought out of gets cheaper as the party subject to it grows
richer. A sequential delay function cannot be bought out of, because its evaluation is
inherently serial and additional parallel resources do not shorten it. This method makes
the required delay a function of the size of the capability step being taken: the larger
the measured increment over the previous reference point, the longer the mandatory serial
interval before the new system may be advanced further or deployed. A larger leap therefore
purchases the surrounding world a proportionally longer interval in which to observe,
evaluate, and respond, and it does so by arithmetic rather than by anyone's forbearance.

The delay proof is seeded from the current root of a shared append-only log rather than
from an operator-chosen value. Because the seed is not known until the log reaches that
state, the evaluation cannot be started in advance, and because every participant seeds
from the same log, the participants share one clock that none of them sets.

Key innovations:

- **Delay as a monotone function of the capability increment**, so the pause scales with
  the size of the step instead of being a flat interval that large steps and small steps
  pay alike.
- **Seeding the sequential evaluation from a shared log root**, which forecloses
  precomputation and gives mutually distrustful participants a common time base.
- **A rate limit whose cost does not fall with scale**, so the constraint does not weaken
  as the constrained party grows.

---

## 2. Problem Statement

### 2.1 Purchasable rate limits weaken with scale

A limit expressed in resources, quota, or currency binds a small party and does not bind a
large one. The parties whose pace matters most are the parties least constrained by any
limit of that form.

### 2.2 A flat interval is wrong in both directions

A fixed waiting period is an obstruction when the step is small and a formality when the
step is large. The quantity that should determine the interval is the size of the change,
and no existing mechanism couples the two.

### 2.3 Operator-chosen seeds permit precomputation

A delay proof over a value the operator selects can be evaluated in advance, so the proof
demonstrates that computation occurred and not that time elapsed between the two events it
is supposed to separate.

### 2.4 Participants have no common clock they all trust

Where several parties must pace relative to one another, each party's own timestamps are
outside the others' trust base, and there is no shared reference that none of them
controls.

---

## 3. Solution (The Invention)

**Reference point and increment.** A reference point is a prior published capability
measurement for the operator or for the field, expressed over an evaluation plan committed
in advance. The increment is computed as the difference between the candidate system's
measurement on the same committed plan and the reference point, using independently signed
measurement records.

**Delay function.** A published, monotone non-decreasing function maps the increment to a
required number of sequential evaluation steps. The function's parameters are themselves
committed in a tamper-evident record so they cannot be softened once an increment is
known.

**Seeding.** The sequential evaluation is seeded from the concatenation of the current
signed tree head root of the shared append-only log and the digest of the candidate step's
registration. The registration must already be present in that log, so the seed is
unavailable before the registration is committed and cannot be anticipated by any party.

**Evaluation and proof.** The operator evaluates the delay function for the required number
of steps and publishes the output with its succinct verification evidence. Verification is
fast; evaluation is serial. Adding parallel resources does not reduce the elapsed time.

**Gate.** The credential authorizing the next advancement or the deployment of the
candidate carries the delay output, the seed components, the increment, and the delay
function parameters in force. A verifier recomputes the required step count from the
increment, checks the seed against the log root at the registration's index, and verifies
the output. Absent a valid proof, the advancement or deployment credential does not verify.

**Composition.** The measurement records that establish the increment may be obtained
without either party disclosing absolute values, by a simultaneous-reveal comparative
disclosure round, so the increment can be established between rivals. The reference point,
the evaluation plan, and the delay function parameters are all committed before
measurement, so none of the three inputs to the required interval can be adjusted after
the result is known.

**Staged release.** The interval may be applied in stages, with progressively wider
deployment classes unlocked by progressively longer cumulative sequential evidence, so a
capability step is released into use at a rate set by its own size.

---

## 4. Prior Art Differentiation

Verifiable delay functions, proof-of-work, timed-release cryptography, and staged rollouts
are prior art. This disclosure does not claim them. What is differentiated is:

- **Making the required sequential interval a monotone function of a measured capability
  increment**, so the pause is proportional to the size of the step being taken.
- **Seeding the sequential evaluation from a shared append-only log root at the index of
  the step's own prior registration**, which forecloses precomputation and establishes a
  common time base among parties that do not trust one another's clocks.
- **Committing the delay function parameters, the reference point, and the evaluation plan
  in advance**, so every input to the required interval is fixed before the result that
  determines it is known.
- **Staged release keyed to cumulative sequential evidence**, so the breadth of deployment
  is paced by the magnitude of the change.

Verifiable delay functions have been proposed as randomness beacons and as anti-spam
measures. Applying one so that its parameterization is derived from a measured capability
change, and seeding it from a shared log so rivals share a clock, is not a use the prior
art describes.

---

## 5. Technical Implementation

A reference implementation defines the committed reference point and evaluation plan, the
increment computation over independently signed measurements, the committed monotone delay
function, seed derivation from the shared log root and registration digest, the sequential
evaluation and its verification, the gating credential and its verifier, and staged release
classes, all over `eddsa-jcs-2022` Data Integrity proofs and JCS canonicalization.

---

## 6. Claims Summary

1. A method in which a minimum wall-clock interval preceding the advancement or deployment
   of an autonomous system is evidenced by a sequential delay function whose required
   number of steps is a monotone non-decreasing function of a measured capability increment
   over a committed reference point.
2. The method of claim 1 wherein the sequential evaluation is seeded from the current root
   of a shared append-only log combined with the digest of the step's own registration in
   that log, so the seed is unavailable before registration.
3. The method of claim 1 wherein the parameters of the delay function are committed in a
   tamper-evident record prior to measurement, so the required interval cannot be reduced
   after the increment is known.
4. The method of claim 1 wherein the increment is computed over an evaluation plan
   committed prior to measurement and from independently signed measurement records.
5. The method of claim 1 wherein a credential authorizing advancement or deployment carries
   the delay output, seed components, increment, and function parameters, and does not
   verify without a valid delay proof.
6. The method of claim 1 wherein additional parallel computing resources do not reduce the
   elapsed interval, so the constraint does not weaken with the scale of the constrained
   party.
7. The method of claim 4 wherein the measurement records establishing the increment are
   obtained through a simultaneous-reveal comparative disclosure among parties that do not
   disclose absolute values to one another.
8. The method of claim 1 wherein progressively wider deployment classes are unlocked by
   progressively longer cumulative sequential evidence.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
