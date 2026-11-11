# PAD-132: Oversight Ratio Bound

**Identifier:** PAD-132  
**Title:** Method for Conditioning Authorization of a Development or Deployment Step on a Committed Minimum Ratio Between the Step's Compute Measure and an Accumulated Measure of Independently Attested Oversight Work Bound to the Same Artifacts, With Non-Reusable Oversight Receipts  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Oversight Accounting / Authorization Predicates / Evaluation Integrity  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-131 (Immutable Red Line Commitment), PAD-125 (Census-Complete Compute Ceiling Attestation), PAD-127 (Pre-Registered Development Step), PAD-021 (Inverse Capability Protocol), PAD-017 (Cryptographic Proof of Reasoning)  

---

## 1. Abstract

The concern most often expressed about the pace of autonomous system development is not
that capability grows, but that oversight does not grow with it. That concern has no
enforceable expression. This method supplies one: an authorization predicate coupling the
two quantities directly. Oversight work is recorded as signed **oversight receipts**, each
naming the party that performed it, the class of work, a measure, and, critically, the
digests of the specific artifacts the work examined. Receipts accumulate over a period. A
development or deployment step is authorized only when the accumulated oversight measure
bound to that step's own artifacts stands in at least a committed ratio to the step's
compute measure.

Two rules give the predicate its force. A receipt is bound to artifact digests and to a
period, and is consumed by nonce, so the same oversight work cannot be counted toward two
steps. And the ratio itself is committed in advance in a tamper-evident record, so it
cannot be lowered once a step fails the check. The result is a rule an operator can state
in one line and a counterparty can verify: capability may not scale faster than the
verified oversight bound to it.

Key innovations:

- **Oversight as a measured, artifact-bound, accumulable quantity** rather than an activity
  described in prose.
- **A committed ratio between compute and oversight as an authorization predicate**,
  evaluated by the party granting the resource.
- **Non-reusable receipts**, so oversight applied to one artifact set cannot be re-spent
  against another.

---

## 2. Problem Statement

### 2.1 Oversight is described, not measured

Interpretability analysis, red-team exercise, evaluation coverage, and human review are
reported qualitatively. There is no quantity that can be compared against anything, and
therefore no way to state a relationship between oversight and the thing overseen.

### 2.2 Oversight is not bound to what it examined

A report that work was done does not identify the artifacts examined. Work performed on one
version is therefore indistinguishable from work performed on the version actually shipped.

### 2.3 The same work can be counted repeatedly

Where oversight is reported in aggregate, a single exercise can be cited in support of many
subsequent decisions, and no observer can detect the reuse.

### 2.4 A ratio stated after the fact is not a constraint

Any relationship between capability and oversight that can be restated once a step is
pending is a description of what happened rather than a condition on what may happen.

---

## 3. Solution (The Invention)

**Oversight receipt.** A receipt is signed by the party that performed the work and names:
the performing identifier and its independence class, the work class (for example
interpretability analysis, adversarial evaluation, coverage evaluation, or human review),
a measure expressed in the unit declared for that class, the period, the set of artifact
digests examined, and a unique receipt nonce.

**Independence weighting.** Each work class carries a declared weight, and receipts from
parties whose independence class is external to the operator may carry a distinct weight
from internal ones. The accumulated oversight measure for a step is the weighted sum over
receipts whose artifact digests intersect the step's own artifact set.

**Compute measure.** The step's compute measure is taken from the step's registration and,
where available, from the period accounting produced by census-complete ceiling
attestation, so the denominator of the ratio is itself evidenced rather than declared.

**Committed ratio.** The minimum ratio is a threshold within the operator's committed
threshold policy, so its value at the time of the check is the value committed before the
step, and any relaxation is a dated amendment ordered after the step.

**Authorization predicate.** The step's authorization credential carries the accumulated
oversight measure, the compute measure, the receipt identifiers relied upon, and the
committed ratio's policy reference. A verifier recomputes the weighted sum from the named
receipts, checks each receipt's artifact intersection with the step, checks that no receipt
nonce has been consumed by a prior step, and admits the step only if the ratio holds.

**Consumption.** On admission, the relied-upon receipt nonces are marked consumed for the
purposes of the predicate, so a subsequent step must be supported by oversight work not
already spent. Partial consumption is expressible where a receipt's measure exceeds what a
step requires, with the remainder available to later steps.

**Class-specific floors.** In addition to the aggregate ratio, per-class floors may be
required, so a step cannot satisfy the predicate entirely from the cheapest class of
oversight work.

**Composition.** The predicate composes with a pre-registered step, whose registration
supplies the artifact set and the compute measure, and with a recursion ceiling, whose
human review edges are themselves receipts of the human review class.

---

## 4. Prior Art Differentiation

Code review requirements, test coverage gates, audit evidence collection, and compliance
attestation are prior art. This disclosure does not claim them. What is differentiated is:

- **Expressing oversight as a weighted, accumulable measure bound to artifact digests**,
  so it can enter an arithmetic relation with a compute measure.
- **Conditioning the grant of a compute or deployment step on a committed ratio between
  the two measures**, evaluated by the granting party.
- **Non-reusable receipts consumed by nonce with expressible partial consumption**, so
  oversight cannot be counted twice.
- **Independence weighting and per-class floors**, so the composition of the oversight, not
  only its total, is constrained.

Coverage gates relate tests to code within one project's tooling and are enforced by that
project on itself. They do not produce signed, independently attributable, artifact-bound,
non-reusable evidence, and they do not condition the allocation of a resource on a
committed ratio.

---

## 5. Technical Implementation

A reference implementation defines the oversight receipt and its canonical form,
independence and work class weighting, artifact-digest intersection, the accumulated
weighted measure, the compute measure sourced from registration and period accounting, the
committed ratio reference into a threshold policy, the authorization predicate and its
verifier, nonce consumption with partial consumption, and per-class floors, all over
`eddsa-jcs-2022` Data Integrity proofs and JCS canonicalization.

---

## 6. Claims Summary

1. A method in which oversight work is recorded as signed receipts naming a performing
   identifier, a work class, a measure, a period, and the digests of the artifacts
   examined.
2. The method of claim 1 wherein an accumulated oversight measure for a step is computed as
   a weighted sum over receipts whose artifact digests intersect the step's artifact set.
3. The method of claim 2 wherein authorization of a development or deployment step is
   conditioned on the accumulated oversight measure standing in at least a declared ratio
   to the step's compute measure.
4. The method of claim 3 wherein the declared ratio is committed in a tamper-evident record
   prior to the step, so it cannot be relaxed after the step fails the predicate.
5. The method of claim 2 wherein each receipt carries a nonce consumed on admission of a
   step, so the same oversight work cannot be counted toward a further step.
6. The method of claim 5 wherein a receipt whose measure exceeds a step's requirement is
   partially consumed, with the remainder available to later steps.
7. The method of claim 2 wherein receipts are weighted by work class and by the
   independence class of the performing party relative to the operator.
8. The method of claim 3 wherein per-class floors are required in addition to the aggregate
   ratio, so the predicate cannot be satisfied entirely from one class of oversight work.
9. The method of claim 3 wherein the step's compute measure is drawn from a period
   accounting evidenced by attested device records rather than from a declared figure.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
