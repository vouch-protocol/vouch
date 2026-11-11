# PAD-126: Recursion Ceiling by Human-Distance Bound

**Identifier:** PAD-126  
**Title:** Method for Bounding Recursive Self-Improvement by Computing, Over a Graph of Signed Authorship and Authorization Credentials, the Number of Hops Between Each Artifact Entering a Development Pipeline and the Nearest Human-Held Signing Key, and Refusing the Pipeline Step Above a Declared Bound  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Recursive Self-Improvement / Authorship Provenance / Delegation Analysis  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-061 (Per-Region Human and AI Code Attribution), PAD-018 (Model Lineage Provenance), PAD-021 (Inverse Capability Protocol), PAD-086 (Executable Caveats), PAD-127 (Pre-Registered Development Step)  

---

## 1. Abstract

"Keep a human in the loop" is stated as an intention and enforced as a habit. This method
turns it into a computable invariant with a single tunable parameter. Every artifact that
enters a development pipeline, including source changes, dataset shards, evaluation
definitions, reward specifications, architecture edits, and configuration selections,
carries a signed authorship credential naming its author identifier and an attested
custody class distinguishing a key held by a human under a presence attestation from a key
held by an autonomous process.

A verifier then computes, for each artifact, its **human distance**: the minimum number of
authorization hops from that artifact to a human-held key that signed over the artifact's
exact digest. A machine-produced artifact reviewed and signed by a human over its digest
has distance one. A machine-produced artifact authorized by a machine that was itself
authorized by a human has distance two. Derivation is non-decreasing, so an artifact
derived from another inherits at least its parent's distance plus one. The pipeline step
is authorized only if the maximum human distance across its inputs is at or below a
declared bound.

The bound is the pacing control. Lowering it forces additional human authorization edges
into the development loop, and because each such edge is a real signature over a real
digest by a key under human custody, lowering the bound lengthens the loop by
construction rather than by policy.

Key innovations:

- **Human distance as a graph metric over signed credentials**, computable by any party
  holding the credential set, with a witness that a verifier can independently recompute.
- **Non-decreasing derivation**, so autonomy accumulates across generations and cannot be
  reset by re-packaging an artifact.
- **Model lineage edges counted in the same metric**, so a system contributing to the
  training of its successor increases the successor's distance unless humans re-anchor.

---

## 2. Problem Statement

### 2.1 Autonomous contribution to development is unmeasured

Systems now contribute to the construction of their successors. The degree of that
contribution is described qualitatively and inconsistently, and there is no quantity that
two parties can compute from the same evidence and agree on.

### 2.2 Human oversight is asserted rather than demonstrated

A statement that a change was reviewed carries no binding to the reviewed bytes, no
identification of the reviewing key, and no distinction between a review performed by a
person and a review performed by a process acting under a person's account.

### 2.3 Re-packaging erases provenance

An artifact produced autonomously and then copied, reformatted, or re-committed loses its
authorship history. Any measure that does not accumulate across derivation can be reset by
a mechanical transformation.

### 2.4 Existing controls act on individual actions, not on the loop

Per-action authorization limits what one step may do. It does not constrain the length of
the chain of steps that occur between one human decision and the next, which is the
quantity that determines how fast a self-improving process can advance.

---

## 3. Solution (The Invention)

**Authorship credentials.** Each artifact entering the pipeline is accompanied by a signed
credential binding the artifact's canonical digest to an author identifier, an authorship
class, and, where the author is autonomous, a reference to the authorization under which
it acted. Human custody is asserted by an attested custody class evidencing that the
signing key is held in an authenticator requiring human presence, so the human and machine
classes are distinguishable by evidence rather than by declaration.

**Authorization edges.** An authorization credential names a subject key, an authorized
scope, and, when it is a review, the exact digest reviewed. Edges are directed from
artifact to authorizing credential and from authorizing credential to the key that signed
it.

**Distance computation.** For artifact `a`, `humanDistance(a)` is the minimum, over all
paths from `a` through authorization edges, of the number of hops to a credential signed by
a key of the human custody class. An artifact with no such path has unbounded distance.

**Derivation rule.** If artifact `b` is derived from artifact `a`, then
`humanDistance(b) >= humanDistance(a) + 1` unless `b` carries its own human review edge
over `b`'s digest, in which case `b`'s distance is one. This is the non-expansion
discipline already applied to delegation scope, applied here to autonomy depth.

**Lineage edges.** Where a model contributed to producing an artifact, an edge runs from
that artifact to the contributing model's lineage credential, and from there to whatever
authorized that model's own production. Generation-over-generation contribution therefore
accumulates distance.

**Pipeline predicate.** A development or training step publishes a step credential carrying
the computed maximum human distance across its inputs and a witness set sufficient for
recomputation. A verifier, including the scheduler that would run the step, recomputes the
metric from the witness and refuses the step when the maximum exceeds the declared bound
`k`.

**Tuning.** `k` is published as part of the operator's declared policy and may itself be
committed in advance so that it cannot be raised after a step fails the check. Distinct
bounds may apply to distinct artifact classes, with the tightest bound applying to
artifacts that affect training objectives, evaluation definitions, or safety
configuration.

---

## 4. Prior Art Differentiation

Code provenance, commit signing, supply-chain attestation frameworks, delegation chains,
and authorship watermarking are prior art. This disclosure does not claim them. What is
differentiated is:

- **Defining a scalar autonomy-depth metric over a signed authorship and authorization
  graph** and making a pipeline step's authorization a predicate on that scalar.
- **A non-decreasing derivation rule for the metric**, so autonomy depth accumulates
  through transformation and across model generations rather than resetting.
- **Distinguishing human-held from machine-held signing keys by attested custody class**,
  so the terminus of the metric is evidenced rather than asserted.
- **Using the bound as an explicit pacing control**, where the parameter governs how many
  autonomous steps may occur between human authorizations.

Supply-chain attestation establishes what produced an artifact and whether it was
tampered with. It does not measure how far the artifact stands from a human decision, and
it does not accumulate that measure across derivation.

---

## 5. Technical Implementation

A reference implementation defines the authorship credential, the attested custody class,
the authorization edge, the graph construction from a credential set, the minimum-hop
distance computation with cycle handling, the non-decreasing derivation rule, the lineage
edge, the step predicate with its recomputable witness, and the verifier that refuses a
step exceeding the bound, all over `eddsa-jcs-2022` Data Integrity proofs and JCS
canonical digests.

---

## 6. Claims Summary

1. A method in which each artifact entering a development pipeline carries a signed
   authorship credential and a scalar human distance is computed as the minimum number of
   authorization hops from the artifact to a credential signed by a key of an attested
   human custody class.
2. The method of claim 1 wherein authorization of a pipeline step is conditioned on the
   maximum human distance across the step's inputs being at or below a declared bound.
3. The method of claim 1 wherein an artifact derived from another artifact inherits a
   human distance of at least the parent's distance plus one, unless a human review edge
   is signed over the derived artifact's own digest.
4. The method of claim 1 wherein contribution by a model to the production of an artifact
   introduces a lineage edge, so autonomy depth accumulates across successive model
   generations.
5. The method of claim 1 wherein a human review edge binds the reviewing key to the exact
   canonical digest of the reviewed artifact, so a review cannot be transferred to
   different content.
6. The method of claim 2 wherein the declared bound is committed in advance in a
   tamper-evident record so it cannot be relaxed after a step fails the predicate.
7. The method of claim 2 wherein distinct bounds apply to distinct artifact classes, with
   tighter bounds on artifacts governing training objectives, evaluation definitions, or
   safety configuration.
8. The method of claim 2 wherein the step credential carries a witness set sufficient for
   an independent party to recompute the metric without access to the artifacts
   themselves.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
