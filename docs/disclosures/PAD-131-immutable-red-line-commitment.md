# PAD-131: Immutable Red Line Commitment

**Identifier:** PAD-131  
**Title:** Method for Committing an Operator's Safety Thresholds and Halt Conditions as Dated Tamper-Evident Entries in an Append-Only Log Prior to Measurement, So a Later Comparison Against Independently Signed Evaluation Results Uses Thresholds Whose Priority in Time Is Established by Log Index Rather Than by Assertion  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Policy Integrity / Commitment Schemes / Evaluation Integrity  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-127 (Pre-Registered Development Step), PAD-071 (Commit Before Outcome), PAD-132 (Oversight Ratio Bound), PAD-079 (Machine-Checkable Regulatory Conformance), PAD-135 (Simultaneous-Reveal Comparative Disclosure)  

---

## 1. Abstract

An operator's published safety thresholds are a document on a website. A document on a
website can be edited, and the edit is visible only to whoever happened to keep a copy of
the previous version. This method makes the thresholds an object whose history cannot be
rewritten. The threshold policy is canonicalized and committed as a digest appended to an
append-only log before any measurement against it occurs, so the commitment's position in
the log establishes that the threshold predates the result. Amendment is possible and
expected; what is foreclosed is silent amendment, because a superseding version is a new
entry referencing the prior one, and the log's consistency proofs show that the version
chain is complete and correctly ordered.

Selective reveal keeps the mechanism usable where the thresholds themselves are sensitive.
Each threshold is committed individually under its own blinding value, so an operator can
open exactly the threshold relevant to a given result while the others remain closed, and
can later open the remainder to show the set was complete at commitment time.

Key innovations:

- **Ordering by log index instead of by asserted timestamp**, so the claim that a threshold
  predates a result does not rest on the operator's clock or its word.
- **Per-threshold blinded commitment with selective reveal**, so a sensitive threshold set
  can be committed in full and opened in part.
- **Amendment as an explicit, ordered, consistency-proved chain**, so revision is
  permitted and silent revision is not.

---

## 2. Problem Statement

### 2.1 Published thresholds are mutable

A safety framework published as a document can be revised at any time. A party consulting
it sees only its current state, with no way to establish what it said before a particular
result was obtained.

### 2.2 A threshold revised after a result is indistinguishable from one set before it

Where the comparison of a result against a threshold is the operative decision, the value
of the comparison depends entirely on the threshold having been fixed first, and nothing in
current practice establishes that.

### 2.3 Self-asserted timestamps do not establish priority

A date printed in a document, or a modification time in a repository, is under the control
of the party asserting it. Priority in time must come from a structure that party does not
control.

### 2.4 Full publication of thresholds is not always available

Some thresholds encode sensitive detail about what an operator can measure and what it
regards as significant. A mechanism that requires publishing all of them in the clear will
not be adopted for the thresholds that matter most.

---

## 3. Solution (The Invention)

**Canonical policy object.** The threshold policy is expressed as a structured object: a
set of named thresholds, each with a measurement reference, a comparison operator, a
threshold value, and a declared consequence such as halt, narrow deployment, or escalate to
a named authority.

**Per-threshold commitment.** Each threshold is committed individually as the digest of its
canonical form concatenated with a per-threshold blinding value. The set of per-threshold
commitments is accumulated into a Merkle tree, and the tree root together with the count of
thresholds is the **policy commitment**.

**Log publication.** The policy commitment is appended to an append-only log that issues
signed tree heads. Its index in that log is the operative fact: a result recorded at a
higher index was obtained after the policy was fixed.

**Measurement.** Evaluation results are recorded as independently signed measurement
records and are themselves appended to the log, so the relative order of policy commitment
and measurement is a property of the log rather than of either party's account.

**Selective reveal.** To demonstrate a comparison, the operator opens the relevant
threshold by publishing its canonical form, its blinding value, and its inclusion proof
against the policy commitment. The verifier recomputes the leaf, checks inclusion, checks
that the policy commitment's log index precedes the measurement's index, and applies the
comparison. The unopened thresholds remain closed, and the published count establishes how
many exist.

**Amendment chain.** A superseding policy commitment names the prior commitment's digest
and its log index. A verifier walking the chain obtains the complete ordered history of the
policy and, by consistency proof between tree heads, confirms no entry between them was
removed or reordered. A threshold weakened after a measurement is therefore visible as a
dated amendment following that measurement, rather than as the original policy.

**Binding to dependent mechanisms.** Other governance predicates may reference a policy
commitment by digest, so a bound they enforce is the bound that was committed. This applies
to the human distance bound of a recursion ceiling, the ratio of an oversight bound, and
the parameters of a delay function, each of which is a value whose usefulness depends on
its having been fixed in advance.

---

## 4. Prior Art Differentiation

Commitment schemes, Merkle trees, certificate transparency logs, notarization, and version
control are prior art. This disclosure does not claim them. What is differentiated is:

- **Applying commit-before-measurement ordering to an operator's own safety thresholds**,
  making the priority of a threshold over a result a checkable property of a log index.
- **Per-threshold blinded commitment within a counted accumulator**, enabling selective
  opening of one threshold while establishing the cardinality of the committed set.
- **An amendment chain proved complete by log consistency**, so revision is permitted and
  the absence of intermediate versions is detectable.
- **Referencing the policy commitment from dependent governance predicates**, so the
  parameters those predicates enforce are provably the committed ones.

Version control records history for parties with repository access and is rewritable by
the party that holds it. Certificate transparency applies the log discipline to certificate
issuance. Neither applies it to the thresholds by which a party judges its own results, and
neither supports opening a single threshold from a committed set.

---

## 5. Technical Implementation

A reference implementation defines the canonical threshold policy object, per-threshold
blinded commitments, the counted accumulator and policy commitment, log publication and
index-based ordering, signed measurement records, selective reveal with inclusion proof and
ordering check, the superseding amendment chain with consistency verification, and digest
references from dependent predicates, all over `eddsa-jcs-2022` Data Integrity proofs and
JCS canonicalization.

---

## 6. Claims Summary

1. A method in which an operator's safety thresholds are committed as digests appended to
   an append-only log prior to measurement, so the priority of a threshold over a result is
   established by log index rather than by assertion.
2. The method of claim 1 wherein each threshold is committed individually under a
   per-threshold blinding value and the commitments are accumulated into a tree whose root
   and cardinality form the published policy commitment.
3. The method of claim 2 wherein a single threshold is selectively opened by publishing its
   canonical form, its blinding value, and its inclusion proof, leaving the remaining
   thresholds closed while their number remains established.
4. The method of claim 1 wherein evaluation results are appended to the same log as
   independently signed measurement records, so the ordering of policy and measurement is a
   property of the log.
5. The method of claim 1 wherein amendment is performed by a superseding commitment naming
   the prior commitment and its index, and the completeness of the version chain is
   established by consistency proof between signed tree heads.
6. The method of claim 5 wherein a threshold relaxed after a measurement is distinguishable
   from an original threshold by the relative log indices of the amendment and the
   measurement.
7. The method of claim 1 wherein a dependent governance predicate references the policy
   commitment by digest, so the parameter the predicate enforces is provably the committed
   parameter.
8. The method of claim 3 wherein an operator subsequently opens the remaining thresholds to
   demonstrate that the committed set was complete at the time of commitment.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
