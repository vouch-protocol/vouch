# PAD-125: Census-Complete Compute Ceiling Attestation

**Identifier:** PAD-125  
**Title:** Method by Which an Operator Proves That No Workload in a Period Exceeded a Declared Compute Ceiling, Evaluated Over a Census of Enrolled Accelerators Whose Completeness Is Itself Attested, Without Disclosing Individual Workload Sizes or Counts  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Compute Accountability / Verifiable Computation / Hardware-Rooted Attestation  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Identity), PAD-090 (Fused Input Provenance Completeness), PAD-018 (Model Lineage Provenance), PAD-022 (Swarm Limits), PAD-030 (Zero-Knowledge Reputation Portability), PAD-128 (Double-Entry Compute Custody)  

---

## 1. Abstract

An operator that has committed to a compute ceiling currently has no artifact with which
to demonstrate that it held to it. This method produces one. Each accelerator in an
operator's fleet is enrolled with a hardware-rooted device credential, and the enrolled
set is committed as a census with published cardinality. In each period every enrolled
device emits a signed work-unit record, the records accumulate into a period tree, and
the operator publishes a bounded predicate attestation asserting that the largest
single workload stayed at or below a declared ceiling and that the period total stayed at
or below a declared quota. The verifier learns the truth of those two statements and
nothing else.

The property that makes the attestation meaningful is completeness rather than integrity.
A signed report over the workloads an operator chose to include says nothing about the
ones it omitted. Here, every enrolled device must contribute exactly one record per
period, and a device that contributes none invalidates the period unless its absence is
explained by a signed, dated decommission or maintenance record chained to the census.
Absence becomes a positive event with an author and a timestamp instead of a silence.

Key innovations:

- **Census-bound accounting.** The unit of accounting is the enrolled device population,
  not the disclosed workload list, so omitting a workload requires omitting a device and
  omitting a device is itself detectable.
- **Bounded predicate disclosure.** The published artifact is a proof of a ceiling
  predicate over committed values, so restraint is demonstrable without disclosing
  capability-revealing magnitudes.
- **Absence as a signed event.** Device silence is resolved by a chained decommission
  record or it breaks the period attestation, so a device cannot be quietly parked
  outside the census and later returned.

---

## 2. Problem Statement

### 2.1 A commitment to pace has no verifiable artifact

An operator that publicly commits to limiting the scale of its workloads can only assert
compliance. A counterparty, a peer operator, or an oversight body has nothing to check.
Assertion does not compose into a multilateral arrangement, because each party's restraint
is conditional on believing the others.

### 2.2 Disclosure of magnitudes is itself disclosure of position

An operator asked to publish workload sizes publishes its competitive position and its
capability trajectory in the same act. Any scheme that requires magnitudes in the clear
will be declined by the parties whose participation matters most.

### 2.3 Integrity of a report says nothing about its completeness

Signing a report proves the reported numbers were not altered. It does not prove the
report covers everything. Existing attestation formats secure the contents of a
disclosure and leave the boundary of the disclosure entirely to the discretion of the
party making it.

### 2.4 Device-level telemetry is not attributable

Cluster telemetry today is operator-controlled software state. A record that a
counterparty is expected to rely on must be signed by a key the operator cannot mint at
will, which means the signing key must be rooted in the accelerator hardware itself.

---

## 3. Solution (The Invention)

**Enrollment and census.** Each accelerator holds a device identity key rooted in its
hardware attestation facility. The operator issues a device enrollment credential binding
that device key to a device identifier and to the operator's own identity. The set of
enrollment credential digests is accumulated into a Merkle tree; its root and cardinality
form the published **census commitment** for the period.

**Per-period records.** In each period, every enrolled device emits a signed work-unit
record naming the census commitment, the period identifier, a commitment to the workload
identifier the work was attributed to, and the work-unit magnitude committed under a
blinding value. Records are leaves of the **period accumulation tree**.

**Ceiling predicate attestation.** Over the period tree, the operator produces an
attestation asserting two predicates: that the maximum magnitude aggregated under any
single workload commitment is at or below the declared ceiling, and that the sum over all
records is at or below the declared quota. The attestation is realizable as a
zero-knowledge range proof over the committed magnitudes. It is also realizable, where
proving systems are unavailable, as a challenge-sampled opening in which the verifier's
sampling indices are derived deterministically from the published log root so the operator
cannot choose which records are examined.

**Completeness rule.** The period attestation is valid only if the count of contributing
device records equals the census cardinality. A device that does not contribute must be
covered by a signed decommission or maintenance record that names the device, the census
commitment, and the period, and is itself accumulated into the period tree. The census
cardinality for the next period is derived from the prior census and the set of signed
enrollment and decommission records, so the population is a chained quantity rather than a
freshly asserted one.

**Continuity chaining.** Each device's successive records carry a commit and reveal chain,
so a device that is absent for a period and returns cannot present a record that appears
continuous. A broken chain marks the device as discontinuous for the intervening periods
and excludes it from contributing to a valid ceiling attestation until re-enrolled.

**Publication.** Census commitments, period roots, and predicate attestations are appended
to an append-only log that issues signed tree heads, so the sequence of periods is
totally ordered and a later revision of an earlier period is detectable by consistency
proof.

---

## 4. Prior Art Differentiation

Trusted execution environments, device attestation quotes, Merkle accumulation,
zero-knowledge range proofs, and append-only transparency logs are all prior art. This
disclosure does not claim any of them. What is differentiated is:

- **Binding a compute-ceiling predicate to an attested device census**, so the boundary of
  the accounting is fixed by the enrolled population rather than by the disclosing party's
  selection.
- **Treating device absence as a signed, dated, chained event** that must be present for
  the period attestation to verify, which converts a completeness question into an
  integrity question over a population record.
- **Publishing a bounded predicate rather than magnitudes**, so a party can demonstrate
  restraint without disclosing scale, and a multilateral arrangement becomes possible
  between parties that will not disclose to each other.
- **Deriving challenge-sampling indices from the published log root**, so the sampled
  fallback retains verifier-chosen selection without an interactive verifier.

Confidential computing attestation proves what code ran on one device. Compute
transparency proposals publish declared totals. Neither establishes that the set of
devices reported on is the complete set the operator controls, and neither yields a
ceiling predicate that a rival will accept without magnitude disclosure.

---

## 5. Technical Implementation

A reference implementation defines the device enrollment credential, the census
commitment, the per-period work-unit record, the period accumulation tree, the ceiling
and quota predicate evaluation, the completeness rule over census cardinality, the
decommission record, and the device continuity chain, all secured with the
`eddsa-jcs-2022` Data Integrity proof and JCS canonicalization already used across Vouch
Protocol, with period roots published as signed tree heads.

---

## 6. Claims Summary

1. A method in which an operator's compute accounting for a period is evaluated over a
   committed census of hardware-rooted enrolled devices, with published cardinality, such
   that the completeness of the accounting is a checkable property.
2. The method of claim 1 wherein each enrolled device emits a signed per-period record
   whose magnitude is committed under a blinding value, and the records accumulate into a
   period tree.
3. The method of claim 2 wherein the operator publishes an attestation of a ceiling
   predicate and a quota predicate over the committed magnitudes, disclosing the truth of
   the predicates without disclosing the magnitudes, the workload count, or their
   distribution.
4. The method of claim 1 wherein a device that contributes no record for a period must be
   covered by a signed decommission or maintenance record accumulated into the same period
   tree, failing which the period attestation does not verify.
5. The method of claim 1 wherein the census cardinality for a period is derived by chaining
   the prior census with signed enrollment and decommission records, so the device
   population is an accumulated quantity rather than a per-period assertion.
6. The method of claim 2 wherein successive records from a device form a commitment and
   reveal chain, so an interruption in a device's participation is detectable after the
   fact.
7. The method of claim 3 wherein, in place of a zero-knowledge proof, the verifier's
   sampling indices are derived deterministically from the published log root so the
   operator cannot influence which records are opened.
8. The method of claim 1 wherein census commitments, period roots, and predicate
   attestations are appended to an append-only log issuing signed tree heads, so revision
   of a previously published period is detectable by consistency proof.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
