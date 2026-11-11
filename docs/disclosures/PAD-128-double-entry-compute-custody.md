# PAD-128: Double-Entry Compute Custody

**Identifier:** PAD-128  
**Title:** Method for Reconciling an Operator's Declared Compute Ledger Against an Independently Signed Provider-Side Allocation Ledger, Where Each Admitted Workload Is Countersigned by the Resource Provider Into an Append-Only Log, So Divergence Between the Two Records Is Machine-Detectable and Attributable  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Compute Accountability / Double-Entry Attestation / Supply Chain  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-125 (Census-Complete Compute Ceiling Attestation), PAD-088 (Auditable Access and Use Record), PAD-087 (Bounded Infrastructure Access Grant), PAD-002 (Chain of Custody), PAD-127 (Pre-Registered Development Step)  

---

## 1. Abstract

Every account of how much compute an operator used is written by the operator. This method
adds the second book. A workload is admitted only against a signed **compute mandate**
naming the operator, the period, and the envelope it may consume. The resource provider
that admits the workload countersigns an **allocation receipt** binding the mandate, the
workload identifier, the period, and the magnitude allocated, and appends it to an
append-only log. At the end of the period the operator publishes its declared ledger and
the provider publishes its allocation ledger, and a reconciliation over the two produces a
typed set of divergences: allocations with no matching declaration, declarations with no
matching allocation, and magnitude mismatches on matched pairs.

The mechanism is the discipline that made large-scale commerce auditable, applied to
compute. Neither book is trusted; the check is that two books kept by parties with
different interests agree. A divergence is not an accusation, it is a machine-detected
typed record naming both entries, which is precisely what a reconciliation regime needs in
order to function without an inspector.

Key innovations:

- **Provider countersignature as the second entry**, so the record of a workload exists in
  the custody of a party that did not run it.
- **Typed reconciliation output**, so divergences are classified and attributable rather
  than reported as an aggregate difference.
- **Attested non-participation**, so a provider can publish period aggregates for an
  operator that has not enrolled, without disclosing that operator's workloads.

---

## 2. Problem Statement

### 2.1 Single-entry accounting is self-certifying

An operator's compute figures are produced by the operator's own systems and signed by the
operator's own keys. There is no second, independently held record against which they can
be checked.

### 2.2 Provider records exist but are not attributable evidence

Providers already meter allocation for billing. Those records are internal commercial data
in a proprietary format, not signed evidence in a form a third party can verify or
reconcile against anything.

### 2.3 Aggregate differences are not actionable

Where two accounts of the same activity differ, an aggregate delta identifies that
something is wrong without identifying which entries disagree or in which direction, so it
cannot drive a response.

### 2.4 Non-participants are invisible

An accountability arrangement covering only enrolled operators produces no signal at all
about parties that decline to enrol, even where the resource providers serving them are
themselves willing participants.

---

## 3. Solution (The Invention)

**Compute mandate.** The operator issues, or receives from its principal, a signed mandate
naming the operator identifier, the period, the total envelope, and optionally a
per-workload ceiling and a per-provider sub-envelope. The mandate is the authority under
which any workload may be admitted.

**Admission and countersignature.** When a provider admits a workload, it verifies the
mandate, checks the running tally against the envelope, and issues an allocation receipt
binding: the mandate identifier, the workload identifier, the period, the allocated
magnitude or a commitment to it, the admitting provider identifier, and the admission
time. The receipt is signed by the provider and appended to an append-only log.

**Operator declaration.** At period close the operator publishes a declared ledger: for
each workload it ran, the workload identifier, the period, and the magnitude or a
commitment to it, signed by the operator.

**Reconciliation.** A reconciliation function takes the two ledgers and produces typed
divergence records:

- *unbacked declaration*: a workload the operator declares that no provider receipt covers.
- *undeclared allocation*: a provider receipt for a workload the operator does not declare.
- *magnitude mismatch*: a matched workload whose two magnitudes differ beyond a declared
  tolerance.
- *envelope breach*: a matched or unmatched set whose total exceeds the mandate envelope.

Each divergence names both entries, both signing identifiers, and the period, so it is
attributable on its face.

**Privacy-preserving variant.** Magnitudes may be carried as commitments with the
reconciliation performed on equality of commitments and on committed sums, so the two
parties can demonstrate agreement without either publishing magnitudes to the other or to
observers.

**Composition with census accounting.** The provider ledger is an external check on the
device census of PAD-125: an allocation receipt naming a workload that appears in no
period record indicates the census did not cover the work, and the two mechanisms
cross-validate rather than duplicate.

**Attested non-participation.** A provider may publish a period aggregate attestation for
a counterparty that has not enrolled, naming the counterparty identifier and the total
allocated, without workload-level detail. The arrangement therefore produces a signal about
non-participants proportional to the participation of the providers, not of the
counterparties.

---

## 4. Prior Art Differentiation

Metering, billing records, cloud audit logs, double-entry bookkeeping, and signed receipts
are prior art. This disclosure does not claim them. What is differentiated is:

- **Requiring a provider countersignature bound to a compute mandate as a condition of
  admitting the workload**, so the second entry is created at admission time by the party
  granting the resource.
- **A typed, attributable reconciliation** between an operator-signed declared ledger and a
  provider-signed allocation ledger, with each divergence naming both entries and both
  signers.
- **Commitment-based reconciliation** allowing agreement to be demonstrated without either
  party disclosing magnitudes.
- **Attested non-participation aggregates**, producing accountability signal for
  counterparties that have not themselves enrolled.

Cloud audit logging records what a tenant did in a format the provider controls and the
tenant consumes. It is not a signed entry designed to be reconciled against an
independently signed tenant record by a third party.

---

## 5. Technical Implementation

A reference implementation defines the compute mandate credential, the provider allocation
receipt, admission checking against a running tally, the operator declared ledger, the
reconciliation function and its typed divergence records, commitment-based magnitude
comparison, and the non-participation aggregate attestation, all over `eddsa-jcs-2022`
Data Integrity proofs with receipts published as append-only log entries.

---

## 6. Claims Summary

1. A method in which a workload is admitted to a compute resource only against a signed
   mandate, and the admitting provider issues a countersigned allocation receipt binding
   the mandate, the workload identifier, the period, and the allocated magnitude.
2. The method of claim 1 wherein allocation receipts are appended to an append-only log so
   the provider-side record is ordered and non-repudiable.
3. The method of claim 1 wherein an operator-signed declared ledger and a provider-signed
   allocation ledger for the same period are reconciled to produce typed divergence
   records.
4. The method of claim 3 wherein the divergence types comprise a declaration with no
   backing receipt, a receipt with no matching declaration, a magnitude mismatch on a
   matched pair beyond a declared tolerance, and a total exceeding the mandate envelope.
5. The method of claim 3 wherein each divergence record names both source entries and both
   signing identifiers, so it is attributable without further investigation.
6. The method of claim 3 wherein magnitudes are carried as commitments and reconciliation
   is performed over commitment equality and committed sums, so agreement is demonstrable
   without disclosure of magnitudes.
7. The method of claim 1 wherein the provider verifies the running tally against the
   mandate envelope before admission, so the envelope is enforced at the point of resource
   grant.
8. The method of claim 2 wherein a provider publishes a period aggregate attestation for a
   counterparty that has not enrolled, naming the counterparty and the total allocated
   without workload-level detail.
9. The method of claim 3 wherein the reconciliation is cross-checked against a device
   census period record so that work absent from the census is detectable from the provider
   side.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
