# PAD-127: Pre-Registered Development Step

**Identifier:** PAD-127  
**Title:** Method for Pre-Registering a High-Consequence Development Step by Committing, Before It Begins, to a Digest Fixing Both Its Configuration and Its Evaluation Plan, Subject to a Mandatory Challenge Window and Externally Named Objection Authorities, So the Step Is Schedulable Only Against a Post-Window Execution Credential  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Pre-Registration / Deliberated Execution / Evaluation Integrity  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-085 (Two-Phase Deliberated Execution), PAD-071 (Commit Before Outcome), PAD-131 (Immutable Red Line Commitment), PAD-126 (Recursion Ceiling), PAD-130 (Capability-Proportional Sequential Delay)  

---

## 1. Abstract

A high-consequence development step, such as a large training run, is currently announced
after the fact if at all, and the evaluations used to characterize it are selected after
its results are known. This method requires the operator to commit, before the step
begins, to a single digest that fixes two things at once: the step's configuration and the
evaluation plan by which the step will be judged. The commitment is published, a mandatory
challenge window elapses, externally named objection authorities may register a binding
objection during that window, and only then does an execution credential become issuable.
The compute scheduler, rather than the operator's own policy process, is the enforcement
point: it will not admit the workload without a valid post-window execution credential
whose configuration digest matches the workload it is being asked to run.

Two properties follow. The step's configuration is fixed before it runs, so a
characterization of the step after the fact must reconcile against a record made before
anyone knew the outcome. And the evaluation plan is fixed before results exist, so the
measurements that characterize a step are the measurements that were planned for it, in
the same discipline that pre-registration brought to experimental trials, enforced here by
a digest rather than by convention.

Key innovations:

- **Joint commitment of configuration and evaluation plan**, so neither the description of
  what was done nor the yardstick applied to it can be selected after the outcome.
- **Externally named objection authorities**, so the parties who may object are
  counterparties and oversight bodies outside the operator's own control rather than
  internal reviewers.
- **Scheduler-side enforcement**, so the check occurs at the point where the resource is
  actually granted rather than at the point where the intention is declared.

---

## 2. Problem Statement

### 2.1 Outcomes are described by the party that produced them

The account of what a development step was intended to do is written after its results are
known. There is no record made before the step that a later account can be checked
against.

### 2.2 Evaluation selection after the fact is unfalsifiable

When the evaluations reported for a step are chosen once the step is complete, a favourable
subset can be reported without any misstatement, and no observer can tell which
measurements were considered and set aside.

### 2.3 Objection has no window and no standing

Where an external party would object to a step, it learns of the step after the step is
complete, and it has no defined interval during which an objection has any effect and no
defined form in which the objection is recognized.

### 2.4 Declarations are decoupled from resource grants

A commitment expressed in a policy document has no coupling to the system that actually
admits the workload. The declaration and the allocation are enforced by different
mechanisms with no cryptographic link between them.

---

## 3. Solution (The Invention)

**Registration credential.** Before the step begins, the operator issues a registration
credential whose subject fixes: a canonical configuration object (scale envelope,
objective, data root commitment, architecture family, intended deployment class), a
canonical **evaluation plan** object (the evaluations that will be run, their thresholds,
and the order in which they will be reported), the digest of each, the challenge window
duration and opening time, and the list of objection authority identifiers.

**Publication and ordering.** The registration credential is appended to an append-only
log. Its log index, not its self-asserted timestamp, establishes that the registration
preceded the step, so the ordering rests on the log's signed tree heads rather than on the
operator's clock.

**Challenge window.** During the declared window, any named objection authority may issue
an objection credential binding the registration digest, the objecting identifier, and a
reason code. An objection present in the log at window close blocks issuance.

**Execution credential.** After the window closes with no blocking objection, the operator
issues an execution credential naming the registration credential, repeating the
configuration digest, and carrying an inclusion proof of the registration in the log at an
index preceding the window's opening.

**Scheduler gate.** The system granting the compute resource recomputes the configuration
digest from the workload it is being asked to admit, checks it against the execution
credential, verifies the window elapsed and no objection blocks, and admits the workload
only on success. The workload identifier admitted by the scheduler is recorded so it can
be reconciled against independent allocation records.

**Result binding.** Results published for the step reference the pre-registered evaluation
plan digest. A result set that includes evaluations absent from the plan, or omits
evaluations present in it, is detectable by comparison against the committed plan without
any need to trust the publisher's account.

**Amendment.** An evaluation plan may be amended only by publishing a superseding
registration that references the prior one, restarting the window. The chain of
registrations for a step is therefore complete and ordered, and a plan changed after
partial results is visible as a dated amendment rather than as the original plan.

---

## 4. Prior Art Differentiation

Two-phase commit, change advisory processes, trial pre-registration in the biomedical
literature, and deliberated execution with a veto window are prior art. This disclosure
does not claim them. What is differentiated is:

- **Fixing the evaluation plan in the same commitment as the configuration**, so the
  yardstick and the object being measured are bound together before either is known to
  produce a favourable result.
- **Establishing the before-and-after ordering by append-only log index** rather than by a
  self-asserted timestamp, so the operator's clock is not part of the trust base.
- **Placing the enforcement at the resource scheduler** with a recomputed configuration
  digest, so admission of the workload is conditioned on the commitment.
- **Naming objection authorities external to the operator** and giving their objection a
  defined credential form with binding effect inside a defined window.

Pre-registration in clinical research is a publication convention enforced by registries
and journals. It has no cryptographic binding to the experiment that runs, no
counterparty veto, and no coupling to the allocation of the resources the experiment
consumes.

---

## 5. Technical Implementation

A reference implementation defines the registration credential and its configuration and
evaluation plan digests, log publication with inclusion proof, the objection credential,
window evaluation, the execution credential, the scheduler gate that recomputes the
configuration digest, result binding against the committed plan, and the superseding
amendment chain, all over `eddsa-jcs-2022` Data Integrity proofs and JCS canonical
digests.

---

## 6. Claims Summary

1. A method in which a development step is registered before it begins by a signed
   credential committing, in one digest set, both the step's canonical configuration and
   the evaluation plan by which the step will be characterized.
2. The method of claim 1 wherein the registration is appended to an append-only log and the
   ordering of registration relative to the step is established by log index and signed
   tree head rather than by an asserted timestamp.
3. The method of claim 1 wherein a mandatory challenge window follows registration, during
   which identifiers named in the registration and external to the operator may issue a
   binding objection credential.
4. The method of claim 3 wherein an execution credential becomes issuable only after the
   window closes with no blocking objection, and carries an inclusion proof of the
   registration at an index preceding the window opening.
5. The method of claim 4 wherein the system granting the compute resource recomputes the
   configuration digest from the submitted workload and admits it only if the digest
   matches the execution credential.
6. The method of claim 1 wherein published results reference the committed evaluation plan
   digest, so an added or omitted evaluation is detectable by comparison against the plan.
7. The method of claim 1 wherein amendment of the configuration or evaluation plan requires
   a superseding registration referencing the prior one and restarts the challenge window,
   producing a complete ordered amendment chain.
8. The method of claim 5 wherein the workload identifier admitted by the scheduler is
   recorded for reconciliation against an independently signed allocation record.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
