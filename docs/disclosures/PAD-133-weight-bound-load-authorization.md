# PAD-133: Weight-Bound Load Authorization

**Identifier:** PAD-133  
**Title:** Method by Which a Set of Model Parameters Is Loadable Only Against a Current Multilaterally Signed Authorization Issued to an Identifier Deterministically Derived From the Parameter Digest, So Any Modification of the Parameters Invalidates Every Existing Authorization and Continued Operation Requires Continuing Consent  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Model Custody / Multilateral Authorization / Runtime Attestation  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-043 (Cryptographic Weight Binding), PAD-065 (Model and Config Provenance Attestation), PAD-129 (Graduated Multilateral Pace Control), PAD-018 (Model Lineage Provenance), PAD-032 (Cryptographic Mortality Protocol)  

---

## 1. Abstract

A set of trained parameters, once produced, is a file. Whatever governance attached to its
creation stops at the moment the file exists, and every subsequent decision to run it is
made unilaterally and silently by whoever holds it. This method extends governance past
that moment. An identifier is derived deterministically from the canonical digest of the
parameter tensors, so the parameters name themselves and no assertion is involved. A
**load authorization** is then issued to that derived identifier by a quorum of holders
drawn from distinct domains. A conforming runtime computes the digest of the parameters it
is about to load, derives the identifier, requires a current authorization for it, and
re-checks that authorization on an interval while the parameters remain resident,
attenuating the operating envelope as the authorization ages.

Two consequences follow from deriving the identifier from the parameters themselves.
Modifying any parameter yields a different identifier, so authorizations do not transfer to
a modified checkpoint and a modified checkpoint must be authorized on its own terms.
And because the authorization carries an anchor time and decays, continued operation is a
continuing multilateral consent rather than a single permission granted once and inherited
forever.

Key innovations:

- **Self-naming parameters**, where the identifier that must be authorized is computed from
  the tensors rather than asserted alongside them.
- **Consent that must be maintained**, since the authorization decays and is re-checked
  while the parameters are resident, so withdrawal takes effect without reaching the
  holder.
- **Non-transferability across modification**, so fine-tuning, merging, or patching
  produces an artifact that requires its own authorization.

---

## 2. Problem Statement

### 2.1 Governance ends at the artifact

Controls applied during development do not attach to the artifact those controls produced.
Once the parameters exist, the decision to load them is outside every mechanism that
governed their creation.

### 2.2 A permission granted once is inherited indefinitely

An approval to deploy is a point-in-time event. Nothing requires it to be renewed, and
nothing causes it to lapse if the circumstances that justified it change.

### 2.3 Identifiers asserted alongside an artifact do not bind to it

Where a model is named by a label in a manifest, the label and the tensors are separable.
An authorization issued against a label can be satisfied by different parameters carrying
the same label.

### 2.4 Withdrawal requires reaching the holder

Retracting a deployment approval requires notifying every party running the artifact.
Coverage is incomplete and the parties least likely to comply are the ones the retraction
most concerns.

---

## 3. Solution (The Invention)

**Derived identifier.** The parameter set is serialized in a declared canonical tensor
order and layout, digested, and the digest is expanded into a stable identifier by a
declared derivation. The identifier is a function of the parameters alone, so it is
recomputable by any party holding them and cannot be claimed for a different parameter set.

**Load authorization.** A quorum of holders from distinct domains signs a load
authorization naming the derived identifier, an anchor time, a decay rate, a deployment
class envelope (for example the interfaces, rate ceilings, and autonomy classes permitted),
and optionally a set of conditions by reference, such as a committed threshold policy or a
period accounting.

**Runtime check at load.** The runtime computes the digest of the parameters it is about to
load, derives the identifier, resolves a current authorization for it, verifies the quorum
proofs, computes the authorization's effective standing from the anchor time and the
prevailing decay rate, and loads only if the standing meets the threshold for the requested
deployment class.

**Continuing check while resident.** The runtime re-evaluates effective standing on a
declared interval. As standing falls, the operating envelope attenuates by deployment class
in order of consequence, so an authorization allowed to lapse narrows the artifact's
permitted use progressively rather than terminating it abruptly. Attenuation follows the
non-expansion discipline, so a derived envelope is never broader than the authorized one on
any dimension.

**Interaction with pace control.** The prevailing decay rate may be supplied by a
multilaterally signed pace epoch, so a graduated global adjustment applies to resident
parameter sets without any authorization being revoked and without any runtime being
contacted directly.

**Modification.** A fine-tune, merge, quantization, or patch produces different parameters
and therefore a different derived identifier. The derived artifact carries a lineage
reference to its parent identifier, so the relationship is recorded, and it requires its own
authorization, so the relationship does not confer permission.

**Attested runtime.** The runtime performing these checks may itself attest its
configuration, so a relying party can distinguish a checked load from an unchecked one, and
authorizations may be conditioned on the class of runtime performing the load.

---

## 4. Prior Art Differentiation

Code signing, secure boot, license enforcement, model watermarking, hardware attestation,
and deriving keys from content digests are prior art. This disclosure does not claim them.
What is differentiated is:

- **Issuing an authorization to an identifier derived from the parameter tensors
  themselves**, so the authorized subject is the artifact rather than a label attached to
  it.
- **Multilateral quorum issuance of the load authorization across distinct domains**, so
  no single party may grant or withhold permission to run.
- **A decaying authorization re-evaluated while the artifact is resident**, so continued
  operation expresses continuing consent and lapse narrows the envelope without any
  notification reaching the holder.
- **Graduated attenuation by deployment class under the non-expansion discipline**, so
  reduced standing yields a strictly narrower envelope rather than a binary outcome.
- **Coupling the decay rate to a multilaterally signed pace parameter**, so a general
  adjustment reaches resident artifacts.

Secure boot authorizes a measured image against a vendor key at start, once. License
enforcement conditions use on a commercial entitlement held by one issuer. Neither issues a
decaying, multilaterally held authorization to an identifier derived from the artifact, and
neither re-evaluates while the artifact is running.

---

## 5. Technical Implementation

A reference implementation defines the canonical tensor serialization and digest, the
identifier derivation, the quorum-signed load authorization and its envelope, the load-time
check, the resident re-check interval and class-ordered attenuation under the non-expansion
rule, coupling of the decay rate to a signed pace epoch, the lineage reference for derived
parameter sets, and the runtime configuration attestation, all over `eddsa-jcs-2022` Data
Integrity proofs and JCS canonicalization.

---

## 6. Claims Summary

1. A method in which an identifier is derived deterministically from the canonical digest of
   a set of model parameters, and a load authorization is issued to that derived identifier
   by a quorum of holders from distinct domains.
2. The method of claim 1 wherein a runtime computes the digest of the parameters it is
   about to load, derives the identifier, and loads only against a current authorization for
   that identifier.
3. The method of claim 1 wherein the authorization carries an anchor time and a decay rate,
   and its effective standing is re-evaluated on an interval while the parameters remain
   resident.
4. The method of claim 3 wherein falling standing attenuates the permitted deployment
   envelope in order of consequence class, with each derived envelope no broader than the
   authorized envelope on any dimension.
5. The method of claim 1 wherein modification of any parameter yields a different derived
   identifier, so an existing authorization does not extend to the modified parameter set.
6. The method of claim 5 wherein a derived parameter set carries a lineage reference to its
   parent identifier while requiring an authorization of its own.
7. The method of claim 3 wherein the prevailing decay rate is supplied by a multilaterally
   signed pace record, so a general adjustment reaches resident parameter sets without
   contacting the runtime.
8. The method of claim 2 wherein the runtime attests its own configuration so a relying
   party can distinguish a checked load, and an authorization is conditioned on the class of
   runtime performing the load.
9. The method of claim 1 wherein the authorization references conditions by digest, such as
   a committed threshold policy or a period accounting, so the conditions in force are the
   committed ones.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
