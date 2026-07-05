# PAD-093: Privacy-Preserving Bystander-Consent Evidence for Robot Capture

**Identifier:** PAD-093  
**Title:** Method for a Robot to Sign Privacy-Preserving Evidence Binding the Basis for a Capture to the Capture Itself, Holding Only Hashes and No Identifying Data  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Privacy / Consent  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-068 (Perception Provenance), PAD-094 (Capture-Bound Bystander Consent Token)  

---

## 1. Abstract

A method for a robot to record, in a signed and privacy-preserving form, the basis
on which it captured people in a shared or public space. A bystander-consent evidence
credential binds a capture, named only by its hash, to a consent basis (an explicit
consent token, posted notice, a legitimate interest, or a redaction that was applied)
and to the robot's identity, signed by the robot. Only hashes and the basis are
stored, never an image or a bystander's identifying data, so the record is verifiable
after the fact without retaining anyone's biometrics.

Key innovations:

- **Consent basis bound to the capture by its hash.** The evidence ties the basis for
  a capture to the specific capture through its hash, so the justification a robot
  acted on is inseparable from the recording it justifies.
- **Privacy-preserving by construction.** The credential carries only hashes, the
  basis, and, for explicit consent, references to consent tokens by their proof value,
  so no image and no identifying data is retained in the evidence.
- **An interoperable set of consent bases.** The basis is drawn from a named set a
  verifier can rely on, so a capture recorded under posted notice, legitimate
  interest, explicit consent, or a redaction is distinguishable and checkable.

---

## 2. Problem Statement

### 2.1 A robot that records people has no verifiable, privacy-preserving basis

A robot with cameras and microphones captures bystanders incidentally. There is no
signed way for it to show the basis it acted on, and any record that stored the
capture or the bystander's identity to prove consent would itself defeat the privacy
it is meant to protect.

### 2.2 A basis asserted separately from the capture is not bound to it

If the basis for a capture is recorded apart from the capture, there is nothing
tying the two together, so a basis cannot be shown to belong to a specific recording.

---

## 3. Solution (The Invention)

`build_consent_evidence(...)` issues a `BystanderConsentEvidence` credential whose
subject carries the robot identifier, the capture hash, the consent basis, and, when
the basis is explicit consent, references to the covering consent tokens by their proof
value, signed eddsa-jcs-2022 by the robot. The basis must be drawn from an accepted set,
and an explicit-consent evidence must reference at least one token. `hash_capture(...)`
produces the capture hash. `verify_consent_evidence(...)` checks the robot's proof, that
the issuer is the robot, and that the basis is accepted, and, when the raw capture is
supplied, that its hash reproduces the attested capture hash, and, when the tokens and
bystander keys are supplied, that each token verifies, is bound to this capture, and
matches a committed reference. Only hashes and the basis are ever stored. Because the
credentials use the shared JCS plus eddsa-jcs-2022 primitives, the same evidence
verifies across the language SDKs. This is the open layer of the cryptographic binding
of a consent basis to a capture; on-device biometric detection and redaction, and
managed consent-registry orchestration, are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, consent receipts, and content hashing each exist as prior art.
This disclosure does **not** claim those mechanisms in the abstract. What is
differentiated is the reduction to privacy-preserving bystander-consent evidence for a
robot capture:

- **Binding a consent basis to a capture by the capture's hash**, so the basis a robot
  acted on belongs to the specific recording.
- **Evidence that retains only hashes and the basis**, so proving the basis does not
  retain the image or the bystander's identity.
- **An interoperable set of consent bases including an applied redaction**, so the way
  a capture was permitted is distinguishable and checkable across implementations.

---

## 5. Technical Implementation

A reference implementation provides `hash_capture`, `build_consent_evidence`, and
`verify_consent_evidence`, using the shared Data Integrity primitives so the same
evidence verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for recording the basis of a robot capture in which a signed credential
   binds a consent basis to the capture by the capture's hash and to the robot's
   identity.
2. The method of claim 1 wherein the credential stores only hashes and the basis, so no
   image or identifying data of a captured person is retained.
3. The method of claim 1 wherein the basis is drawn from an accepted set that includes
   an explicit consent token, posted notice, a legitimate interest, and an applied
   redaction.
4. The method of claim 1 wherein an explicit-consent evidence references its covering
   consent tokens by proof value, and verification reproduces the capture hash from the
   raw capture when supplied.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same evidence verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
