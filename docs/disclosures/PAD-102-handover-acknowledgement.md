# PAD-102: Recipient Acknowledgement Bound to a Specific Robot-to-Human Handover

**Identifier:** PAD-102  
**Title:** Method for a Recipient-Signed Acknowledgement Bound to One Handover by Its Proof Value, So Receipt Is Mutual and Cannot Be Reused  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Physical Safety / Human-Robot Interaction  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-094 (Capture-Bound Bystander Consent Token), PAD-101 (Human-Handover Credential)  

---

## 1. Abstract

A method for making a robot-to-human handover mutual by letting the recipient sign an
acknowledgement bound to that one handover. The recipient signs an acknowledgement that
references the handover by its proof value, so the acknowledgement verifies only against the
handover it was given for and cannot be reused for another. The robot's signed handover and
the recipient's signed acknowledgement together are a two-sided, non-repudiable record that
a specific object passed from the robot to the person.

Key innovations:

- **Receipt bound to one handover by its proof value.** The acknowledgement references the
  specific handover credential, so it is meaningful only for that release and cannot be
  replayed against a different one.
- **A two-sided handover record.** The robot signs the release and the recipient signs the
  receipt, so the transfer to a person is confirmed by both parties rather than asserted by
  one.
- **Non-repudiable by construction.** Each side signs under its own identity, so neither the
  robot's release nor the recipient's receipt can be denied after the fact.

---

## 2. Problem Statement

### 2.1 A one-sided handover record can be disputed

A robot's signed handover states that it released an object, but without the recipient's
confirmation the person can dispute receiving it, and the record is one-sided.

### 2.2 A generic receipt can be reused

A receipt that is not bound to the specific handover could be presented to acknowledge a
different release, so a receipt must be tied to the one handover it belongs to.

---

## 3. Solution (The Invention)

`build_handover_ack(...)` issues a `HandoverAcknowledgement` whose subject carries the
recipient identifier, a reference to the handover by its proof value, and the object
identifier, signed eddsa-jcs-2022 by the recipient. `verify_handover_ack(...)` checks the
recipient's proof, that the issuer is the recipient, and that the acknowledgement is bound to
the given handover by its proof value, so a receipt verifies only against the handover it was
given for. Combined with the robot-signed handover of PAD-101, the pair is a two-sided,
non-repudiable record of the transfer. Because the credentials use the shared JCS plus
eddsa-jcs-2022 primitives, the same pair verifies across the language SDKs. This is the open
layer of the recipient-bound acknowledgement; any hardware-sensed confirmation of the
physical release is out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, delivery receipts, and nonce binding each exist as prior art, as
does this project's own capture-bound consent token. This disclosure does **not** claim those
in the abstract. What is differentiated is the reduction to a robot-to-human handover:

- **A recipient receipt bound to one handover by its proof value**, so it cannot be reused
  for another release.
- **A two-sided record** in which the robot signs the release and the recipient signs the
  receipt.
- **Non-repudiation on both sides**, each signing under its own identity.

---

## 5. Technical Implementation

A reference implementation provides `build_handover_ack` and `verify_handover_ack`, which
bind and check an acknowledgement against a specific handover's proof value, using the shared
Data Integrity primitives so the same pair verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for acknowledging a robot-to-human handover in which the recipient signs an
   acknowledgement referencing the handover by its proof value.
2. The method of claim 1 wherein verification accepts the acknowledgement only against the
   handover whose proof value it references, so a receipt cannot be reused for another
   release.
3. The method of claim 1 wherein the robot-signed handover and the recipient-signed
   acknowledgement together form a two-sided record of the transfer.
4. The method of claim 3 wherein each side signs under its own identity, so neither the
   release nor the receipt can be repudiated.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same pair verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
