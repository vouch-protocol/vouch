# PAD-103: Root-Anchored, Hardware-Rooted Robot Identity Binding

**Identifier:** PAD-103  
**Title:** Method for Confirming, Against a Single Pinned Root, Both That a Robot Comes From a Recognized Manufacturer and That Its Identity Key Is Hardware-Rooted  
**Publication Date:** July 12, 2026  
**Prior Art Effective Date:** July 12, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Identity / Root of Trust  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-068 (Perception Provenance), Root of Trust for Machine Identity (recognized-issuer authority layer)  

---

## 1. Abstract

A method that lets a verifier pinning one root confirm two facts about a robot in a
single offline check: that the robot's identity was issued by a manufacturer the root
recognizes to issue robot identities, and that the robot's identity key is bound to a
hardware root of trust. A recognized manufacturer issues an authority identity
credential for the robot whose subject references the robot's hardware-rooted key. The
robot separately holds a hardware-attested identity credential that binds that same key
to a secure element or TPM. Verification anchors the manufacturer's recognition to the
pinned root, verifies the hardware attestation, and checks that the key the manufacturer
vouched for is the exact key the hardware attested, so provenance and hardware-rooting
are confirmed together and cannot be presented apart.

Key innovations:

- **One pinned root confirms provenance and hardware-rooting together.** A verifier
  that pins a single root learns both "this robot is from a recognized manufacturer"
  and "this robot's key is hardware-rooted" from one anchored check, with no online
  lookup.
- **The manufacturer's authority identity references the hardware-rooted key.** The
  root-recognized identity names the robot's key, and verification requires that key to
  equal the key the hardware root attested, so a legitimate provenance record cannot be
  reused over a different or software-only key.
- **Anchor-once composition over an existing recognized-issuer layer.** The binding
  reuses the recognized-issuer authority format and the hardware-rooted identity format
  unchanged, composing them so the two independent facts resolve to the same pinned
  root.

---

## 2. Problem Statement

### 2.1 Provenance and hardware-rooting are proven separately, and can be mixed

A robot can carry a manufacturer's attestation that it is a genuine unit, and it can
carry a hardware attestation that a key lives in its secure element. Proven separately,
nothing forces the manufacturer's attestation to refer to the hardware-rooted key. A
genuine provenance record can then be presented alongside a software-only key, or over a
key that never touched the attested hardware, and a verifier checking one fact learns
nothing about the other.

### 2.2 A verifier should not have to pin two roots or query a manufacturer online

If the manufacturer's recognition and the hardware attestation resolve to different
trust anchors, a verifier must pin several roots or contact the manufacturer at
verification time. A robot operating in the field needs a single pinned root and an
offline check.

---

## 3. Solution (The Invention)

`build_robot_identity(...)` has a manufacturer, recognized by the pinned root to issue
robot identities, issue an authority identity credential for the robot whose subject
names the robot's DID and its hardware-rooted key. The robot independently holds a
hardware-attested identity credential (PAD-064) that binds that same key to its hardware
root.

`verify_robot_identity_chain(...)` performs a single anchored check:

1. It verifies the manufacturer's recognition and the authority identity against the one
   pinned root, requiring the recognized action for issuing robot identities, using the
   same anchor-once model and reason codes as the recognized-issuer authority layer.
2. It verifies the robot's hardware attestation, confirming the identity key is bound to
   the hardware root.
3. It confirms the hardware-attested subject is the robot named by the authority
   identity, and that the key the manufacturer vouched for is the exact key the hardware
   attested.

Only when all three hold does verification return success with a hardware-rooted result.
Each failure returns a distinct reason code (issuer not recognized for the robot action,
recognition not from the pinned root, no hardware key in the identity, hardware root
invalid, hardware subject mismatch, hardware key mismatch, recognition revoked), so a
verifier learns which fact failed. Because the credentials use the shared JCS plus
eddsa-jcs-2022 primitives, the same chain verifies across the language SDKs. This is the
open layer of the binding; quorum-based issuance and continuous behavioral binding are
out of scope for this disclosure.

---

## 4. Prior Art Differentiation

Verifiable Credentials, certificate chains anchored to a root, and hardware attestation
(TPM, secure element) each exist as prior art. This disclosure does **not** claim those
mechanisms in the abstract. What is differentiated is their composition into a
single-root robot identity binding:

- **A manufacturer authority identity that references the robot's hardware-rooted key**,
  such that verification requires the vouched key to equal the hardware-attested key, so
  provenance cannot be reused over a different or software-only key.
- **One pinned root that confirms both provenance and hardware-rooting** in an offline
  anchor-once check, rather than pinning multiple roots or querying the manufacturer.
- **A reason-coded verification** distinguishing a provenance failure from a
  hardware-rooting failure from a key-linkage failure, so the specific broken fact is
  identifiable.

---

## 5. Technical Implementation

A reference implementation provides `build_robot_identity` and
`verify_robot_identity_chain`, composing the recognized-issuer authority layer with the
hardware-rooted identity format and using the shared Data Integrity primitives, so the
same chain verifies across the language SDKs. A deterministic interop vector carries a
recognized manufacturer, a hardware-attested robot credential, and a root-anchored
authority identity, which every SDK verifies to confirm both recognized-manufacturer
provenance and hardware-rooting.

---

## 6. Claims Summary

1. A method for confirming a robot's identity in which a verifier pinning a single root
   confirms, in one offline check, both that the robot was issued an identity by a
   manufacturer the root recognizes and that the robot's identity key is bound to a
   hardware root of trust.
2. The method of claim 1 wherein a recognized manufacturer issues an authority identity
   credential whose subject references the robot's hardware-rooted key, and verification
   requires that key to equal the key attested by the hardware root.
3. The method of claim 1 wherein the manufacturer's recognition and the authority
   identity are anchored to the same single pinned root, requiring a recognized action
   for issuing robot identities.
4. The method of claim 1 wherein verification returns distinct reason codes
   distinguishing a provenance failure, a hardware-rooting failure, and a key-linkage
   failure between the vouched key and the hardware-attested key.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same chain verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
