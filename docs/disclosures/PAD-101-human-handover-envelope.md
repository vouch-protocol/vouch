# PAD-101: Robot-to-Human Handover Credential With a Safety-Envelope Attestation at the Release

**Identifier:** PAD-101  
**Title:** Method for a Robot-Signed Handover Credential That Records the Force and Speed at the Moment It Released an Object to a Person and Whether They Stayed Inside the Near-Human Safety Envelope  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Physical Safety / Human-Robot Interaction  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-066 (Physical Capability Scope), PAD-083 (Physical Custody Handoff Chain), PAD-102 (Handover Acknowledgement)  

---

## 1. Abstract

A method for making a robot's physical handover of an object to a person accountable at the
point of release, which is the moment a human hand is inside the robot's working envelope.
A human handover credential records that a robot released an object to a recipient, the
force and speed of the robot at the moment of release, and whether those stayed inside the
near-human safety envelope, signed by the robot. A handover injury then traces to whether
the robot was inside its safety envelope at the release, rather than to an unsigned log.

Key innovations:

- **The release itself as the accountable event.** Where a custody chain covers a task
  passing between actors, this covers the physical safety of the release, when the risk to a
  person is highest.
- **Force and speed attested at the handover moment.** The credential records the robot's
  force and speed at release, so the physical conditions of the handover are verifiable.
- **In-envelope verdict against the near-human safety scope.** Whether the release stayed
  inside the near-human force and speed limits is computed and carried, and reproduced on
  verification, so a claimed safe handover is confirmable.

---

## 2. Problem Statement

### 2.1 The release is the highest-risk moment and has no signed record

A robot handing an object to a person puts a human hand inside its envelope at the instant
of release. There is no signed record of the force and speed at that instant, so a handover
injury cannot be tied to whether the robot was operating safely.

### 2.2 A custody record does not cover physical release safety

A custody handoff records that responsibility for a task passed between actors, but it says
nothing about the physical safety of the release to a human.

---

## 3. Solution (The Invention)

`build_human_handover(...)` issues a `HumanHandoverCredential` whose subject carries the
robot identifier, the recipient, the object identifier, and the force and speed at the
handover, signed eddsa-jcs-2022 by the robot. When the near-human safety scope is supplied,
whether the force and speed stayed inside it is computed and carried as an in-envelope
verdict. `verify_human_handover(...)` checks the robot's proof and, when the scope is
supplied, that recomputing the near-human envelope check over the attested force and speed
reproduces the attested verdict, so a claimed safe handover cannot be signed when the
attested conditions were unsafe. Because the credential uses the shared JCS plus
eddsa-jcs-2022 primitives, the same handover verifies across the language SDKs. This is the
open layer of the signed handover with its envelope attestation and check; hardware-sensed
grip-release safety confirmation is out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, collaborative-robot safety limits, and this project's own custody
handoff and capability scope each exist as prior art. This disclosure does **not** claim
those in the abstract. What is differentiated is the reduction to a robot-to-human release:

- **The physical release to a person as the accountable event**, distinct from a
  machine-to-machine custody transfer.
- **Force and speed attested at the handover moment**, with an in-envelope verdict against
  the near-human safety scope.
- **Verification that reproduces the in-envelope verdict**, so a claimed safe handover is
  confirmable from the attested conditions.

---

## 5. Technical Implementation

A reference implementation provides `build_human_handover` and `verify_human_handover`,
using the shared Data Integrity primitives and the near-human safety-scope check so the same
handover verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for a robot-to-human handover in which the robot signs a credential recording
   the object released, the recipient, and the force and speed at the moment of release.
2. The method of claim 1 wherein an in-envelope verdict against a near-human safety scope is
   computed from the attested force and speed and carried in the credential.
3. The method of claim 2 wherein verification reproduces the in-envelope verdict, so a
   claimed safe handover cannot be signed when the attested conditions were unsafe.
4. The method of claim 1 wherein the subject of the handover is the physical release to a
   person, distinct from a custody transfer between actors.
5. The method of claim 1 wherein the credential uses canonicalization and signature
   primitives shared across language SDKs, so the same handover verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
