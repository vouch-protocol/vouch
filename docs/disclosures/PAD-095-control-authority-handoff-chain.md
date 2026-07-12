# PAD-095: Accountable Control-Authority Handoff Chain Between Autonomy and Human Teleoperators

**Identifier:** PAD-095  
**Title:** Method for a Signed Chain of Control-Authority Handoffs Between an Autonomous Policy and Human Teleoperators, So Who or What Was in Control of a Robot at Any Moment Is Verifiable  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Teleoperation / Accountability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-083 (Physical Custody Handoff Chain), PAD-096 (Control Continuity)  

---

## 1. Abstract

A method for making the transfer of control of a robot between an autonomous policy
and human teleoperators accountable. A control handoff credential records that a
receiving controller took control of a robot from a releasing controller, tagged
with the control mode (autonomous, teleoperated, or shared), signed by the receiver,
the party taking responsibility. Linking each handoff forms a chain a verifier walks
to establish who held control, and a controller-at-time lookup returns who held it at
any moment, so an incident traces to the controller in charge then.

Key innovations:

- **Mode-tagged control handoff.** Each handoff carries whether control passed to an
  autonomous policy, a human teleoperator, or a shared mode, so the record
  distinguishes machine control from human control for liability.
- **Autonomy and human in one chain.** A controller is a Vouch identity that may be an
  autonomous policy or a human operator, so control passing back and forth between them
  is one verifiable structure.
- **Controller-at-time attribution.** Given the chain and a time, the method returns the
  controller in charge then, so an incident is attributed to whoever or whatever was
  driving at that moment.

---

## 2. Problem Statement

### 2.1 Control passes between autonomy and humans with no signed record

An autonomous robot hands control to a remote operator for a hard case and takes it
back afterward. When something goes wrong, the first question is who or what was in
control, and the answer today is an unsigned log the infrastructure asserts.

### 2.2 The machine-versus-human distinction is the liability question

Whether a robot was under autonomous control or human teleoperation at the moment of
an incident changes who is responsible, and nothing binds that distinction to the
transfer in a verifiable form.

---

## 3. Solution (The Invention)

`build_control_handoff(...)` issues a `ControlHandoffCredential` whose subject carries
the robot identifier, the releasing controller, the receiving controller, and the
control mode, signed eddsa-jcs-2022 by the receiver. `verify_control_handoff(...)`
checks the proof, that the issuer is the receiving controller, and that the mode is one
an interoperable verifier accepts. `verify_control_chain(...)` walks an ordered list of
handoffs, confirms each verifies under its receiver's key and every link's receiving
controller matches the next link's releasing controller, and returns the current
controller. `controller_at(...)` returns the controller in charge at a given time.
Controllers are Vouch identities that may be autonomous policies or human operators, so
the chain crosses the machine-human boundary. Because the credentials use the shared JCS
plus eddsa-jcs-2022 primitives, the same chain verifies across the language SDKs. This is
the open layer of signed handoffs and chain verification; latency-bound safe-takeover
enforcement and biometric operator binding are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, custody chains, and handover logging each exist as prior art,
including this project's own physical custody chain. This disclosure does **not** claim
those mechanisms in the abstract. What is differentiated is the reduction to control
authority over a robot:

- **The subject is control of the robot itself**, not a task or object it carries, tagged
  with the autonomous-or-human control mode.
- **Autonomy and human operators in one chain**, so control passing between them is a
  single verifiable structure.
- **Controller-at-time attribution across the machine-human boundary**, so an incident
  points at whoever or whatever was driving then.

---

## 5. Technical Implementation

A reference implementation provides `build_control_handoff`, `verify_control_handoff`,
`verify_control_chain`, and `controller_at`, using the shared Data Integrity primitives
so the same control chain verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for a control-authority handoff chain in which each handoff credential records
   a receiving controller taking control of a robot from a releasing controller, tagged
   with a control mode, and is signed by the receiver.
2. The method of claim 1 wherein the control mode distinguishes an autonomous policy, a
   human teleoperator, and a shared mode.
3. The method of claim 1 wherein a controller is an identity that may be an autonomous
   policy or a human operator, so the chain crosses the machine-human boundary.
4. The method of claim 1 wherein a controller-at-time lookup returns the controller in
   charge at a given time, so an incident traces to whoever was driving then.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same chain verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
