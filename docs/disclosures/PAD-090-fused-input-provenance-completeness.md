# PAD-090: Detecting a Dropped or Substituted Input in a Robot's Fused Perception Output

**Identifier:** PAD-090  
**Title:** Method for Verifying That Every Input Named by a Fused Perception Attestation Traces to a Frame the Robot Recorded, So a Dropped or Substituted Fused Input Is Detected  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Perception / Provenance  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-068 (Perception Provenance), PAD-089 (Fused-Sensor Provenance Attestation)  

---

## 1. Abstract

A method for confirming that a robot's fused perception output was built only from
frames the robot actually recorded, so a fused input that was dropped or substituted is
detected. A fused-perception attestation names the input frame hashes that produced a
fused output. This method checks each named input against the robot's signed,
hash-linked perception log and reports any input that does not appear as a recorded
frame, so a fused result that silently drew on an unrecorded or substituted input is
named rather than hidden.

Key innovations:

- **Fused inputs checked against the recorded perception log.** Each input named by the
  attestation is required to appear as a frame in the robot's signed, hash-linked
  perception log, tying the fusion to the robot's own recorded evidence.
- **A dropped or substituted input is named, not hidden.** The check returns the
  specific inputs that do not trace to a recorded frame, so the discrepancy is
  localized rather than reducing to a single pass or fail.
- **Completeness on top of a tamper-evident input set.** Because the attestation's
  input digest already makes the declared input set tamper-evident, this completeness
  check closes the remaining gap that a declared input never existed.

---

## 2. Problem Statement

### 2.1 A declared input may never have been captured

A fused-perception attestation commits to the set of inputs it declares, but a
signature over a declared set does not by itself prove each declared input corresponds
to a frame the robot actually captured. A fabricated or substituted input hash could be
declared and signed.

### 2.2 A dropped input is invisible without cross-checking the record

If a fused output quietly omits an input it should have used, or swaps one input for
another, a consumer holding only the attestation cannot tell, because there is nothing
to compare the declared inputs against.

---

## 3. Solution (The Invention)

`verify_fusion_inputs(...)` takes a fused-perception attestation and the robot's
perception log entries, collects the frame hashes recorded in the log, and returns
whether every input frame hash named by the attestation appears among them, along with
the list of any inputs that do not. Combined with the attestation's signed input digest
from PAD-089, which makes the declared input set tamper-evident, this confirms both that
the declared inputs cannot be altered after signing and that each declared input traces
to a frame the robot recorded, so a dropped or substituted fused input is detected and
named. Because the perception log uses the shared hash-linked chain semantics, the same
check runs across the language SDKs. This is the open layer of a software completeness
check against the recorded log; hardware sensor attestation and managed sensor-fusion
orchestration are out of scope.

---

## 4. Prior Art Differentiation

Set membership checks, audit reconciliation, and hash-linked logs each exist as prior
art. This disclosure does **not** claim those mechanisms in the abstract. What is
differentiated is the reduction to fused-input provenance completeness for a robot:

- **Reconciling a fused output's declared inputs against the robot's recorded
  perception log**, so a fused result is tied to the robot's own evidence trail.
- **Naming the specific inputs that do not trace to a recorded frame**, localizing a
  dropped or substituted fused input rather than returning a bare pass or fail.
- **Completeness layered on a signed, tamper-evident input set**, closing the gap that a
  declared input never existed.

---

## 5. Technical Implementation

A reference implementation provides `verify_fusion_inputs`, which reconciles the input
frame hashes named by a `FusedPerceptionAttestation` against the frame hashes in the
robot's signed perception log, using the shared hash-linked chain so the same check runs
across the language SDKs.

---

## 6. Claims Summary

1. A method for verifying a robot's fused perception output in which each input frame
   hash named by a fused-perception attestation is checked against the frame hashes
   recorded in the robot's signed perception log.
2. The method of claim 1 wherein an input that does not appear as a recorded frame is
   returned by name, so a dropped or substituted fused input is localized.
3. The method of claim 1 wherein the attestation carries a signed digest over its
   declared inputs, so the completeness check is layered on a tamper-evident input set.
4. The method of claim 1 wherein the perception log is a hash-linked chain, so the same
   reconciliation runs across language SDKs.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
