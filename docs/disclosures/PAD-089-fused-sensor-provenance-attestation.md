# PAD-089: Signed Provenance Binding a Robot's Fused World Model to Its Input Frames

**Identifier:** PAD-089  
**Title:** Method for a Signed Attestation That Binds a Robot's Fused Perception Output to the Ordered Set of Input Sensor Frames and the Fusion Method That Produced It  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Perception / Provenance  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-068 (Perception Provenance), PAD-090 (Fused-Input Provenance Completeness)  

---

## 1. Abstract

A method for making a robot's fused world model accountable to the sensor frames
that produced it. Perception provenance signs individual sensor frames, but a robot
acts on the fusion of many frames into a single output, an object set, an occupancy
grid, or a pose. A fused-perception attestation binds the hash of the fused output to
an ordered list of the input frame hashes, a digest over those inputs, and a fusion
method identifier, signed by the robot. A verifier reproduces the input digest from
the listed inputs and, when it holds the raw fused output, reproduces its hash, so the
attestation commits to exactly those inputs and that output.

Key innovations:

- **Fused output bound to its exact input frame set.** The attestation names the
  ordered input frame hashes and a digest over them, so the fused output is tied to
  the precise frames it was derived from rather than to a single frame.
- **Reproducible input digest.** The digest over the ordered inputs is a
  deterministic computation reproduced byte-identically across language SDKs, so
  adding, removing, or reordering an input changes it and breaks verification.
- **Fusion method as part of the provenance.** The attestation records the identifier
  of the method that produced the output, so the fused result is attributable to a
  named process as well as to the frames it consumed.

---

## 2. Problem Statement

### 2.1 A robot acts on the fusion, not on one frame

Signing individual sensor frames establishes what each sensor captured, but the
decision a robot makes is driven by the fusion of many frames into one world model.
There is no signed record tying that fused output back to the specific frames and the
method that produced it.

### 2.2 A manipulated fusion result has no provenance

If a fused output is altered, or is produced from a different set of inputs than
claimed, a downstream consumer holding only per-frame signatures cannot detect it,
because nothing binds the fused output to its inputs.

---

## 3. Solution (The Invention)

`build_fused_attestation(...)` issues a `FusedPerceptionAttestation` whose subject
carries the robot identifier, the fusion method identifier, the hash of the fused
output, the ordered list of input frame hashes, and a digest over those inputs, signed
eddsa-jcs-2022 by the robot. `fusion_inputs_digest(...)` computes the input digest as a
deterministic hash over the ordered input frame hashes, reproduced byte-identically
across language SDKs. `verify_fused_attestation(...)` checks the robot's proof,
reproduces the input digest and requires it to equal the attested value, and, when the
raw fused output is supplied, reproduces its hash and requires it to equal the attested
value. Because the credentials and the digest use the shared JCS plus eddsa-jcs-2022
primitives, the same attestation verifies across the language SDKs. This is the open
layer of a software-signed binding of a fused output to its inputs, reusing the
perception frame hashes; hardware sensor attestation and managed sensor-fusion
orchestration are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, content hashing, and Merkle commitments each exist as prior
art, as does this project's own per-frame perception provenance. This disclosure does
**not** claim those mechanisms in the abstract. What is differentiated is the reduction
to a robot's fused perception output:

- **A fused perception output bound to the ordered set of input frame hashes**, so the
  world model a robot acts on is tied to the exact frames it was derived from.
- **A reproducible digest over the ordered inputs**, so the input set is tamper-evident
  and reproduced identically across language implementations.
- **The fusion method recorded as part of the provenance**, attributing the fused
  result to a named process.

---

## 5. Technical Implementation

A reference implementation provides `hash_fused_output`, `fusion_inputs_digest`,
`build_fused_attestation`, and `verify_fused_attestation`, using the shared Data
Integrity primitives and the perception frame hashes so the same attestation verifies
across the language SDKs.

---

## 6. Claims Summary

1. A method for attesting a robot's fused perception output in which a signed
   attestation binds the hash of the fused output to an ordered list of input frame
   hashes and a fusion method identifier.
2. The method of claim 1 wherein a digest over the ordered input frame hashes is
   carried in the attestation, so adding, removing, or reordering an input changes the
   digest and breaks verification.
3. The method of claim 2 wherein the digest is a deterministic computation reproduced
   byte-identically across language SDKs.
4. The method of claim 1 wherein a verifier holding the raw fused output reproduces its
   hash and requires it to equal the attested fused-output hash.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same attestation verifies
   cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
