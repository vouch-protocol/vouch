# PAD-079: Machine-Checkable Regulatory Conformance Over Robot Verifiable Credentials

**Identifier:** PAD-079  
**Title:** Method for Expressing a Regulatory Requirement as a Machine-Checkable Predicate Over Robot Verifiable Credentials, Producing a Deterministic Per-Requirement Report and a Signed Point-in-Time Conformance Attestation  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Regulatory Conformance / Verifiable Credentials  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-065 (Model and Config Provenance), PAD-066 (Physical Capability Scope), PAD-078 (Robot Lifecycle)  

---

## 1. Abstract

A method for making regulatory conformance of a robot verifiable in the open. A
conformance profile is an ordered list of requirements, each naming a clause of a
public safety or AI regulation and the credential evidence that satisfies it. A
deterministic checker runs a profile against the set of credentials a robot
presents and returns a per-requirement report citing each clause and whether it is
satisfied. An issuer then signs a point-in-time conformance attestation that embeds
the report and binds it by digest.

Key innovations:

- **Regulatory requirement as a machine-checkable predicate over credentials.** Each
  requirement maps a regulation clause to the presence and fields of specific robot
  credentials, turning a document into something a verifier runs.
- **Deterministic, reproducible report.** The same credentials and profile produce
  the same report in any language, and a report digest lets the report be referenced
  by hash.
- **Signed point-in-time attestation bound to its report.** An assessing party signs
  an attestation embedding the report and its digest, so the report cannot be
  altered after signing without breaking verification.

---

## 2. Problem Statement

### 2.1 Conformance lives in documents no machine can check

A robot may carry a hardware-rooted identity, a physical scope, a safety record, and
more, but the question "does this satisfy ISO 10218 or the EU Machinery Regulation?"
is still answered by hand, against evidence a third party cannot independently
recheck.

### 2.2 A conformance claim can be asserted without backing

A plain statement that a robot is compliant carries no cryptographic link to the
credentials that would substantiate it, and no way to confirm the claim was not
edited after it was made.

---

## 3. Solution (The Invention)

A profile is data: an ordered list of requirements, each naming a regulation clause,
a title, the credential type it needs, and the fields that must be present.
`check_conformance(credentials, profile_id)` walks the profile and, for each
requirement, decides whether some presented credential matches the type and carries
the required fields, returning a deterministic report of per-requirement results
with the clause cited. `report_digest(...)` gives the report's multibase hash. An
assessing party calls `build_conformance_attestation(...)` to sign a point-in-time
attestation embedding the report and its digest, and
`verify_conformance_attestation(...)` checks the signature and that the embedded
report reproduces its bound digest. Reference profiles map to ISO 10218-1/-2, ISO/TS
15066, the EU Machinery Regulation 2023/1230, the EU AI Act high-risk requirements,
and UL 3300. The profiles are an open reference crosswalk, and a deployment confirms
each mapping against the current regulation text. The shared JCS plus eddsa-jcs-2022
primitives make the report and attestation reproduce and verify across the language
SDKs.

---

## 4. Prior Art Differentiation

Policy engines, credential schema validation, and signed attestations each exist as
prior art. This disclosure does **not** claim rule evaluation in the abstract. What
is differentiated is the reduction to regulatory conformance over robot credentials:

- **Regulatory clause as a predicate over robot Verifiable Credentials**, so the
  answer is reproducible from the robot's own credentials rather than a manual audit.
- **A deterministic report with a digest**, so any language reproduces the same
  result and the report can be referenced and bound by hash.
- **A signed point-in-time attestation that embeds and binds its report**, so a
  passing result cannot be edited after signing.

This disclosure covers the static checker and the full-evidence report and
attestation.

---

## 5. Technical Implementation

A reference implementation provides the built-in `PROFILES`, `profile`,
`check_conformance`, `report_digest`, `build_conformance_attestation`, and
`verify_conformance_attestation`, using the shared Data Integrity primitives so the
report and attestation reproduce and verify across the language SDKs.

---

## 6. Claims Summary

1. A method for expressing a regulatory requirement as a machine-checkable predicate
   over robot Verifiable Credentials, producing a deterministic per-requirement
   report that cites the clause each requirement maps to.
2. The method of claim 1 wherein the same credentials and profile reproduce the same
   report across independent implementations, and a report digest allows the report
   to be referenced by hash.
3. The method of claim 1 wherein an assessing party signs a point-in-time
   conformance attestation that embeds the report and binds it by digest.
4. The method of claim 3 wherein verification rejects an attestation whose embedded
   report does not reproduce its bound digest.
5. The method of claim 1 wherein the report and attestation use canonicalization and
   signature primitives shared across language SDKs, so they reproduce and verify
   cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
