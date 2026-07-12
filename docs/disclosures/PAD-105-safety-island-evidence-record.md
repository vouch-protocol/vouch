# PAD-105: Signed Tamper-Evident Safety-Evidence Record Bound to a Robot's Identity and Certified Stack

**Identifier:** PAD-105  
**Title:** Method for Sealing a Robot's Functional-Safety Event Stream Into a Confidential, Tamper-Evident Record Bound to the Robot's Identity and the Certified Safety Stack It Ran On  
**Publication Date:** July 12, 2026  
**Prior Art Effective Date:** July 12, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Safety / Evidence  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-072 (Encrypted Black-Box and Kill-Switch), PAD-103 (Root-Anchored Hardware-Rooted Robot Identity)  

---

## 1. Abstract

A method by which a robot turns the event stream produced by its functional-safety
subsystem into a signed record that is confidential, tamper-evident, attributable to
the specific robot, and tied to the certified safety stack the robot ran on. A
design-time safety certification establishes that a robot's stack meets a standard. It
does not, on its own, produce a verifiable account of what a specific robot actually did.
This method supplies that account as the evidence layer beneath such a certification.

The robot records each safety-relevant event, from a safety monitor, a safety event
integrator, a safety decision maker running on an isolated safety island, a sensor input
pipeline, an emergency stop, or an operator action, into an encrypted, hash-linked,
append-only log. The robot then signs a credential that seals the log's chain head and
its entry count and binds them to the robot's identity and to the named elements of the
certified safety stack, such as the compute module, the safety operating system version,
and the safety-application set. A verifier that holds the sealed credential and the log
entries, without the log's confidentiality key, confirms four things: the record is
unaltered, it has not been truncated or extended since it was sealed, it is attributable
to that specific robot, and it was produced on the named certified configuration.

Key innovations:

- **A safety-island event stream sealed into a tamper-evident record.** The events a
  robot's functional-safety subsystem produces are captured into a hash-linked encrypted
  log, so the sequence is confidential yet any alteration is detectable.
- **A seal over both the record's length and its content.** The signed credential
  binds both the chain head and the entry count, so a later truncation or extension of
  the log is detected, along with any change to an existing entry.
- **Evidence bound to identity and to the certified configuration.** The seal ties the
  record to the robot's identity and to the specific certified safety-stack elements it
  ran on, so the account is attributable and tied to the configuration a certifier
  assessed.
- **Verifiable without the confidentiality key.** The chain and the seal verify from the
  encrypted entries alone, so a certifier, insurer, or investigator confirms integrity,
  length, attribution, and configuration without being able to read the payloads.

---

## 2. Problem Statement

### 2.1 A safety certification does not record what a specific robot did

A functional-safety certification assesses that a robot's stack is safe by design. It
produces no signed, verifiable record of the events a specific unit produced in service,
so after an incident there is no attributable account tied to the certified stack.

### 2.2 A plain log can be altered, truncated, or detached from the robot

A log kept by the robot can be edited, shortened to hide events, or presented apart from
the robot's identity and the configuration it ran on. A record that stored the events in
the clear to prove them would also expose whatever the robot captured.

### 2.3 Proving the record should not require reading it

A party that needs to confirm a record is intact and complete, such as a certifier or an
insurer, is often not the party permitted to read its contents. Integrity and
completeness should be checkable without decrypting the payloads.

---

## 3. Solution (The Invention)

A `SafetyEventRecorder` writes each safety-relevant event, tagged by its source in the
functional-safety subsystem, into an append-only log in which every entry's payload is
encrypted and every entry is hash-linked to the previous one, so the log is confidential
and any change breaks the chain. `build_safety_evidence(...)` has the robot sign a
credential whose subject carries the log's chain head, the entry count, the robot
identity, the named certified safety-stack elements, and the covered time window.
`verify_safety_evidence(...)` checks the robot's proof and that the issuer is the robot,
and, when the entries are supplied, that the hash chain is intact, that the number of
entries equals the sealed count, and that the head of the presented entries equals the
sealed head. A tampered, truncated, extended, or reordered log is therefore rejected, and
the payloads never need to be read to perform the check. Because the credentials use the
shared JCS plus eddsa-jcs-2022 primitives, the same evidence verifies across the language
SDKs. This is the open evidence layer; multi-party quorum issuance of the record and
continuous behavioral binding of the robot are out of scope for this disclosure.

---

## 4. Prior Art Differentiation

Encrypted flight recorders, hash-linked logs, Verifiable Credentials, and functional-safety
certification each exist as prior art. This disclosure does **not** claim those mechanisms
in the abstract. What is differentiated is their reduction to a safety-evidence record for
a certified robot:

- **Sealing a functional-safety event stream with both a head and a count**, so a later
  truncation or extension of the record is detected, along with any change to an entry.
- **Binding the sealed record to the robot's identity and to the named certified
  safety-stack elements**, so the account is attributable and tied to the assessed
  configuration.
- **Confirming integrity, completeness, attribution, and configuration without the
  confidentiality key**, so a party that may not read the payloads can still verify the
  record.

---

## 5. Technical Implementation

A reference implementation provides `SafetyEventRecorder`, `build_safety_evidence`, and
`verify_safety_evidence`, composing an encrypted hash-linked log with the robot-identity
and Data Integrity primitives, so the same evidence verifies across the language SDKs and
through a C application binding interface.

---

## 6. Claims Summary

1. A method in which a robot records the event stream of its functional-safety subsystem
   into an encrypted, hash-linked, append-only log and signs a credential that seals the
   log's chain head and entry count and binds them to the robot's identity and to the
   certified safety-stack elements it ran on.
2. The method of claim 1 wherein verification of the sealed credential against the log
   entries rejects a record that has been altered, truncated, extended, or reordered,
   using the sealed head and count.
3. The method of claim 1 wherein the log entries are encrypted so that integrity,
   completeness, attribution, and configuration are verified without reading the payloads.
4. The method of claim 1 wherein the sealed record names the compute module, the safety
   operating system version, and the safety-application set of the certified stack, and
   the robot identity is a hardware-rooted identity.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same evidence verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
