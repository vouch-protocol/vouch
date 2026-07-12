# PAD-097: Operator-Certified Operating Domain and Robot-Attested In-Domain Conformance

**Identifier:** PAD-097  
**Title:** Method for an Operator-Signed Operating-Domain Credential and a Robot-Signed Conformance Attestation That It Operated Inside the Certified Domain  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Autonomy Safety / Conformance  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-066 (Physical Capability Scope), PAD-072 (Living-Trust Heartbeat), PAD-079 (Regulatory Conformance), PAD-098 (In-Domain Predicate)  

---

## 1. Abstract

A method for binding an autonomous robot to the operational design domain it is certified
for and letting the robot attest that it stayed inside it. An operating-domain credential,
signed by the operator, names the allowed zones, a maximum speed, condition bounds such as
a maximum wind speed and a minimum visibility, and the time windows the robot is rated for.
An operating-domain conformance attestation, signed by the robot, reports the operating
parameters it observed over an interval and whether they stayed inside the domain. Acting
outside the certified domain, where certification stops applying, becomes detectable and
attributable.

Key innovations:

- **The operating domain as a signed credential.** The zones, speed regime, condition
  bounds, and hours a robot is certified for are carried in an operator-signed credential,
  so the domain a robot is bound to is verifiable rather than configuration.
- **Robot-attested in-domain operation over intervals.** The robot self-signs the
  parameters it observed and the in-domain verdict per interval, so a record of whether it
  stayed in its envelope travels with it.
- **The same credential base as the rest of the robot's trust.** The domain and the
  conformance attestation are verifiable credentials on the shared primitives, so they
  compose with the robot's identity, capability scope, and conformance work.

---

## 2. Problem Statement

### 2.1 The operating domain is configuration, not a signed fact

An autonomous robot is certified for a specific operational design domain, but that domain
usually lives in configuration or paperwork, not in a signed credential a verifier can
check against the robot's identity.

### 2.2 There is no portable record of staying in domain

Whether a robot operated inside its certified domain over its shifts is exactly what an
operator, insurer, or regulator wants to confirm after the fact, and there is no
robot-signed, portable record of it.

---

## 3. Solution (The Invention)

`build_odd_credential(...)` issues an `OperatingDomainCredential` whose subject carries the
robot identifier and the operating domain (allowed zones, maximum speed, condition bounds,
and time windows), signed eddsa-jcs-2022 by the operator. `verify_odd_credential(...)`
returns the certified domain. `build_odd_conformance(...)` issues an
`ODDConformanceAttestation` in which the robot reports the operating parameters it observed
over an interval and the in-domain verdict, signed by the robot. `verify_odd_conformance(...)`
checks the robot's proof and, when the domain is supplied, that recomputing the in-domain
check over the attested observations reproduces the attested verdict, so the robot cannot
claim it stayed in domain when its own reported observations say otherwise. Because the
credentials use the shared JCS plus eddsa-jcs-2022 primitives, the same domain and
attestation verify across the language SDKs. This is the open layer of the signed domain
credential, the conformance attestation, and the check; real-time out-of-domain prediction
and automatic safe-stop enforcement are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, geofencing, and operational-limit configuration each exist as prior
art, as does this project's own capability scope and regulatory conformance work. This
disclosure does **not** claim those in the abstract. What is differentiated is the
reduction to a certified operating domain for an autonomous robot:

- **An operator-signed operating-domain credential** spanning zones, speed, environmental
  conditions, and hours, bound to a robot identity.
- **A robot-signed in-domain conformance attestation over intervals**, portable across
  owners and regulators.
- **Verification that reproduces the in-domain verdict** from the robot's own observations,
  so an out-of-domain excursion cannot be signed away as in-domain.

---

## 5. Technical Implementation

A reference implementation provides `build_odd_credential`, `verify_odd_credential`,
`build_odd_conformance`, and `verify_odd_conformance`, using the shared Data Integrity
primitives so the same domain and attestation verify across the language SDKs.

---

## 6. Claims Summary

1. A method for binding an autonomous robot to its operating domain in which an
   operator-signed credential names the allowed zones, a speed regime, condition bounds,
   and time windows the robot is certified for.
2. The method of claim 1 wherein the robot signs a conformance attestation reporting the
   parameters it observed over an interval and whether they stayed inside the domain.
3. The method of claim 2 wherein verification reproduces the in-domain verdict from the
   attested observations, so an out-of-domain excursion cannot be claimed as in-domain.
4. The method of claim 1 wherein the domain condition bounds carry named upper and lower
   limits such as a maximum wind speed and a minimum visibility.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same records verify cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
