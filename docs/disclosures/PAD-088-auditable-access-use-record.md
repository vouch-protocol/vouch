# PAD-088: Auditable, Attributable Record of a Robot's Use of Physical Infrastructure

**Identifier:** PAD-088  
**Title:** Method for Pairing a Robot-Signed Access Request With an Operator-Signed Grant to Form a Tamper-Evident, Attributable Record of Which Robot Used Which Physical Resource, for Which Operation, and When  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Physical Access Control / Audit  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-083 (Physical Custody Handoff Chain), PAD-087 (Bounded Infrastructure Access Grant)  

---

## 1. Abstract

A method for producing a tamper-evident, attributable record of a robot's use of a
physical infrastructure resource. When a robot exercises an operator's access grant,
it presents an access request for a specific operation on a specific resource, signed
by the robot's own key. The request paired with the operator's grant is a
self-contained record that attributes the access to a specific robot, resource,
operation, and moment, verifiable after the fact by anyone holding the two public
keys, without trusting a central log.

Key innovations:

- **Robot-signed request as the accountability half of an access.** The robot signs
  its own request naming the resource and the operation, so the record of what access
  was exercised is attributable to the robot that exercised it, not to an
  after-the-fact server entry.
- **Grant-plus-request pair as a self-contained audit record.** The operator-signed
  grant and the robot-signed request together attribute the access to a specific
  robot, resource, operation, and time, and each half is independently verifiable, so
  the record does not depend on a trusted central log.
- **Reason-carrying refusal.** When authorization fails, the decision names each
  reason, so a refused access is as auditable as an allowed one.

---

## 2. Problem Statement

### 2.1 An access log is asserted by the resource, not by the robot

A conventional access log is a list of entries a door controller or a server wrote.
It is trusted because the infrastructure is trusted, and it carries no signature from
the robot that acted. After an incident, there is no cryptographic proof that a
particular robot requested a particular operation at a particular time.

### 2.2 Grant and use are recorded separately

The permission to act and the act of exercising it are usually recorded in different
places, by different parties, so tying a specific use back to the specific grant that
allowed it, and to the robot that exercised it, requires trusting the correlation
rather than verifying it.

---

## 3. Solution (The Invention)

`build_access_request(...)` issues an `InfrastructureAccessRequest` whose subject
carries the robot identifier, the resource, and the requested operation, signed
eddsa-jcs-2022 by the robot. `authorize_access(...)` decides at the resource whether
to allow the operation and, in doing so, binds the robot-signed request to the
operator-signed grant of PAD-087: it verifies the grant under the operator's key and
the request under the robot's key, confirms the grant and request name the same robot
and resource, confirms the operation is permitted, and returns an explicit list of
reasons for any refusal. The grant and the request together are a self-contained,
tamper-evident record that attributes the access to a specific robot, resource,
operation, and moment, independently verifiable by anyone holding the two public
keys. Because the credentials use the shared JCS plus eddsa-jcs-2022 primitives, the
same record verifies across the language SDKs. This is the open layer of a
robot-signed request, an offline authorization decision, and an attributable audit
record; hardware-enforced actuation at the resource and managed fleet access-policy
orchestration are out of scope.

---

## 4. Prior Art Differentiation

Signed audit logs, access tokens, and request signing each exist as prior art. This
disclosure does **not** claim those mechanisms in the abstract. What is differentiated
is the reduction to an attributable record of physical infrastructure use:

- **A robot-signed request for a physical operation on a named resource**, so the use
  is attributed to the robot that exercised it rather than asserted by the resource.
- **A grant-plus-request pair as a self-contained, independently verifiable record**,
  tying a specific use to the specific operator grant that allowed it, without a
  trusted central log.
- **A reason-carrying authorization decision**, so a refused physical access is
  auditable with the same evidence as an allowed one.

---

## 5. Technical Implementation

A reference implementation provides `build_access_request` and the `authorize_access`
decision that binds a robot-signed request to the operator-signed grant of PAD-087,
using the shared Data Integrity primitives so the same record verifies across the
language SDKs.

---

## 6. Claims Summary

1. A method for recording a robot's use of a physical infrastructure resource in which
   the robot signs an access request naming the resource and the requested operation.
2. The method of claim 1 wherein the robot-signed request paired with an
   operator-signed access grant forms a self-contained record attributing the access
   to a specific robot, resource, operation, and moment.
3. The method of claim 2 wherein each half of the record is independently verifiable
   under its signer's public key, so the record does not depend on a trusted central
   log.
4. The method of claim 1 wherein the authorization decision returns an explicit list
   of reasons for a refusal, so a refused access is auditable with the same evidence
   as an allowed one.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same record verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
