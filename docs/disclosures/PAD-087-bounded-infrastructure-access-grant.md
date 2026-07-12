# PAD-087: Bounded, Offline-Verifiable Robot Access to Physical Infrastructure

**Identifier:** PAD-087  
**Title:** Method for an Operator-Signed, Bounded, Offline-Verifiable Access Grant That Authorizes a Robot to Operate a Named Physical Infrastructure Resource, With Shrink-Only Attenuation  
**Publication Date:** July 5, 2026  
**Prior Art Effective Date:** July 5, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Physical Access Control / Delegation  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-064 (Hardware-Rooted Robot Identity), PAD-069 (Offline Delegation Lease), PAD-088 (Auditable Access Use Record)  

---

## 1. Abstract

A method for giving a robot bounded, revocable, offline-verifiable access to a
physical infrastructure resource such as a door, an elevator, a charger, or a
machine. An infrastructure operator issues an access grant naming the resource, the
permitted operations, an optional zone, and a time window, signed by the operator.
The resource authorizes a requested operation offline by checking that the grant
verifies under the operator's key, is within its window, names the robot presenting
it, and permits the requested operation. A sub-grant may only narrow what it
inherits, never widen it.

Key innovations:

- **Operator-signed grant scoped to a resource, operations, a zone, and a window.**
  Access is expressed as a signed credential bound to one robot, one resource, a set
  of operations, and a validity window, rather than a shared badge, key, or fixed
  code that cannot be scoped.
- **Offline authorization at the resource.** The resource decides whether to allow an
  operation with no live call to a server, by verifying the operator's grant against
  the robot presenting it, so access works in a disconnected or intermittently
  connected environment.
- **Shrink-only attenuation.** A grant can be passed down a chain and checked at each
  step so that a sub-grant only narrows the resource scope, the operation set, and
  the zone it inherits.

---

## 2. Problem Statement

### 2.1 Physical access is a shared, unscoped credential

A robot in a warehouse, hospital, or building needs to open doors, call elevators,
dock at chargers, and operate machines. Today that access is a shared badge, a
physical key, or a fixed code. It cannot be scoped to one robot, one resource, and
one time window, and it cannot be handed down in a narrowed form.

### 2.2 A network-dependent access check does not fit the physical edge

A resource on a factory floor or in a basement may be offline or intermittently
connected. An access decision that requires a live call to a central server is
fragile exactly where robots operate, and a cached allow-list is not bound to the
specific robot, resource, and moment.

---

## 3. Solution (The Invention)

`build_access_grant(...)` issues an `InfrastructureAccessGrant` whose subject carries
the robot identifier, the resource, the permitted operations, and an optional zone,
with a validity window, signed eddsa-jcs-2022 by the operator. `verify_access_grant(...)`
checks the operator's proof and that the grant is within its window.
`authorize_access(...)` makes the decision at the resource, offline: it allows the
requested operation only when the grant verifies under the operator's key and is in
window, the robot presenting the request is the robot the grant names, the resource
matches, and the operation is one the grant permits, returning the reasons for any
refusal. `attenuates_grant(...)` confirms a sub-grant only narrows the resource, the
operation set, and the zone it inherits. Because the credentials use the shared JCS
plus eddsa-jcs-2022 primitives, the same grant verifies across the language SDKs.
This is the open layer of signed grants, an offline authorization decision, and
shrink-only attenuation; hardware-enforced actuation at the resource and managed
fleet access-policy orchestration are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, capability-based access control, macaroons with caveats, and
delegation tokens each exist as prior art. This disclosure does **not** claim those
mechanisms in the abstract. What is differentiated is the reduction to bounded robot
access to a physical infrastructure resource:

- **A grant bound to a physical resource, its operations, a zone, and a window**,
  issued by the infrastructure operator to a named robot identity.
- **An offline authorization decision made at the resource**, binding the operator's
  grant to the specific robot presenting a request, with no live server call.
- **Shrink-only attenuation of a physical-access grant**, so a narrowed grant can be
  passed down a chain and checked at each step.

---

## 5. Technical Implementation

A reference implementation provides `build_access_grant`, `verify_access_grant`, and
`attenuates_grant`, together with the `authorize_access` decision described in
PAD-088, using the shared Data Integrity primitives so the same grant verifies across
the language SDKs.

---

## 6. Claims Summary

1. A method for authorizing a robot to operate a physical infrastructure resource in
   which an operator-signed access grant names the resource, the permitted operations,
   an optional zone, and a validity window bound to a robot identity.
2. The method of claim 1 wherein the resource authorizes a requested operation offline
   by verifying the operator's grant against the robot presenting the request, with no
   live server call.
3. The method of claim 1 wherein authorization allows the operation only when the
   grant is in window, the robot and resource match, and the requested operation is
   permitted by the grant.
4. The method of claim 1 wherein a sub-grant is a valid attenuation only when it
   narrows the resource, the operation set, and the zone it inherits, never widening
   them.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same grant verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
