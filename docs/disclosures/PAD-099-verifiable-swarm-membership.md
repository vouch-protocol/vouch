# PAD-099: Verifiable Swarm Membership for a Multi-Robot Group

**Identifier:** PAD-099  
**Title:** Method for a Coordinator-Signed Membership Credential That Admits a Robot to a Named Swarm With an Optional Role  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Multi-Robot Systems / Accountability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-067 (Robot-to-Robot Handshake), PAD-100 (Collective-Action Attribution)  

---

## 1. Abstract

A method for making membership in a multi-robot swarm verifiable. A swarm membership
credential records that a coordinator admitted a robot to a named swarm, optionally with a
role, signed by the coordinator. A verifier confirms that a robot is a member of a specific
swarm under a specific coordinator, so a group of robots acting together has a checkable
boundary of who belongs and who authorized them, rather than an anonymous collection.

Key innovations:

- **Coordinator-admitted membership scoped to a named swarm.** Membership is a signed
  credential naming the swarm and the admitted robot, so belonging to a group is verifiable
  and scoped rather than assumed.
- **Role carried in the membership.** An optional role lets the membership distinguish what
  part a robot plays in the swarm.
- **The same identity base as a single robot.** The member is a Vouch robot identity, so
  swarm membership composes with the robot's hardware-rooted identity and the rest of its
  trust.

---

## 2. Problem Statement

### 2.1 A swarm has no verifiable boundary

Robots increasingly act as a group, but there is no signed way to say which robots are
members of that group and who admitted them, so a collective action cannot be tied to an
authorized membership.

### 2.2 Anonymous membership defeats attribution

If any robot can claim to be part of a swarm, a collective action cannot be attributed to
the specific robots that were authorized to take part.

---

## 3. Solution (The Invention)

`build_swarm_membership(...)` issues a `SwarmMembershipCredential` whose subject carries the
robot identifier and the swarm identifier, optionally with a role, signed eddsa-jcs-2022 by
the coordinator. `verify_swarm_membership(...)` checks the coordinator's proof and, when a
swarm identifier is supplied, that the membership is for that swarm, returning the subject.
Because the member is a Vouch robot identity and the credential uses the shared JCS plus
eddsa-jcs-2022 primitives, membership composes with the robot's identity and verifies
across the language SDKs. This is the open layer of the signed membership credential and its
verification; managed swarm orchestration and formation control are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, group membership tokens, and access-control lists each exist as
prior art. This disclosure does **not** claim those in the abstract. What is differentiated
is the reduction to a multi-robot swarm:

- **A coordinator-signed membership scoped to a named swarm of robots**, bound to a robot
  identity.
- **A role carried in the membership**, distinguishing a member's part in the swarm.
- **Membership that composes with a hardware-rooted robot identity**, so the boundary of a
  swarm is as verifiable as a single robot.

---

## 5. Technical Implementation

A reference implementation provides `build_swarm_membership` and `verify_swarm_membership`,
using the shared Data Integrity primitives so the same membership verifies across the
language SDKs.

---

## 6. Claims Summary

1. A method for swarm membership in which a coordinator signs a credential admitting a robot
   to a named swarm.
2. The method of claim 1 wherein the membership carries an optional role for the member in
   the swarm.
3. The method of claim 1 wherein verification confirms the membership is for a specific
   swarm under the coordinator's key.
4. The method of claim 1 wherein the member is a hardware-rooted robot identity, so swarm
   membership composes with the robot's identity.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same membership verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
