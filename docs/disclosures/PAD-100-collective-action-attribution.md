# PAD-100: Attribution of a Multi-Robot Collective Action to Its Participating Members

**Identifier:** PAD-100  
**Title:** Method for a Coordinator-Signed Collective-Action Attestation Whose Participants Are Each Checkable as Admitted Members of the Same Swarm  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Multi-Robot Systems / Accountability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-076 (Physical Quorum), PAD-099 (Verifiable Swarm Membership)  

---

## 1. Abstract

A method for attributing a physical action taken by a swarm of robots to the specific
members that performed it. A collective action attestation records the action, the swarm,
and the participating members, signed by the coordinator. Each participant can be checked
against a swarm membership signed by the same coordinator for the same swarm, so a
collective physical action ties only to admitted members and the coordinator that
authorized the group, rather than diffusing across an anonymous swarm.

Key innovations:

- **A collective physical action bound to its participants.** The attestation names the
  members that took part in a specific action, so a group action is attributable to the
  robots that performed it.
- **Participants checkable as admitted members.** Each participant is confirmed to hold a
  membership in the same swarm signed by the same coordinator, so an action cannot name a
  non-member as a participant.
- **The coordinator as the accountable authority.** The action and the memberships are both
  signed by the coordinator, so the authority behind the collective action is the same
  identity that admitted the members.

---

## 2. Problem Statement

### 2.1 A collective action has no attributable set of actors

When a swarm takes a physical action together, the responsibility diffuses across the
group, and there is no signed record binding the action to the specific robots that
performed it.

### 2.2 Naming participants is meaningless without membership

Listing participants in an action is only trustworthy if each named participant can be
confirmed to have been an authorized member of the swarm at the time.

---

## 3. Solution (The Invention)

`build_collective_action(...)` issues a `CollectiveActionAttestation` whose subject carries
the swarm identifier, the action, and the participants, signed eddsa-jcs-2022 by the
coordinator. `verify_collective_action(...)` checks the coordinator's proof and, when the
swarm memberships are supplied, that every participant holds a membership in the same swarm
signed by the same coordinator, returning the participants that lack a valid membership.
Because the memberships are coordinator-signed, they verify under the same coordinator key
as the action, so a single authority binds the group and the action. Because the credentials
use the shared JCS plus eddsa-jcs-2022 primitives, the same attestation verifies across the
language SDKs. This is the open layer of the signed collective-action attestation and the
membership check; managed swarm orchestration is out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, multi-party attestation, and this project's own physical-quorum work
each exist as prior art. This disclosure does **not** claim those in the abstract. What is
differentiated is the reduction to a multi-robot collective action:

- **A collective physical action bound to its participating members**, distinct from an
  M-of-N approval of a single action.
- **Participants confirmed as admitted members of the same swarm**, so an action cannot name
  a non-member.
- **A single coordinator authority** signing both the memberships and the action, so the
  group and the action share one accountable source.

---

## 5. Technical Implementation

A reference implementation provides `build_collective_action` and `verify_collective_action`,
which reconciles the participants against coordinator-signed memberships, using the shared
Data Integrity primitives so the same attestation verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for attributing a multi-robot collective action in which a coordinator signs an
   attestation naming the swarm, the action, and the participating members.
2. The method of claim 1 wherein each participant is confirmed to hold a swarm membership
   signed by the same coordinator for the same swarm.
3. The method of claim 2 wherein verification returns the participants that lack a valid
   membership.
4. The method of claim 1 wherein the memberships and the action are signed by one
   coordinator, so the group and the action share one accountable authority.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same attestation verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
