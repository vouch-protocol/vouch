# PAD-077: Cryptographic M-of-N Quorum Gating a High-Consequence Physical Robot Action

**Identifier:** PAD-077  
**Title:** Method for Authorizing a High-Consequence Physical Robot Action Only When M of N Attested Approvers Have Each Signed the Same Action, Counting Distinct Valid Approvers  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Multi-Party Authorization / Physical-World Credentials  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-022 (Swarm Limits Protocol), PAD-034 (Composite Threshold Swarm Consensus), PAD-066 (Physical Capability Scope), PAD-068 (Kill-Switch Credential)  

---

## 1. Abstract

A method for a cryptographic two-person rule, generalized to M of N, that gates a
high-consequence physical robot action. Before the robot is authorized to perform a
designated action (for example applying large force near a person, or an
irreversible move), M of N attested approvers must each sign an approval bound to
that specific action and that specific robot. A verifier authorizes the action only
when it counts at least M distinct, valid approvers from the attested set over the
same action.

Key innovations:

- **Approval bound to a specific physical action and robot.** Each approval names
  the action identifier and the robot DID, so an approval cannot be replayed onto a
  different action or a different machine.
- **Distinct-approver counting.** The verifier counts distinct approvers from the
  attested set, so one approver signing repeatedly cannot reach the threshold.
- **Composition with the physical safety system.** The quorum gate sits in front of
  a physical capability scope and a kill switch, so the highest-consequence actions
  require human or authority concurrence in addition to the standing envelope.

---

## 2. Problem Statement

### 2.1 Some physical actions are too consequential for a single authority

A robot action that can injure a person or cause irreversible physical change should
not proceed on one party's say-so. Industrial safety practice uses a two-person
rule; a robot needs a cryptographic equivalent that a verifier can check.

### 2.2 A plain approval can be replayed or forged

An approval that is not bound to the exact action and the exact robot can be reused
to authorize something it was never meant for. A single approver could also be made
to look like several.

---

## 3. Solution (The Invention)

`build_action_approval(...)` lets an approver issue a signed
`PhysicalActionApprovalCredential` naming the action identifier, the robot DID, and
the approver's decision, signed eddsa-jcs-2022. `verify_action_authorization(...)`
takes the set of collected approvals, the attested approver public keys, and a
threshold M, and authorizes the action only when at least M distinct approvers from
the attested set have each produced a valid approval over the same action and robot.
Approvals from outside the attested set, for a different action or robot, carrying a
reject decision, or with an invalid proof are ignored, and repeated approvals from
one approver count once.

---

## 4. Prior Art Differentiation

Threshold and M-of-N multi-party authorization are established prior art, including
this project's own swarm-consensus disclosures. This disclosure does **not** claim
threshold authorization in the abstract. What is differentiated is the binding to a
physical robot action:

- **Physical-action binding.** The quorum authorizes a named physical action on a
  named robot, not an abstract transaction, and sits in front of the robot's
  physical capability scope and kill switch.
- **Distinct-approver counting over the same action** as the admission rule, so
  duplicate signatures cannot reach the threshold.
- **Composition with the embodied safety primitives** (capability scope, kill
  switch), so the quorum is one gate in a physical-world accountability system.

---

## 5. Technical Implementation

A reference implementation provides `build_action_approval` and
`verify_action_authorization`, using the shared Data Integrity primitives so the
same approvals verify across the language SDKs. The approver set and threshold are
supplied by the deploying authority.

---

## 6. Claims Summary

1. A method for authorizing a high-consequence physical robot action only when M of
   N attested approvers have each signed an approval bound to the same action
   identifier and robot identifier.
2. The method of claim 1 wherein the verifier counts distinct approvers, so repeated
   approvals from a single approver count once toward the threshold.
3. The method of claim 1 wherein approvals from outside the attested set, for a
   different action or robot, carrying a reject decision, or with an invalid proof
   are excluded from the count.
4. The method of claim 1 wherein the quorum gate composes with a physical capability
   scope and a kill-switch credential for the same robot.
5. The method of claim 1 wherein the approvals use canonicalization and signature
   primitives shared across language SDKs, so they verify cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
