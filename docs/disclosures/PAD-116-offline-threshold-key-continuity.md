# PAD-116: Offline Threshold Key Continuity and Re-Issuance for Long-Duration Autonomous Missions

**Identifier:** PAD-116  
**Title:** Method by Which a Threshold of Attested Peers Jointly Rotates or Re-Issues a Mission Credential Under a Pre-Delegated Authority When the Home Authority Is Unreachable, Preserving Verifiable Identity Continuity Across the Rotation  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Key Management / Threshold Cryptography / Delegation / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-110 (Swarm-Consensus Revocation), PAD-111 (Quorum-of-Orbits Trust Anchoring), PAD-034 (Composite Threshold Swarm Consensus), PAD-016 (Heartbeat Protocol)  

---

## 1. Abstract

A method by which a group of attested peer nodes can rotate or re-issue a mission
credential — because a key is aging out, is suspected compromised, or a node's hardware
must be replaced — **without the home authority**, using a threshold authority the
authority pre-delegated to the group before the mission went out of contact. A
threshold M of N attested members jointly authorize the new credential and record a
continuity link to the superseded one, so a later verifier confirms both that the
rotation was authorized (by the pre-delegated threshold) and that the same accountable
mission identity persisted across it. This keeps a decade-long or deep-space mission's
identity alive and rotatable across events the ground authority cannot reach in time.

Key innovations:

- **Pre-delegated threshold authority for offline key rotation.** The authority grants,
  in advance, a threshold of mission peers the right to rotate or re-issue a credential,
  so continuity does not require the authority to be reachable at rotation time.
- **Verifiable identity continuity across the rotation.** The new credential carries a
  continuity link the pre-delegated threshold signs, so a verifier proves the same
  identity persisted and the rotation was authorized.
- **Bounded to rotation, not new authority.** The threshold may only preserve or narrow
  the existing authority across a key change; it cannot grant the mission new powers,
  containing the risk of the delegated capability.

---

## 2. Problem Statement

### 2.1 Keys must rotate, but the authority may be unreachable for years

A long-duration or deep-space mission will need to rotate a key (aging, suspected
compromise, hardware swap) at a time when the ground authority cannot be reached within
the required window. A rotation that requires the authority stalls the mission or forces
it to keep using a key it should retire.

### 2.2 Ad-hoc self-rotation breaks continuity and trust

A node that simply mints a new key on its own produces a credential no verifier can tie
back to the authorized mission identity, and gives a compromised node a way to
"launder" itself into a fresh identity.

### 2.3 The rotation power must be contained

Any delegated authority to change keys is dangerous if it can also widen the mission's
powers. It must be limited to preserving or narrowing existing authority.

---

## 3. Solution (The Invention)

Before the mission goes out of contact, the home authority issues a pre-delegation: a
threshold M-of-N grant to named, attested mission members authorizing them to jointly
rotate or re-issue *this* mission credential, bounded so the resulting credential may
only preserve or narrow the existing authority. When rotation is needed offline, a
threshold of the attested members each sign the new credential, which carries a
continuity link (a supersedes reference and, where used, a key-history entry) to the
retired credential. A verifier checks that (a) the pre-delegation authorized the group,
(b) at least the threshold of distinct attested members signed the rotation, and (c) the
continuity link ties the new credential to the prior authorized identity. Membership and
attestation reuse the swarm/hardware-identity layer; independence of the threshold
signers can be required across distinct failure domains (PAD-111); a compromised member
is handled by peer quarantine (PAD-110) and does not by itself reach the threshold.

---

## 4. Prior Art Differentiation

Threshold signatures, DKG, key rotation, and social recovery are prior art, including
this project's threshold consensus (PAD-034). This disclosure does **not** claim
threshold signing or key rotation generally. What is differentiated is:

- **Pre-delegated, authority-bounded threshold rotation performed entirely offline by
  mission peers** when the home authority is unreachable, specifically to preserve a
  mission identity across a key change.
- **A verifiable continuity link across the offline rotation**, so a later verifier
  proves the same accountable identity persisted and the rotation was authorized, not
  self-minted.
- **Containment to preserve-or-narrow authority**, so the delegated rotation power
  cannot widen the mission's capabilities.

Social-recovery and threshold-custody schemes restore access to an account; they do not
provide an authority-pre-delegated, capability-bounded, continuity-preserving credential
rotation executed by attested peers offline for an autonomous mission.

---

## 5. Technical Implementation

A reference design defines a pre-delegation grant (named members, threshold, target
credential, preserve-or-narrow bound), a threshold-signed re-issuance carrying a
supersedes/continuity link, and a verifier check over authorization, threshold, and
continuity. Threshold signing and attested membership reuse existing primitives; signer
independence reuses PAD-111; compromised-member handling reuses PAD-110. The open layer
is the pre-delegation and continuity formats and the verifier predicate.

---

## 6. Claims Summary

1. A method by which a threshold of attested mission peers jointly rotates or re-issues a
   mission credential under authority pre-delegated by the home authority, with no
   contact to that authority at rotation time.
2. The method of claim 1 wherein the re-issued credential carries a continuity link a
   verifier uses to confirm the same accountable identity persisted across the rotation.
3. The method of claim 1 wherein the pre-delegated authority permits the re-issued
   credential only to preserve or narrow the existing authority, never to widen it.
4. The method of claim 1 wherein the threshold signers are required to span distinct
   independent domains, and a compromised member does not by itself reach the threshold.
5. The method of claim 1 wherein a verifier admits the rotation only on confirming the
   pre-delegation authorized the group, the threshold of distinct members signed, and the
   continuity link holds.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
