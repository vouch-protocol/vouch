# PAD-122: Byzantine Sensor Agreement via Cross-Checked Signed Perception Provenance

**Identifier:** PAD-122  
**Title:** Method by Which Peer Nodes Cross-Check Each Other's Signed Perception Provenance of an Overlapping Observation and Flag or Down-Weight a Node Whose Attested Perception Is Inconsistent With a Threshold of Independent Peers  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Perception Integrity / Swarm / Byzantine Fault Tolerance / Robotics  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-108 (Channel-Geometry Proof of Presence), PAD-110 (Swarm-Consensus Revocation), PAD-095+ (Perception Provenance), PAD-100 (Collective-Action Attestation)  

---

## 1. Abstract

Signed perception provenance lets a node prove what its sensors recorded. This method
uses that provenance *cross-node*: when several nodes observe an overlapping scene, each
signs its perception of the shared feature, and the group cross-checks the attestations,
flagging or down-weighting a node whose signed perception is inconsistent with a
threshold of independent peers. A node that reports a phantom obstacle, misses a real
one, or fabricates a reading is detected by disagreement with peers that saw the same
thing — turning a swarm into a Byzantine-fault-tolerant perception system where a lying
or failed sensor is caught by consensus, offline.

Key innovations:

- **Cross-node agreement over signed perception, not just self-provenance.** Each node's
  attested perception of a shared observation is compared against peers', so integrity is
  established by independent corroboration.
- **Byzantine detection of a lying or failed sensor.** A node inconsistent with a
  threshold of independent peers on an overlapping observation is flagged or
  down-weighted, tolerating a minority of faulty/malicious sensors.
- **Offline and identity-bound.** The cross-check runs among the nodes with no live
  authority, and each perception is bound to its node's identity, so a flagged
  disagreement is attributable.

---

## 2. Problem Statement

### 2.1 Self-provenance proves recording, not truth

A node can faithfully sign a fabricated or faulty reading; signed provenance proves *it
recorded this*, not *this is real*. A compromised or failed sensor's attestation looks
valid.

### 2.2 Overlapping observations are mutually constraining

When multiple nodes see the same feature, their perceptions should agree within
tolerance. Disagreement localizes a problem to a node, but only if the perceptions are
comparable and attributable.

### 2.3 The check must tolerate a faulty minority and run offline

A robust swarm must keep operating when a minority of sensors are wrong or adversarial,
and must decide this at the edge without a central referee.

---

## 3. Solution (The Invention)

Nodes observing an overlapping scene each publish a signed perception attestation of the
shared feature (a hash-linked record binding the observation, the node's identity, its
attested pose/position, and a common reference such as a scene nonce or timestamp). A
cross-check combines the attestations for the shared feature and computes agreement:
those consistent within tolerance form the corroborated set; a node whose attestation is
inconsistent with a threshold of independent peers is flagged or down-weighted for that
observation. Persistent or safety-relevant disagreement escalates to peer quarantine
(PAD-110). Peer independence and correct pose are corroborated via presence/location
(PAD-108/PAD-113), so a node cannot excuse a disagreement by misreporting where it stood.
The mechanism runs among the nodes offline and yields an attributable, evidence-bound
record of who disagreed with whom.

---

## 4. Prior Art Differentiation

Sensor fusion, voting/median filtering, and Byzantine agreement are prior art, including
this project's fused-perception provenance. This disclosure does **not** claim fusion or
BFT generally. What is differentiated is:

- **Cross-node agreement computed over signed, identity-bound perception provenance of an
  overlapping observation**, so a disagreement is attributable to a specific node and
  usable as trust evidence.
- **Byzantine detection/down-weighting of a lying or failed sensor by independent-peer
  corroboration, evaluated offline** among edge nodes with no central fusion authority.
- **Composition with presence/location and peer quarantine** (PAD-108/113/110), so pose
  is corroborated and persistent disagreement escalates.

Multi-sensor voting inside one connected system rejects outlier measurements; it does not
cross-check signed, identity-bound perception across independent nodes as attributable
trust evidence with escalation to revocation.

---

## 5. Technical Implementation

A reference design defines a shared-observation perception attestation (feature
reference, node identity, attested pose, scene nonce), a cross-check combiner computing
the corroborated set and flagging inconsistent nodes against a threshold, and an
escalation path to PAD-110. Pose corroboration reuses PAD-108/PAD-113. Feature
association is platform-specific; the open layer is the attestation format and the
agreement predicate.

---

## 6. Claims Summary

1. A method by which nodes observing an overlapping scene each sign a perception
   attestation of the shared feature and a cross-check flags a node inconsistent with a
   threshold of independent peers.
2. The method of claim 1 wherein each perception is bound to the node's identity and
   attested pose, so a disagreement is attributable.
3. The method of claim 1 tolerating a faulty or malicious minority of sensors by
   requiring agreement of a threshold of independent peers.
4. The method of claim 1 wherein a node's pose used in the comparison is corroborated by
   a presence or proof-of-location check.
5. The method of claim 1 wherein persistent or safety-relevant disagreement escalates to
   peer quarantine, evaluated offline among the nodes.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
