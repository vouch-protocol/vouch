# PAD-123: Mutual-Attestation Mesh — A Live Offline Trust Graph Maintained by Pairwise Periodic Attestation

**Identifier:** PAD-123  
**Title:** Method by Which Peers in a Disconnected Cluster Maintain a Live Trust Graph Through Pairwise Periodic Attestations, So a Node's Standing Is Derived From Recent Corroboration by Its Neighbors and Decays When Attestation Lapses  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Trust Modeling / Swarm / Delay-Tolerant Networking / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-016 (Heartbeat Protocol), PAD-110 (Swarm-Consensus Revocation), PAD-111 (Quorum-of-Orbits Trust Anchoring), PAD-119 (Graded Trust Decay)  

---

## 1. Abstract

Where a single authority is unreachable, a disconnected cluster can still maintain a live
sense of who is currently trustworthy among itself. This method has peers periodically
sign pairwise attestations of each other — "I successfully authenticated and interacted
with peer X at epoch E" — forming a continuously-updated, signed trust graph. A node's
standing within the cluster is derived from recent corroboration by its neighbors and
decays when its attestations lapse, so a node that goes silent, fails, or is quarantined
loses standing without any central authority. It is the swarm-internal analogue of the
heartbeat: trust as a live signal, but sourced from peers rather than a validator.

Key innovations:

- **A peer-sourced live trust graph maintained offline.** Pairwise periodic attestations
  form an authenticated graph whose edges are recent corroborations, updated as the
  cluster operates.
- **Standing derived from recent neighbor corroboration, with decay.** A node's cluster
  standing rises with fresh attestations and decays when they lapse, so silence or
  failure automatically lowers standing.
- **Composes with quorum trust and peer revocation.** The graph feeds threshold decisions
  (PAD-111) and quarantine (PAD-110), and reuses graded decay (PAD-119) for edge aging.

---

## 2. Problem Statement

### 2.1 Without an authority, "who is currently trusted" is unknown

A disconnected cluster has no validator to renew trust, so a node's standing can go stale:
a failed or compromised node may still appear trusted to peers that have not re-checked
it.

### 2.2 A single self-heartbeat is not corroborated

A node attesting its own liveness proves nothing about whether peers still successfully
interact with it. Trust should be sourced from others.

### 2.3 The signal must be live and decay gracefully

Standing should reflect *recent* corroboration and fade smoothly when interaction lapses,
not flip on a single event.

---

## 3. Solution (The Invention)

Peers that successfully authenticate and interact sign pairwise attestations binding the
two identities, an outcome, and the epoch. Each node accumulates the attestations
involving its neighbors, forming a signed trust graph whose edges carry epochs. A node's
cluster standing is computed from the freshness and breadth of its incoming attestations —
recent corroboration from multiple distinct neighbors yields high standing; lapsed or
absent attestations decay it (using the graded-decay curve of PAD-119). Standing feeds
cluster decisions: a threshold decision (PAD-111) can require corroborating signers of
sufficient standing, and a node whose standing collapses (silence, failure) or that is
flagged by distress (PAD-110) is treated as untrusted, all offline. Because edges are
signed and epoch-stamped, the graph is auditable and cannot be fabricated by a node about
itself.

---

## 4. Prior Art Differentiation

Web-of-trust, gossip reputation, and liveness heartbeats (including this project's
PAD-016) are prior art. This disclosure does **not** claim web-of-trust or heartbeats
generally. What is differentiated is:

- **A live, epoch-edged, signed trust graph maintained by pairwise periodic attestation
  within a disconnected cluster**, where standing is recent-corroboration-derived and
  decays, rather than a static web-of-trust or a self-sourced heartbeat.
- **Peer-sourced standing feeding offline threshold and quarantine decisions**
  (PAD-111/PAD-110), so cluster trust is corroborated, not self-declared.
- **Graceful decay of graph edges** (PAD-119), so standing reflects current interaction.

Web-of-trust builds a mostly-static endorsement graph; this maintains a decaying,
epoch-stamped interaction graph offline as the live trust substrate for a disconnected
cluster.

---

## 5. Technical Implementation

A reference design defines a pairwise interaction attestation (both identities, outcome,
epoch), a per-node standing function over incoming attestations using PAD-119 decay, and
hooks into PAD-111 threshold decisions and PAD-110 quarantine. The open layer is the
attestation format and the standing computation.

---

## 6. Claims Summary

1. A method by which peers in a disconnected cluster sign pairwise periodic attestations
   of successful interaction, forming a signed, epoch-edged trust graph.
2. The method of claim 1 wherein a node's cluster standing is derived from the freshness
   and breadth of incoming attestations and decays when they lapse.
3. The method of claim 1 wherein a node that goes silent or fails loses standing with no
   central authority.
4. The method of claim 1 wherein standing feeds an offline threshold decision that
   requires corroborating signers of sufficient standing.
5. The method of claim 1 wherein the graph edges decay by a graded curve and a
   distress-flagged node is treated as untrusted.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
