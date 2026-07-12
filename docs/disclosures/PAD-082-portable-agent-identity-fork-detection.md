# PAD-082: Fork Detection for a Portable Agent Identity via Embodiment Time-Overlap

**Identifier:** PAD-082  
**Title:** Method for Detecting a Forked Portable Agent Identity by Confirming No Two Embodiment Credentials Place the Agent in Different Robot Bodies With Overlapping Active Time Windows  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Embodied Agents / Identity Integrity  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-081 (Cross-Embodiment Identity Continuity), PAD-064 (Hardware-Rooted Robot Identity)  

---

## 1. Abstract

A method for detecting a fork of a portable agent identity: the same accountable
agent active in two robot bodies at once. Each embodiment credential is active over a
time window (from its `validFrom` to its `validUntil`, an absent end meaning
open-ended). The method confirms no two embodiments place the agent in different
bodies with overlapping active windows. A clean handover sets one body's window to
end where the next begins, so there is no overlap; two bodies active at the same
instant are reported as a fork.

Key innovations:

- **Time-overlap fork rule for a portable identity.** A fork is defined as two
  embodiment credentials for the same agent on different bodies whose active windows
  overlap, so a single mind cannot be validly embodied in two bodies at once.
- **Half-open windows that make a clean handover unambiguous.** Treating each active
  window as half-open, and an absent end as open-ended, means a handover that ends one
  window exactly where the next begins does not overlap, while a lingering or
  open-ended second body does.
- **Composes with the continuity chain.** The same embodiment credentials that form
  the continuity chain are the input to the fork check, so continuity and
  non-duplication are checked over one set of credentials.

---

## 2. Problem Statement

### 2.1 A portable mind could be duplicated across bodies

If an agent identity can move between bodies, the core integrity risk is duplication:
the same accountable identity running on two bodies at the same time, so an action
cannot be attributed to one machine. A continuity chain proves the mind moved, but
does not by itself rule out that it was in two places at once.

### 2.2 A clean handover must be distinguishable from a fork

A legitimate handover, where the mind leaves one body as it enters the next, looks
superficially like two embodiments on two bodies. A method needs to distinguish that
from a genuine overlap.

---

## 3. Solution (The Invention)

`check_no_fork(...)` takes a set of embodiment credentials and treats each as active
over the half-open interval from its `validFrom` to its `validUntil`, with an absent
`validUntil` meaning open-ended. For every pair of embodiments on different bodies it
tests whether the intervals overlap; any overlap is reported as a fork naming the two
conflicting bodies. Because the windows are half-open, a handover that ends one body's
window exactly at the next body's start does not overlap and passes, while a second
body that is still active, or open-ended, when another begins is caught. The check
runs over the same embodiment credentials that form the continuity chain, so a
verifier confirms both that the agent persisted and that it was never duplicated.

---

## 4. Prior Art Differentiation

Interval-overlap tests and double-spend or double-use detection each exist as prior
art. This disclosure does **not** claim interval comparison in the abstract. What is
differentiated is the application to a portable agent identity across robot bodies:

- **The fork definition for an embodied mind**, that a single agent identity is
  invalidly embodied when its active windows overlap on different bodies.
- **Half-open windows tuned to embodiment handover**, so a clean handover is a
  non-overlap and a lingering or open-ended second body is a fork.
- **Composition with the embodiment continuity chain**, so the same credentials prove
  persistence and non-duplication together.

---

## 5. Technical Implementation

A reference implementation provides `check_no_fork` over the same
`AgentEmbodimentCredential` set used by the continuity chain, returning the two
conflicting bodies on a fork.

---

## 6. Claims Summary

1. A method for detecting a fork of a portable agent identity by confirming that no
   two embodiment credentials place the agent in different robot bodies with
   overlapping active time windows.
2. The method of claim 1 wherein each active window is half-open and an absent end is
   treated as open-ended, so a handover that ends one window where the next begins is
   not a fork.
3. The method of claim 1 wherein a detected fork names the two conflicting bodies.
4. The method of claim 1 wherein the fork check runs over the same embodiment
   credentials that form the identity continuity chain.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
