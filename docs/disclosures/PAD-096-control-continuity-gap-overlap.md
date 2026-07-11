# PAD-096: Detecting an Unattributed-Control Gap or a Dual-Control Overlap in a Robot's Control Timeline

**Identifier:** PAD-096  
**Title:** Method for Verifying That a Robot's Control Timeline Is Continuous and Single-Held, Detecting a Moment With No Attributed Controller or Two Controllers at Once  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Teleoperation / Accountability  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-082 (Portable Agent Identity Fork Detection), PAD-095 (Control-Authority Handoff Chain)  

---

## 1. Abstract

A method for confirming that control of a robot was continuous and held by exactly one
controller at a time. Each control handoff names the controller it took over from. This
method checks that every handoff after the first begins where the previous one left off,
so there is no moment with no attributed controller (a gap where authority is
unaccounted for) and no moment with two controllers claiming authority across the seam (an
overlap). A seam whose releasing controller is not the previous receiving controller is
reported, so a control timeline that silently dropped or double-counted authority is
detected rather than assumed clean.

Key innovations:

- **Single-authority invariant over a control timeline.** The check enforces that control
  is held by exactly one controller at every moment, the control analogue of a
  single-body constraint on a portable identity.
- **Gap and overlap named at the seam.** A discontinuity is returned as the specific seam
  where the releasing controller does not match the previous receiving controller, so the
  unaccounted moment is localized.
- **Layered on the signed handoff chain.** Because each handoff is signed, the continuity
  check runs over authenticated transfers, so a detected gap or overlap is attributable.

---

## 2. Problem Statement

### 2.1 A verified chain can still hide a control gap

A chain of signed handoffs can each verify individually while the sequence still contains
a moment where no controller held authority, or where a new controller claimed it while
the previous one had not released, and nothing flags that discontinuity.

### 2.2 Gaps and overlaps are exactly the liability-sensitive moments

The moment with no attributed controller, or with two, is where responsibility for an
incident is most contested. There is no method that isolates those moments from the
transfer record.

---

## 3. Solution (The Invention)

`check_control_continuity(...)` walks an ordered list of control handoffs and confirms
each handoff after the first begins where the previous one left off, that is, its
releasing controller is the previous receiving controller. A link whose releasing
controller does not match is reported both as a gap (the previous controller's authority
is left unaccounted for across the seam) and as an overlap (a new controller claims
authority the previous one had not released), and the offending seam is returned with the
expected and found controllers. Combined with the signed handoff chain of PAD-095, this
confirms both that transfers are authentic and that the control timeline is continuous and
single-held. Because the handoffs use the shared JCS plus eddsa-jcs-2022 primitives, the
same check runs across the language SDKs. This is the open layer of a software continuity
check over signed transfers; enforcement mechanisms that prevent a gap in hardware are out
of scope.

---

## 4. Prior Art Differentiation

Interval reconciliation, chain-of-custody continuity, and this project's own embodiment
fork detection each exist as prior art. This disclosure does **not** claim those in the
abstract. What is differentiated is the reduction to a robot's control timeline:

- **A single-authority invariant over control of a robot**, distinct from a
  single-body invariant over an identity.
- **Naming a gap and an overlap at the specific seam** in the control record.
- **Continuity layered on signed control handoffs**, so a detected discontinuity is
  attributable.

---

## 5. Technical Implementation

A reference implementation provides `check_control_continuity`, which reconciles adjacent
handoffs in a control chain and returns any seam that breaks the single-authority
invariant, using the shared primitives so the same check runs across the language SDKs.

---

## 6. Claims Summary

1. A method for verifying a robot's control timeline in which each control handoff after
   the first is required to begin where the previous one left off, so control is held by
   exactly one controller at every moment.
2. The method of claim 1 wherein a discontinuity is reported as a gap where the previous
   controller's authority is unaccounted for and as an overlap where a new controller
   claims authority not yet released.
3. The method of claim 2 wherein the offending seam is returned with the expected and
   found controllers.
4. The method of claim 1 wherein the check runs over signed control handoffs, so a
   detected discontinuity is attributable.
5. The method of claim 1 wherein the primitives are shared across language SDKs, so the
   same check runs cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented, to
prevent patenting by any party and to keep them available to the open Vouch Protocol
ecosystem and the robotics community.
