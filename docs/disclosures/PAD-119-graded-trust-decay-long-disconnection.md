# PAD-119: Graded Continuous Trust Decay for Long-Duration Disconnection

**Identifier:** PAD-119  
**Title:** Method by Which a Verifier Assigns a Continuously-Decaying Trust Weight to a Presented Credential as a Function of Time Since Last Trusted Contact and Admits an Action Only When the Weight Meets a Consequence-Scaled Threshold  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Trust Modeling / Delay-Tolerant Networking / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-016 (Heartbeat Protocol), PAD-117 (Connectivity-Scaled Autonomy)  

---

## 1. Abstract

Bounded-staleness (PAD-106) and connectivity-scaled autonomy (PAD-117) use stepped
thresholds. For very long disconnection — deep-space transits measured in months — a
hard step can be too blunt. This method assigns a *continuously* decaying trust weight
to a credential as a function of time since last trusted contact, using a declared decay
curve, and admits an action only when the decayed weight meets a threshold scaled to the
action's consequence. Trust becomes a smooth, computed quantity that erodes with
disconnection and is renewed on contact, rather than a binary valid/invalid.

Key innovations:

- **Continuous decay, not a step.** A declared curve (for example exponential with a
  per-credential half-life) yields a smooth trust weight over long disconnection.
- **Consequence-scaled admission threshold.** A high-consequence action requires a
  higher remaining weight, so it becomes impermissible earlier than a routine one as
  trust decays.
- **Renewal resets the weight.** An in-contact renewal restores the weight, so the
  curve models "trust that must be refreshed" over mission timescales.

---

## 2. Problem Statement

### 2.1 Stepped staleness is coarse over long horizons

A small number of thresholds cannot express the gradual erosion of confidence over a
months-long transit; either the steps are too few (a cliff) or too many (unmanageable).

### 2.2 Different actions should cross the line at different times

As confidence erodes, consequential actions should become impermissible before trivial
ones, which a single validity flag cannot express.

### 2.3 The weight must be computed offline and deterministically

Every verifier, disconnected, must compute the same weight from the same inputs so the
decision is reproducible and auditable.

---

## 3. Solution (The Invention)

A credential (or the authority's policy) declares a decay curve — for example an
exponential with a stated half-life, or a piecewise-linear ramp — parameterized in
monotonic epochs since last trusted contact (PAD-107). At decision time the verifier
computes the decayed trust weight from the elapsed epochs and admits the action only if
the weight meets a threshold scaled to the action's consequence. An in-contact renewal
(a fresh session voucher / heartbeat, PAD-016) resets the last-contact marker and hence
the weight. The computation is deterministic and offline, so all verifiers agree, and the
result is auditable (the weight and threshold are recorded with the decision). The curve
generalizes PAD-106's stepped budgets (a step curve is a special case) and can drive
PAD-117's envelope selection continuously.

---

## 4. Prior Art Differentiation

Trust decay, reputation aging, and time-decay weighting are prior art, including this
project's trust-entropy in the heartbeat model. This disclosure does **not** claim decay
weighting generally. What is differentiated is:

- **A declared, per-credential decay curve over monotonic epochs used as an offline
  admission gate at a disconnected verifier**, with the threshold scaled to the action's
  consequence.
- **Deterministic, reproducible computation across all verifiers**, so the decayed
  weight is auditable rather than a local heuristic.
- **Unification with stepped staleness and envelope selection** (PAD-106/PAD-117) as the
  continuous generalization of both.

Reputation-aging systems decay a score in a connected store for ranking; they do not
provide a per-credential decay curve evaluated offline as a consequence-scaled
authorization gate on mission timescales.

---

## 5. Technical Implementation

A reference design carries a decay-curve parameter set (form and half-life/ramp) on a
credential or policy, and a verifier function computing the decayed weight from elapsed
epochs and gating on a per-consequence threshold. Renewal reuses PAD-016; epochs reuse
PAD-107. The open layer is the curve parameterization and the gate.

---

## 6. Claims Summary

1. A method by which a verifier computes a continuously-decaying trust weight for a
   credential from time since last trusted contact using a declared curve and admits an
   action only if the weight meets a consequence-scaled threshold.
2. The method of claim 1 wherein the curve is parameterized in a monotonic epoch counter
   so the weight is well-defined without a trusted wall-clock.
3. The method of claim 1 wherein an in-contact renewal resets the last-contact marker and
   restores the weight.
4. The method of claim 1 wherein the computation is deterministic so all disconnected
   verifiers compute the same weight, and the weight and threshold are recorded for audit.
5. The method of claim 1 wherein a stepped staleness budget is a special case of the
   curve and the weight drives a continuous authority-envelope selection.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
