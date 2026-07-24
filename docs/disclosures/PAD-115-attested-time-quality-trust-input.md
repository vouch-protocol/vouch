# PAD-115: Attested Time-Quality as an Input to Offline Trust Decisions

**Identifier:** PAD-115  
**Title:** Method by Which a Node Signs an Attestation of Its Own Clock Source and a Bounded Uncertainty, and a Verifier Admits Time-Dependent Trust Decisions Only When the Attested Time Uncertainty Is Within a Consequence-Scaled Bound  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Trust Inputs / Secure Time / Offline Verification / Delay-Tolerant Networking  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-016 (Heartbeat Protocol)  

---

## 1. Abstract

Offline trust decisions that depend on time — credential windows, staleness budgets
(PAD-106), freshness (PAD-107) — silently assume the verifier's clock is correct. A
node out of contact for a long period may hold a drifted or reset clock, which
invalidates that assumption exactly where it matters. This method makes *time quality
itself* an explicit, signed input: a node attests its clock source and a bounded time
uncertainty, and a verifier admits a time-dependent decision only when the attested
uncertainty is within a bound scaled to the consequence of the action, failing closed
(or falling back to epoch-based, clock-independent checks) when time quality is
insufficient.

Key innovations:

- **Clock quality as a first-class, signed trust input.** The uncertainty of the time a
  decision rests on is attested and checked, rather than assumed.
- **Consequence-scaled time-uncertainty budgets.** A high-consequence action requires
  tighter attested time than a routine one; when the budget is exceeded the decision
  fails closed or degrades to a clock-independent path.
- **Grounded in the same accountability model.** The time attestation is bound to the
  node's identity and hardware root, so a claimed "good clock" is itself accountable.

---

## 2. Problem Statement

### 2.1 Time-dependent trust rests on an unverified clock

Validity windows, staleness gates, and freshness all compare against "now." A
disconnected node's "now" may be wrong by an unknown amount, silently corrupting every
time-dependent decision.

### 2.2 Clock quality is not uniform or self-evident

A node disciplined by a recent trusted time source has very different time quality from
one running free for months on a low-grade oscillator, yet nothing in a normal decision
distinguishes them.

### 2.3 Some decisions can proceed under poor time; others cannot

A routine action may tolerate coarse time; an irreversible one should not proceed on a
clock that could be wildly wrong. The tolerance should track consequence.

---

## 3. Solution (The Invention)

A node signs a time-quality attestation binding: the clock source class (for example
GNSS-disciplined, chip-scale atomic clock, or free-running oscillator), the time since
last discipline, and a bounded time uncertainty derived from the source class and
elapsed free-run, all tied to the node's identity and hardware root. A verifier
performing a time-dependent decision reads the attested uncertainty and admits the
decision only if the uncertainty is within a bound scaled to the action's consequence.
When the uncertainty exceeds the bound, the verifier fails closed for consequential
actions, or falls back to clock-independent checks — monotonic network epochs (PAD-107)
and consequence-scaled staleness (PAD-106) — which do not depend on absolute time.
Because the attestation is identity- and hardware-bound, a node cannot cheaply claim a
better clock than it has.

---

## 4. Prior Art Differentiation

Secure time, roughtime, GNSS-disciplined clocks, and holdover specifications are prior
art. This disclosure does **not** claim time synchronization or holdover. What is
differentiated is:

- **Treating attested time uncertainty as an explicit, signed input to an offline
  identity/authorization decision**, rather than assuming a correct clock.
- **Consequence-scaled time-uncertainty budgets with fail-closed or clock-independent
  fallback**, so decisions degrade gracefully as time quality worsens.
- **Binding the time-quality claim to identity and a hardware root**, making a claimed
  clock quality accountable.

Time-security work establishes *how* to obtain or bound time; it does not make the
resulting uncertainty a signed, consequence-scaled gate on decentralized-identity
authorization decisions at a disconnected verifier.

---

## 5. Technical Implementation

A reference design defines a time-quality attestation (source class, since-discipline,
uncertainty bound, identity, hardware-root binding) and a verifier predicate that gates
time-dependent decisions on the attested uncertainty against a per-consequence budget,
falling back to PAD-106/PAD-107 epoch checks when time is too poor. Deriving the
uncertainty from a source class and holdover is standard; the open layer is the
attestation format and the consequence-scaled gate.

---

## 6. Claims Summary

1. A method by which a node signs an attestation of its clock source and a bounded time
   uncertainty, bound to its identity, and a verifier admits a time-dependent decision
   only when the attested uncertainty is within a consequence-scaled bound.
2. The method of claim 1 wherein, when the uncertainty exceeds the bound, a consequential
   decision fails closed.
3. The method of claim 1 wherein, when absolute time is insufficient, the decision falls
   back to a monotonic-epoch and consequence-scaled staleness path that does not depend
   on absolute time.
4. The method of claim 1 wherein the attested uncertainty is derived from a clock source
   class and the elapsed time since last discipline.
5. The method of claim 1 wherein the time-quality attestation is bound to a hardware root
   so a claimed clock quality is accountable.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
