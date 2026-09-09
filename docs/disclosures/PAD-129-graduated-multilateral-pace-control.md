# PAD-129: Graduated Multilateral Pace Control

**Identifier:** PAD-129  
**Title:** Method for Graduated Multilateral Control of Autonomous Activity by Threshold-Signed Pace Epochs Carrying a Continuous Decay Rate, Where Every Outstanding Authority Grant Loses Effect at the Signed Rate Until Re-Anchored, So Coordination Adjusts a Rate Rather Than Actuating a Switch  
**Publication Date:** September 10, 2026  
**Prior Art Effective Date:** September 10, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Governance / Multilateral Coordination / Threshold Signing / Trust Decay  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-021 (Inverse Capability Protocol), PAD-068 (Kill-Switch Credential), PAD-117 (Connectivity-Scaled Autonomy Envelope), PAD-119 (Graded Trust Decay), PAD-046 (Algorithm Quorum)  

---

## 1. Abstract

Coordination proposals for autonomous systems offer a switch: run or halt. What
coordinating parties actually need is a dial, because a switch that no party dares pull is
not a control at all. This method supplies the dial. A quorum of holders drawn from
distinct governance domains threshold-signs a **pace epoch**: a small state object carrying
a monotonically increasing epoch number, a continuous decay rate, an effective time, and a
scope. Consumers of authority already compute effective trust as a decaying function of
time since the grant was anchored. The pace epoch sets the rate in that function. Raising
the rate shortens the half-life of every outstanding grant inside the scope at once, so
autonomy contracts smoothly everywhere without any grant being revoked and without any
system being stopped.

The quorum signs a state transition, not an identity credential, so nothing about the
issuance of identity moves into the quorum's hands. Because the shares are held across
distinct domains, no single holder can raise the rate, which removes the abuse case, and
no single holder can prevent the quorum from raising it, which removes the capture case.
Where the shares are combined by a threshold signature scheme over the same curve the
ecosystem already uses, the aggregate is an ordinary signature that every deployed verifier
accepts with no new verification path.

Key innovations:

- **A continuous rate as the coordination output**, so a multilateral body can apply
  graduated braking instead of choosing between inaction and a halt.
- **Effect through decay of existing grants rather than revocation**, so the control needs
  no enumeration of the systems it acts on and no delivery guarantee to each of them.
- **Threshold custody across distinct governance domains**, so the control is neither
  unilaterally actuatable nor unilaterally blockable.

---

## 2. Problem Statement

### 2.1 A halt is the only lever on offer

Existing coordination instruments describe stopping. Stopping is disproportionate to most
of the situations that would warrant a response, so the instrument is never used, and its
non-use is mistaken for the absence of a problem.

### 2.2 A control held by one party is either abusable or ignorable

A control that one participant may actuate alone will not be accepted by the others. A
control that any participant may block alone will not function when it is needed.

### 2.3 Revocation requires reaching every holder

A response implemented by revoking grants must enumerate and reach every outstanding
grant. Coverage is incomplete, propagation is slow, and the parties least likely to accept
the message are the ones the response most concerns.

### 2.4 Withdrawal of an authority is indistinguishable from silence

Where the coordination signal is a message that must arrive, its absence is ambiguous
between "nothing to say" and "the channel failed", and systems continue at full authority
in both cases.

---

## 3. Solution (The Invention)

**Pace epoch record.** The signed object carries: a monotonically increasing epoch number,
a decay rate parameter, an effective-from time, a scope descriptor naming the classes of
activity governed, and optionally per-class rate overrides. It carries no subject
identifier, because it modifies the evaluation of authority generally rather than the
standing of any particular holder.

**Threshold custody.** Shares are distributed among N holders selected from distinct
governance domains, with M required. Signing may be performed as M independent proofs
co-attached to the record, or aggregated by a threshold signature scheme producing a single
signature verifiable under a group public key by the ordinary verification path.

**Consumption.** A verifier evaluating any authority grant computes effective standing as a
decaying function of elapsed time since the grant's anchor, using the rate from the highest
epoch it holds whose effective time has passed and whose scope covers the activity.
Operations are gated by class-specific thresholds on effective standing, so raising the
rate first removes the highest-consequence operations, then the next class, and so on.
Contraction is therefore ordered by consequence without any per-operation instruction.

**Monotonicity and freshness.** Epoch numbers strictly increase, and a verifier never
regresses to a lower epoch, so an old, slower epoch cannot be replayed to restore
authority. A verifier that has not seen a new epoch within a declared interval treats the
absence as itself a reason to apply the more conservative of the last known rate and a
declared default, so silence contracts authority rather than preserving it.

**Re-anchoring.** Authority is restored by re-anchoring a grant, which requires a fresh
signature from the grant's own principal. Braking is therefore continuous and reversible by
ordinary operation rather than by a second emergency action, and the cost of a raised rate
is paid as a higher re-anchoring frequency rather than as an outage.

**Scoped application.** Scope descriptors allow the rate to apply to a class of activity,
for example autonomous development steps, without applying to unrelated activity under the
same identities.

---

## 4. Prior Art Differentiation

Threshold and multi-signature schemes, key revocation, certificate validity periods,
emergency stop credentials, and time-decaying trust are prior art. This disclosure does not
claim them. What is differentiated is:

- **A multilaterally signed continuous rate parameter as the coordination instrument**,
  producing graduated contraction of authority rather than a binary stop.
- **Acting on the evaluation function rather than on the grants**, so the control reaches
  every grant without enumerating or delivering to any of them.
- **Ordered contraction by consequence class** as an emergent property of thresholds on a
  decaying quantity, so the highest-consequence activity ceases first.
- **Treating a stale epoch as grounds for the more conservative rate**, so failure of the
  coordination channel contracts authority instead of preserving it.
- **Signing a scope-bearing state object with no subject**, so the quorum's power is
  confined to modifying evaluation and does not extend to issuing or withholding identity.

Emergency-stop credentials target a system and require delivery. Certificate revocation
lists enumerate subjects. Neither expresses a graduated rate, and neither takes effect on
grants the signer has never seen.

---

## 5. Technical Implementation

A reference implementation defines the pace epoch record and its canonical form, M-of-N
signing with independent co-attached proofs, epoch monotonicity and selection, the
effective-standing computation combining the epoch rate with an existing time-decay model,
consequence-class thresholds and their ordered contraction, staleness handling for a
missing epoch, and re-anchoring, all over `eddsa-jcs-2022` Data Integrity proofs and JCS
canonicalization.

---

## 6. Claims Summary

1. A method in which a quorum of holders from distinct governance domains threshold-signs a
   state record carrying a monotonically increasing epoch number and a continuous decay
   rate governing the evaluation of authority within a declared scope.
2. The method of claim 1 wherein a verifier computes the effective standing of an
   authority grant as a decaying function of elapsed time since anchoring, at the rate
   carried by the highest applicable epoch, without modifying or revoking the grant.
3. The method of claim 2 wherein operations are gated by consequence-class thresholds on
   effective standing, so raising the rate contracts authority in order of consequence.
4. The method of claim 1 wherein the record carries no subject identifier, so the quorum's
   authority is confined to modifying the evaluation of standing generally.
5. The method of claim 1 wherein epoch numbers strictly increase and a verifier does not
   regress to a lower epoch, so a prior slower rate cannot be replayed.
6. The method of claim 2 wherein a verifier that has not observed a current epoch within a
   declared interval applies the more conservative of the last known rate and a declared
   default.
7. The method of claim 2 wherein authority is restored by re-anchoring a grant with a fresh
   signature from its own principal, so a raised rate is paid as increased re-anchoring
   frequency rather than as an interruption.
8. The method of claim 1 wherein the quorum signatures are aggregated by a threshold
   signature scheme yielding a single signature verifiable by the ecosystem's ordinary
   verification path with no additional proof type.
9. The method of claim 1 wherein per-class rate overrides in the scope descriptor apply
   different rates to different classes of activity under the same identities.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented, to prevent
patenting by any party and to keep them available to the open Vouch Protocol ecosystem and
to the wider AI governance and verification communities.
