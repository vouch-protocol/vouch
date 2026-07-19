# PAD-118: Radiation- and Fault-Aware Key Attestation with Authority Narrowing on Integrity-Risk Events

**Identifier:** PAD-118  
**Title:** Method by Which a Node Attests Detected Integrity-Risk Events to Its Key Store — Radiation Dose, Single-Event Upsets, Memory Faults — and Automatically Narrows Its Authority or Triggers Key Re-Attestation When the Cumulative Risk Crosses a Threshold  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Hardware Trust / Key Management / Robotics / Space Systems  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-116 (Offline Threshold Key Continuity), PAD-117 (Connectivity-Scaled Autonomy), PAD-105 (Safety-Island Evidence Record)  

---

## 1. Abstract

A signing key held in hardware that is exposed to radiation or fault conditions — a
spacecraft in orbit, a robot near a reactor or an industrial radiation source — is at
risk of silent corruption: a single-event upset or memory fault can flip bits in the
key store or its computations, so a key believed intact may no longer be. This method
has a node attest, in a hash-linked signed record, the integrity-risk events it detects
(accumulated radiation dose, single-event-upset counts, memory-integrity faults) bound
to its identity, and automatically narrow its authority or trigger key re-attestation
when the cumulative risk crosses a threshold — so a node operating in a degrading
integrity environment provably tightens its own envelope before a corruption can cause a
trusted-but-wrong action.

Key innovations:

- **Key-store integrity risk as a signed, hash-linked attestation.** The node records
  the physical risk to its key material over time, bound to its identity, producing a
  tamper-evident integrity history.
- **Automatic authority narrowing on cumulative risk.** When attested risk crosses a
  threshold, the node's permitted authority narrows (or high-consequence actions are
  withheld) until its key integrity is re-established.
- **Re-attestation / rotation trigger.** Crossing a higher threshold triggers a key
  re-attestation or an offline threshold re-issuance, so a possibly-corrupted key is
  retired rather than trusted.

---

## 2. Problem Statement

### 2.1 A key can be silently corrupted by the environment

Radiation-induced upsets and memory faults can corrupt a key or its use without any
adversary. A node may keep signing with a key that is no longer the key it was
provisioned with, producing valid-looking but untrustworthy credentials.

### 2.2 Integrity risk is observable but unused

Spacecraft and hardened robots already monitor radiation dose and detect upsets, but
that signal is not connected to the trust the node's key is granted.

### 2.3 The response must be self-enforcing and provable

At the edge there is no operator to reduce a node's authority or force a key rotation,
and a later auditor needs proof of the integrity conditions under which the node acted.

---

## 3. Solution (The Invention)

The node maintains a hash-linked, signed integrity-risk attestation recording detected
events — cumulative dose, single-event-upset counts, ECC/memory-integrity faults —
each entry linked to the prior so the history is tamper-evident and bound to the node's
identity and hardware root (PAD-064). A deterministic rule maps cumulative attested risk
to authority: below a first threshold, full envelope; above it, a narrowed envelope
(withholding high-consequence or irreversible actions, composing with PAD-117); above a
second threshold, the node treats its key integrity as suspect and triggers
re-attestation of its key against the hardware root, or an offline threshold re-issuance
(PAD-116), retiring the possibly-corrupted key. A verifier can read the attested
integrity history to confirm the node operated within the envelope its key integrity
justified. The rule is deterministic and offline, so the node enforces its own
contraction with no live authority, and the safety subsystem's evidence record (PAD-105)
can seal the integrity stream.

---

## 4. Prior Art Differentiation

Radiation monitoring, ECC memory, TMR, and fault-tolerant computing are prior art. This
disclosure does **not** claim fault detection or radiation hardening. What is
differentiated is:

- **Binding detected key-store integrity risk into a signed, identity-bound attestation
  and using it as an input to authorization**, connecting a physical integrity signal to
  the trust a key is granted.
- **Deterministic authority narrowing and a key-re-attestation/rotation trigger on
  cumulative attested risk**, self-enforced offline.
- **A verifiable integrity history** so an auditor confirms the node acted within the
  envelope its key integrity justified.

Fault-tolerance techniques keep a computation correct or detect an error; they do not
attest integrity risk as an identity-bound credential input that narrows authorization
and triggers key retirement for a decentralized identity.

---

## 5. Technical Implementation

A reference design defines a hash-linked integrity-risk attestation (event type,
cumulative measure, identity and hardware-root binding), a deterministic risk-to-
authority rule composing with PAD-117, and a re-attestation/rotation trigger reusing
PAD-064 and PAD-116. Detection of dose and upsets is platform-specific; the open layer
is the attestation format and the risk-to-authority rule.

---

## 6. Claims Summary

1. A method by which a node records detected integrity-risk events to its key store as a
   hash-linked, identity-bound signed attestation.
2. The method of claim 1 wherein cumulative attested risk crossing a threshold
   deterministically narrows the node's permitted authority, offline.
3. The method of claim 1 wherein cumulative risk crossing a higher threshold triggers
   re-attestation of the node's key against its hardware root or an offline threshold
   re-issuance, retiring a possibly-corrupted key.
4. The method of claim 1 wherein a verifier reads the attested integrity history to
   confirm the node acted within the envelope its key integrity justified.
5. The method of claim 1 wherein the risk-to-authority mapping is deterministic and
   self-enforced with no live authority.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
