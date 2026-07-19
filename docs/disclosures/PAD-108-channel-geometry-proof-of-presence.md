# PAD-108: Channel-Geometry Proof of Presence as a Freshness Factor in Decentralized-Identity Handshakes

**Identifier:** PAD-108  
**Title:** Method for Binding a Decentralized-Identity Trust Handshake to a Measured Physical-Channel Geometry Predicate — Signal Time-of-Flight, Doppler Shift, or Two-Way Range — So a Credential Replayed From a Different Physical Location Fails Verification  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Anti-Replay / Proof of Presence / Physical-Layer Binding / Offline Verification  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-106 (Bounded-Staleness Revocation), PAD-107 (Presenter Proof of Freshness), PAD-015 (Ambient Witness Protocol), PAD-039 (Deterministic Multi-Party Trust State)  

---

## 1. Abstract

A method for fusing a *measured physical-channel geometry predicate* into a
decentralized-identity (DID) and Verifiable Credential trust handshake, so that
proof of *who* a peer is becomes inseparable from proof of *where* it is. During the
handshake, the verifying node measures a property of the physical link that is a
function of the peer's location and motion — one-way signal time-of-flight, round-
trip range, or Doppler shift on an RF or optical inter-node link — and admits the
peer only if the measured value agrees, within tolerance, with a claimed or
independently-known position and velocity bound into the signed exchange. A valid
credential captured and replayed from a different physical location, orbit, or
vehicle fails the geometry check, because the attacker cannot reproduce the victim's
channel geometry from where it actually is.

Key innovations:

- **Physical-channel geometry as a signed freshness and presence factor.** The
  handshake binds a signed nonce to a measured time-of-flight, range, or Doppler
  value, making replay from another location detectable without any shared secret or
  live authority.
- **Applicable to fully disconnected peers.** The check is made locally by the
  verifying node from its own measurement, with no connection to a ground station or
  registry, so it works at the disconnected edge where other anti-replay anchors are
  unavailable.
- **Composes with identity and consequence.** The geometry predicate is one factor
  alongside credential verification (identity) and consequence-scaled freshness
  (PAD-106/107), so a high-consequence action can require a tighter geometry
  tolerance than a routine one.

---

## 2. Problem Statement

### 2.1 A signed credential does not prove physical presence

A DID handshake proves key possession. It does not prove the counterpart is where it
claims to be. A captured, unexpired credential can be presented from anywhere,
including from a spoofing platform impersonating a legitimate node.

### 2.2 Disconnected nodes lack a live anti-replay anchor

Standard anti-replay relies on a live server, a synchronized clock, or a fresh
challenge from a trusted third party. A node in orbit, under water, or underground
has none of these at decision time, so replay and impersonation are harder to
detect exactly where the stakes (physical maneuvers, docking, formation flight) are
highest.

### 2.3 Location claims are themselves forgeable

A peer can simply assert a false position in a signed message. Without an
independent physical measurement, the verifier has no way to test the claim.

---

## 3. Solution (The Invention)

The trust handshake is extended so that, during the exchange, the verifying node
measures a geometry-dependent property of the physical channel to the peer and binds
it into the signed protocol:

- **Time-of-flight / range.** The verifier issues a signed challenge and measures the
  elapsed time to a signed response; the derived range must agree with the peer's
  claimed or known position relative to the verifier, within a tolerance set by
  measurement precision and the action's consequence.
- **Doppler.** The verifier measures the frequency shift on the peer's carrier; the
  derived relative velocity must agree with the peer's claimed or known velocity.

The measured value, the claimed position/velocity, and the handshake nonce are bound
together and signed, so the record is both attributable and location-committed. A
credential replayed from a different platform produces a measurement inconsistent
with the victim's committed geometry and is rejected. The predicate is evaluated
entirely by the verifying node from its own instrument, requiring no live authority,
and is layered on top of ordinary DID/VC verification: identity, presence, and
consequence-scaled freshness are checked together.

---

## 4. Prior Art Differentiation

Distance-bounding protocols, secure ranging, and Doppler/time-of-flight measurement
are established prior art in RFID, UWB, GNSS, and radar. This disclosure does **not**
claim those measurement techniques themselves. What is differentiated is:

- **Fusing a measured channel-geometry predicate into a DID/Verifiable-Credential
  trust handshake** as a signed presence-and-freshness factor, rather than treating
  ranging and identity as separate layers.
- **Evaluation by a fully disconnected verifier** with no live authority, for
  inter-node links at the edge (inter-satellite RF or optical, acoustic subsea,
  through-rock RF), as an anti-replay anchor where clocks and servers are
  unavailable.
- **Consequence-scaled geometry tolerance**, so the strictness of the presence check
  tracks the consequence of the action, composing with PAD-106 and PAD-107.

Prior distance-bounding establishes proximity between two connected devices; it does
not bind the measured geometry into a portable, signed DID handshake decision made
by a disconnected verifier alongside credential identity and consequence-scaled
freshness.

---

## 5. Technical Implementation

A reference design adds, to the existing signed three-message handshake, an optional
geometry-commitment field carrying the verifier's measured range or Doppler, the
peer's claimed position/velocity, and a tolerance, all covered by the handshake
signatures. Measurement acquisition is platform-specific (the radio, laser terminal,
or acoustic modem); the open layer is the commitment format and the verifier's
accept/reject predicate. When no measurement is available the field is absent and the
handshake degrades to identity-and-freshness only, disclosed as such.

---

## 6. Claims Summary

1. A method for a trust handshake between decentralized-identity holders wherein the
   verifying party measures a geometry-dependent property of the physical channel to
   the counterpart and admits the counterpart only if the measurement agrees, within
   tolerance, with a position or velocity bound into the signed exchange.
2. The method of claim 1 wherein the measured property is one-way signal time-of-
   flight, round-trip range, or Doppler shift on an inter-node radio-frequency or
   optical link.
3. The method of claim 1 wherein a credential presented from a physical location
   inconsistent with the committed geometry is rejected, providing anti-replay and
   anti-impersonation without a shared secret or a live authority.
4. The method of claim 1 wherein the measurement, the claimed position or velocity,
   and a handshake nonce are bound together and signed, producing a location-
   committed, attributable record.
5. The method of claim 1 wherein the tolerance applied to the geometry check is
   scaled to the consequence of the requested action and composed with credential
   identity verification and consequence-scaled freshness bounding.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
