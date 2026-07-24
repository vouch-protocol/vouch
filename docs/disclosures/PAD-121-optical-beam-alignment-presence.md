# PAD-121: Narrow-Beam Optical Alignment as an Implicit Proof of Presence in a Trust Handshake

**Identifier:** PAD-121  
**Title:** Method by Which Successful Reception Over a Narrow-Beam Optical or Directional Link, Whose Geometry Only Closes When the Peer Physically Occupies the Pointed Direction, Is Bound Into a Trust Handshake as an Implicit Presence Factor  
**Publication Date:** July 19, 2026  
**Prior Art Effective Date:** July 19, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Proof of Presence / Physical-Layer Binding / Offline Verification / Space Systems  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-108 (Channel-Geometry Proof of Presence), PAD-113 (Distributed Proof of Location), PAD-015 (Ambient Witness Protocol)  

---

## 1. Abstract

A narrow-beam optical inter-satellite link (or any highly-directional link) only closes
when both terminals are physically pointed at each other along a known line of sight; a
node in a different direction simply cannot receive the beam. This method binds the fact
of *successful reception over a pointed narrow-beam link* into a trust handshake as an
implicit proof-of-presence factor: the pointing direction and the received nonce are
bound into the signed exchange, so a party that could not have been in the beam could not
have participated, without any ranging measurement. It complements measured-range
presence (PAD-108) with a geometry that is enforced by the physics of the channel itself.

Key innovations:

- **Directionality of the channel as a presence factor.** Reception over a narrow beam
  physically constrains the receiver to the pointed direction, which the handshake binds
  and signs.
- **No ranging instrument required.** Presence follows from link closure and pointing,
  so it works when time-of-flight or Doppler measurement is unavailable.
- **Composable with range and triangulation.** The pointing constraint (a direction) and
  a range measurement (a distance) together localize a peer more tightly than either
  alone.

---

## 2. Problem Statement

### 2.1 Omnidirectional links give no location constraint

A credential presented over an omnidirectional RF link could originate from anywhere in
range; the channel itself imposes no directional constraint on the presenter.

### 2.2 Ranging is not always available

Time-of-flight or Doppler measurement requires instrumentation and calibration that a
given terminal may lack, leaving no physical presence factor.

### 2.3 The physical constraint must be captured in the signed record

For the pointing constraint to have trust value, the direction and the exchange must be
cryptographically bound, or a later verifier cannot rely on it.

---

## 3. Solution (The Invention)

During a handshake over a narrow-beam optical or directional link, the terminals bind the
pointing geometry — the commanded/attested pointing direction (and beamwidth) of each
terminal — together with the handshake nonce into the signed exchange. Because the link
only closes when the peer physically occupies the pointed direction within the beamwidth,
a signed exchange that closed over the beam is evidence that the peer was in that
direction. A verifier checks the signatures and the bound pointing geometry and treats
successful closure over the declared narrow beam as a directional presence factor,
optionally combined with a range measurement (PAD-108) to localize the peer to a
direction-and-distance, or with multiple terminals (PAD-113) to triangulate. The factor
is evaluated offline from the signed record; the pointing/attitude solution is the
terminal's own.

---

## 4. Prior Art Differentiation

Free-space optical communication, directional antennas, and their inherent
low-probability-of-intercept geometry are prior art. This disclosure does **not** claim
directional links or FSO. What is differentiated is:

- **Binding successful narrow-beam link closure and the pointing geometry into a signed
  trust handshake as an explicit, offline-evaluable proof-of-presence factor** tied to a
  decentralized identity.
- **Deriving presence from channel directionality without a ranging measurement**, for
  terminals that lack ranging.
- **Composition with range and multi-terminal triangulation** to localize a peer to a
  direction, a distance, or a point.

Directional links provide interception resistance as a physical property; they do not
bind pointing geometry into a signed identity handshake as a verifiable presence factor.

---

## 5. Technical Implementation

A reference design adds a bound pointing-geometry field (direction, beamwidth, terminal
attitude reference) to the signed handshake, and a verifier predicate that treats signed
closure over a declared narrow beam as a directional presence factor, composable with
PAD-108 range and PAD-113 triangulation. Attitude/pointing acquisition is terminal-
specific; the open layer is the pointing-commitment format and the presence predicate.

---

## 6. Claims Summary

1. A method by which successful reception over a narrow-beam directional link is bound,
   together with the pointing geometry and a handshake nonce, into a signed trust
   exchange as a proof-of-presence factor.
2. The method of claim 1 wherein presence in a direction is established from link closure
   without a ranging measurement.
3. The method of claim 1 wherein the directional presence factor is combined with a range
   measurement to localize the peer to a direction and distance.
4. The method of claim 1 wherein multiple directional terminals combine to triangulate
   the peer's position.
5. The method of claim 1 wherein the pointing geometry is evaluated offline from the
   signed record with no live authority.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the delay-tolerant and robotics communities.
