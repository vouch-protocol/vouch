# PAD-070: Self-Contained, Offline-Verifiable Robot Passport for Physical-World Scanning

**Identifier:** PAD-070  
**Title:** Method for a Self-Contained Robot Passport Encoded into a Scannable (QR/NFC) URI Carrying the Full Signed Credential, Conveying Owner, Authorized Physical Actions, Certification, and Live Standing, Verifiable Offline  
**Publication Date:** June 15, 2026  
**Prior Art Effective Date:** June 15, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Offline Verification / Physical-World Credentials / QR-NFC  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-066 (Physical Capability Scope), PAD-069 (Robot Black-Box)  

---

## 1. Abstract

A method for a robot "passport": a compact signed Verifiable Credential conveying
a robot's identity, owner, authorized physical actions, certification, and current
operational standing (active, suspended, or decommissioned), encoded into a
scannable URI (a `vouch-passport:` URI carrying the multibase canonical bytes of
the credential) so that any bystander or inspector can scan a QR code or NFC tag
and verify the credential's signature and contents **fully offline**, with no
network round-trip and no issuer lookup at scan time.

Key innovations:

- **Self-contained scannable credential for an embodied agent.** The QR/NFC
  payload carries the entire signed credential, not a URL to be resolved, so a
  person can verify a physical robot on the spot with no connectivity.
- **Embodied-agent passport semantics.** The credential subject is robot-specific:
  owner, the **authorized physical actions** the robot may perform, certification,
  and a live **standing** field, so the scan answers "is this robot legitimate,
  whose is it, what may it do, and is it currently in good standing."
- **Composition with the robot identity and capability system.** The passport is
  built on the same credential format as hardware-rooted robot identity (PAD-064)
  and physical capability scope (PAD-066), so a passport composes with, and can be
  cross-checked against, those credentials rather than standing alone.

---

## 2. Problem Statement

### 2.1 No on-the-spot, offline trust check for a physical robot

A person who encounters a robot in a warehouse, a hospital corridor, or a public
space has no reliable way to check, on the spot, whether it is legitimate, who is
responsible for it, what it is permitted to do, and whether it is currently
certified and active. Connectivity may be absent exactly where the check is needed.

### 2.2 URL-bearing codes centralize trust and fail offline

A QR code that encodes a URL requires a network fetch and a trusted server to
return an answer. That fails with no connectivity and concentrates trust in a
single endpoint that can be down, spoofed, or retired.

### 2.3 Physical plates and labels are forgeable

A printed serial plate or sticker carries no cryptographic proof of issuer or
content and is trivially copied onto an impostor unit.

---

## 3. Solution (The Invention)

`build_passport(...)` issues a `RobotPassport` Verifiable Credential whose subject
carries the robot DID, make, model, owner, `authorizedActions`, `status`
(active/suspended/decommissioned), and optional certification, signed
eddsa-jcs-2022 by the robot or an authority. `encode_passport(...)` serializes it:

```
vouch-passport:u<base64url( JCS(passport credential) )>
```

The full signed credential travels inside the code. An offline reader runs
`decode_passport(uri)` then `verify_passport(...)`, which checks the Data Integrity
proof and validity window using only the issuer's public key (resolved or cached
out of band). No network call is made at scan time. Rendering the URI to a QR image
or writing it to an NFC tag is left to any standard QR/NFC library. Because the
credential uses the shared JCS plus eddsa-jcs-2022 primitives, the same passport
verifies across the language SDKs.

---

## 4. Prior Art Differentiation

Encoding a signed Verifiable Credential into a QR code for offline verification is
established prior art (for example, digital health certificates). This disclosure
does **not** claim that general mechanism. What is differentiated here is the
embodied-agent application and semantics:

- **Robot-specific subject.** The passport asserts the robot's owner, its
  authorized **physical** actions, certification, and live operational standing,
  the properties a bystander needs to judge a machine acting in the physical world,
  rather than a person's attributes.
- **`vouch-passport:` self-contained URI scheme** carrying the canonical credential
  bytes for QR or NFC, designed for a robot tag.
- **Composition with hardware-rooted identity and physical capability scope.** The
  passport is one credential in a system where the same robot's hardware-bound
  identity (PAD-064) and physical limits (PAD-066) are independently verifiable, so
  a scan can be cross-checked against them.
- **URL-bearing QR/NFC robot labels.** Require connectivity and a trusted server;
  the present method is self-contained and offline.

---

## 5. Technical Implementation

A reference implementation provides `build_passport`, `encode_passport`,
`decode_passport`, and `verify_passport`, plus the `vouch-passport:` URI scheme and
a `status` of active, suspended, or decommissioned. This ships the open verifier
and the encoding; rendering the URI to a QR image or writing an NFC tag is the
caller's concern.

---

## 6. Claims Summary

1. A method for a robot passport expressed as a signed credential whose full bytes
   are encoded into a scannable URI, so the robot's owner, authorized physical
   actions, certification, and standing are verifiable offline without a network
   round-trip.
2. The method of claim 1 wherein verification at scan time requires only the
   issuer's public key, resolved or cached out of band, and no server lookup.
3. The method of claim 1 wherein the subject carries a live standing field
   (active, suspended, or decommissioned) within the offline-verifiable credential.
4. The method of claim 1 wherein the passport is built on the same credential
   format as the robot's hardware-rooted identity and physical capability scope, so
   the passport composes with and can be cross-checked against them.
5. The method of claim 1 wherein the credential uses canonicalization and signature
   primitives shared across language SDKs, so the same passport verifies
   cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
