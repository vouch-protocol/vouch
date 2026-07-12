# PAD-094: Capture-Bound Bystander Consent Token That Cannot Be Replayed

**Identifier:** PAD-094  
**Title:** Method for a Bystander-Signed Consent Token Bound to a Single Capture and Robot, So Consent Verifies Only Against the Recording It Was Given For  
**Publication Date:** July 6, 2026  
**Prior Art Effective Date:** July 6, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Privacy / Consent  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-093 (Bystander-Consent Evidence)  

---

## 1. Abstract

A method for a bystander to grant consent for a specific robot capture in a form that
cannot be reused for any other recording. A bystander consent token is signed by the
bystander over the hash of one capture and the robot's identity, so a verifier accepts
it only for that capture and that robot. Because the token is bound to the capture
hash, consent granted for one recording cannot be replayed to justify a different one,
and a robot's evidence can commit to the tokens that cover a capture without embedding
the bystander's identifying data.

Key innovations:

- **Consent bound to a single capture and robot.** The bystander signs over the capture
  hash and the robot's DID, so the token is meaningful only for that recording by that
  robot.
- **Non-replayable by construction.** Because the binding is to the capture hash, a
  token cannot be presented against a different capture, so consent for one recording
  cannot be stretched to cover others.
- **Committed by reference, not by content.** A robot's evidence commits to a token by
  its proof value, so an explicit-consent record names exactly which consents apply
  without carrying the bystander's identity.

---

## 2. Problem Statement

### 2.1 Consent that is not bound to a capture can be reused

A generic consent record, once given, can be presented to justify recordings the
person never agreed to. Nothing ties the consent to the one capture it was meant for.

### 2.2 Proving which consents cover a capture should not expose identity

Listing the consents that cover a capture by embedding the tokens would carry the
bystanders' identifiers into the robot's evidence, so a way to reference them without
exposing identity is needed.

---

## 3. Solution (The Invention)

`build_consent_token(...)` issues a `BystanderConsentToken` whose subject carries the
bystander identifier, the capture hash, and the robot's DID, signed eddsa-jcs-2022 by
the bystander. `verify_consent_token(...)` checks the bystander's proof, that the issuer
is the bystander, that the token is bound to the given capture hash and robot, and that
it is within its window, so the token is accepted only for the recording and robot it
was granted for and cannot be replayed. A robot's bystander-consent evidence of PAD-093
commits to each covering token by its proof value, so verifying the evidence confirms
the tokens are bound to its capture without embedding a bystander's identifying data.
Because the credentials use the shared JCS plus eddsa-jcs-2022 primitives, the same
token verifies across the language SDKs. This is the open layer of the capture-bound
consent token and its verification; managed consent-registry orchestration and consent
revocation at scale are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, signed consent, and nonce binding each exist as prior art. This
disclosure does **not** claim those mechanisms in the abstract. What is differentiated
is the reduction to a capture-bound bystander consent token:

- **Binding a bystander's consent to a single capture hash and robot**, so the token is
  meaningful only for that recording.
- **Non-replayability from the capture binding**, so consent for one recording cannot be
  presented against another.
- **Committing to tokens by proof value in the robot's evidence**, so the consents that
  cover a capture are named without carrying the bystander's identity.

---

## 5. Technical Implementation

A reference implementation provides `build_consent_token` and `verify_consent_token`,
which bind and check a token against a capture hash and a robot, using the shared Data
Integrity primitives so the same token verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for bystander consent to a robot capture in which the bystander signs a
   token over the hash of one capture and the robot's identity.
2. The method of claim 1 wherein verification accepts the token only for the capture
   hash and robot it names, so consent cannot be replayed to a different recording.
3. The method of claim 1 wherein the token is accepted only within its validity window.
4. The method of claim 1 wherein a robot's evidence commits to the covering tokens by
   their proof value, so the consents are named without embedding a bystander's
   identifying data.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same token verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
