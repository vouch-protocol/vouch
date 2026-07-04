# PAD-080: Post-Quantum-by-Default Robot Credentials With Backward-Compatible Dual Verification and Software Migration

**Identifier:** PAD-080  
**Title:** Method for Defaulting Long-Lived Robot Credentials to a Hybrid Classical-Plus-Post-Quantum Signature, With Verification That Auto-Detects Classical or Hybrid and a Software Re-Sign Migration for Fielded Credentials  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Post-Quantum Cryptography / Credential Migration  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-040 (Hybrid Composite Signature, Same Canonical Bytes), PAD-046 (Algorithm-Quorum Cryptosuite Diversity), PAD-064 (Hardware-Rooted Robot Identity)  

---

## 1. Abstract

A method for keeping a long-lived robot's credentials unforgeable across its service
life by defaulting them to a hybrid classical-plus-post-quantum signature, with
verification that accepts either a classical or a hybrid proof and a software
migration that re-signs already-fielded credentials under a post-quantum key. A
robot fielded today runs for ten to twenty years, longer than classical Ed25519 is
expected to stay safe, so signing a robot credential now with a hybrid proof keeps
it verifiable and unforgeable once classical signatures no longer hold.

Key innovations:

- **Service-life-driven post-quantum default for robot credentials.** Because a
  robot outlives the safe window of a classical signature, the hybrid cryptosuite is
  the default for robot credentials rather than an opt-in add-on.
- **Backward-compatible dual verification with auto-detection.** A single verify
  path reads the proof cryptosuite and validates a classical or a hybrid credential
  accordingly, so a fleet migrates gradually while the classical credentials already
  in the field keep verifying.
- **Software re-sign migration for fielded robots.** A fielded robot's classical
  credential is re-signed under a post-quantum key in software, so a deployment
  upgrades in place rather than reissuing from scratch.

---

## 2. Problem Statement

### 2.1 Robots outlive their signatures

A machine deployed today may still be operating in fifteen or twenty years, past the
point where a classical-only signature on its identity should be trusted. An
identity signed now could be forged once a quantum computer arrives.

### 2.2 A hard cutover breaks fielded credentials

Switching a fleet to a new signature scheme all at once would invalidate every
classical credential already in service. A migration path must let old and new
credentials coexist and verify during the transition.

---

## 3. Solution (The Invention)

`sign_pq(...)` attaches a hybrid proof carrying a classical Ed25519 signature
alongside an ML-DSA-44 signature under one cryptosuite. `verify_robot_credential(...)`
reads the proof cryptosuite and verifies a classical or a hybrid credential
accordingly, requiring the post-quantum key only for a hybrid proof, so a verifier
accepts both kinds during migration. `is_pq(...)` reports whether a credential is
hybrid-signed, and `migrate_to_pq(...)` re-signs a fielded robot's classical
credential under a post-quantum key. A hybrid credential passes only when both the
classical and the post-quantum signature validate, so it is at least as strong as
the classical signature and stays safe once classical signatures do not. The shared
JCS plus hybrid Data Integrity primitives make the same credential verify across the
language SDKs.

---

## 4. Prior Art Differentiation

Hybrid classical-plus-post-quantum signatures and dual verification exist as prior
art, including this project's own hybrid cryptosuite disclosures. This disclosure
does **not** claim the hybrid signature scheme itself. What is differentiated is the
reduction to long-lived robot credentials:

- **The service-life-driven default**, making hybrid the default for a robot
  credential because the machine outlives the classical safe window.
- **Auto-detecting dual verification across a robot fleet**, so classical and hybrid
  robot credentials coexist and verify through a gradual migration.
- **A software re-sign migration for fielded robots**, upgrading credentials in
  place rather than reissuing.

This disclosure covers software signing, backward-compatible verification, and the
software re-sign migration.

---

## 5. Technical Implementation

A reference implementation provides `sign_pq`, `is_pq`, `verify_pq`,
`verify_robot_credential`, and `migrate_to_pq` over the hybrid
`hybrid-eddsa-mldsa44-jcs-2026` cryptosuite, using the shared Data Integrity
primitives so the same credential verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for defaulting a long-lived robot's credentials to a hybrid classical-
   plus-post-quantum signature, given that the robot's service life exceeds the safe
   window of a classical signature.
2. The method of claim 1 wherein a single verification path reads the proof
   cryptosuite and validates a classical or a hybrid robot credential accordingly.
3. The method of claim 2 wherein a hybrid credential is admitted only when both the
   classical and the post-quantum signature validate.
4. The method of claim 1 wherein a fielded robot's classical credential is re-signed
   under a post-quantum key in software, so classical and hybrid credentials coexist
   during a gradual fleet migration.
5. The method of claim 1 wherein the credential uses canonicalization and signature
   primitives shared across language SDKs, so the same credential verifies
   cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
