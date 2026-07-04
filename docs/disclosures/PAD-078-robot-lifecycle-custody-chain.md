# PAD-078: Verifiable Robot Lifecycle: Chained Custody, Key History, and Signed Decommission

**Identifier:** PAD-078  
**Title:** Method for a Verifiable Robot Lifecycle Combining a Chained Ownership Custody Record, a Key-Rotation History, and a Signed Decommission Credential, Bound to a Hardware-Rooted Robot Identity  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Lifecycle / Ownership / Key Management  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-002 (Chain of Custody), PAD-064 (Hardware-Rooted Robot Identity), PAD-016 (Dynamic Credential Renewal)  

---

## 1. Abstract

A method for making a robot's whole life cryptographically accountable through three
composed credential types bound to a hardware-rooted robot identity: an ownership
transfer that chains into a verifiable chain of custody, a key rotation that forms a
key history, and a decommission credential that retires the robot. A verifier can
confirm who owns the robot now, that its key history is unbroken, and that a retired
robot is no longer to be trusted.

Key innovations:

- **Chained custody with an owner-authorization rule.** Each ownership transfer is
  signed by the current owner and links to the previous transfer, so a verifier
  walks the chain from origin to current owner and confirms that only the holder at
  each step could pass the robot on.
- **Key-history chain authorized by the predecessor key.** Each key rotation is
  signed by the key it rotates from and names both the previous and the new key, so
  anyone who trusted an earlier key can follow the chain to the current key.
- **Signed decommission a verifier honors.** A retirement credential, optionally
  restricted to an attested authority, marks the robot as no longer to be trusted,
  and the three types compose over the same hardware-rooted identity.

---

## 2. Problem Statement

### 2.1 A robot outlives its first owner

A robot is commissioned, resold, repurposed, and eventually scrapped over a service
life of a decade or more. There is no cryptographic way today to prove who owns it
now, which keys it has used, or that it was properly retired.

### 2.2 Ownership and key changes are unaccountable

When a robot changes hands or rotates a compromised key, nothing ties the new state
to the old in a way a third party can verify. A buyer cannot confirm a clean chain
from the manufacturer; a verifier cannot tell a current key from a stale one.

### 2.3 A retired robot can still present old credentials

A decommissioned machine still holds its previously valid credentials. Without a
signed retirement a verifier has no basis to stop trusting it.

---

## 3. Solution (The Invention)

Three credential types compose over a hardware-rooted robot identity. An ownership
transfer (`build_ownership_transfer`) is signed by the current owner and names the
prior transfer, so `verify_custody_chain(...)` walks the links and confirms each
step was signed by the then-current owner and that the chain runs unbroken to the
claimed current owner. A key rotation (`build_key_rotation`) is signed by the
outgoing key and names the incoming key, so `verify_key_history(...)` follows the
chain from an origin key to the current key. A decommission
(`build_decommission`), optionally restricted to a trusted authority set, retires
the robot, after which a verifier refuses to trust it. All three use the shared JCS
plus eddsa-jcs-2022 primitives, so they verify across the language SDKs.

---

## 4. Prior Art Differentiation

Verifiable Credentials, custody chains, key rotation, and revocation each exist as
prior art, including this project's own agent-side work. This disclosure does
**not** claim those mechanisms in the abstract. What is differentiated is the
combined lifecycle profile for an embodied machine:

- **The combined custody-chain plus key-history plus decommission profile** bound to
  one hardware-rooted robot identity, so a single verifier answers ownership, key
  currency, and retirement together.
- **The owner-authorization rule on each transfer**, so only the current holder can
  pass the robot on and the chain cannot be forked by a prior owner.
- **The predecessor-signed key-history chain** carried alongside the same robot
  identity, so trust in an old key transfers to the current one without a central
  registry.

This disclosure covers the plain signed lifecycle credentials only.

---

## 5. Technical Implementation

A reference implementation provides `build_ownership_transfer`,
`verify_ownership_transfer`, `verify_custody_chain`, `build_key_rotation`,
`verify_key_rotation`, `verify_key_history`, `build_decommission`, and
`verify_decommission`, using the shared Data Integrity primitives so the same
credentials verify across the language SDKs.

---

## 6. Claims Summary

1. A method for an accountable robot lifecycle combining a chained ownership custody
   record, a predecessor-signed key-rotation history, and a signed decommission
   credential, all bound to a hardware-rooted robot identity.
2. The method of claim 1 wherein each ownership transfer is signed by the current
   owner and links to the prior transfer, so a verifier confirms an unbroken chain
   from origin to current owner.
3. The method of claim 1 wherein each key rotation is signed by the key it rotates
   from and names the successor, so trust in a prior key follows the chain to the
   current key.
4. The method of claim 1 wherein a signed decommission credential, optionally
   restricted to an attested authority, marks the robot as no longer to be trusted.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so they verify cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
