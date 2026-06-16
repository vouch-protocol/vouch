# PAD-064: Hardware-Rooted Verifiable Robot Identity and Lifecycle Credential

**Identifier:** PAD-064  
**Title:** Method for Binding a Robot's Software Identity Key to a Hardware Root of Trust via an Attested Verifiable Lifecycle Credential, as a Vendor-Neutral Robot Identity  
**Publication Date:** June 14, 2026  
**Prior Art Effective Date:** June 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Hardware Root of Trust / Verifiable Credentials / Device Identity / AI Safety  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-018 (Model Lineage Provenance), PAD-065 (Model and Config Provenance), PAD-068 (Kill-Switch Credential)  

---

## 1. Abstract

A method for giving a physical robot a verifiable identity in which the robot's
software identity key (a Vouch Ed25519 key used to sign actions) is
cryptographically bound to a hardware root of trust (a TPM or a secure element)
through an attested, verifiable lifecycle credential. The hardware root signs a
canonical binding over the robot's decentralized identifier and its software
public key; that attestation is embedded in a Verifiable Credential carrying the
robot's make, model, serial, and lifecycle history. A verifier checks both the
credential's own proof (the software key) and the hardware attestation (the root
key), so the identity cannot be cloned to other hardware.

Key innovations:

- **Dual-proof identity.** The identity verifies only when both the software-key
  credential proof and the hardware-root attestation over the (DID, key) binding
  verify, tying the portable software identity to one physical device.
- **Vendor-neutral, open profile.** The identity is an open Verifiable Credential
  profile, not a proprietary or state-run registry, so any manufacturer or owner
  can issue and any party can verify it.
- **Pluggable hardware root.** A single interface (public key plus a
  sign-over-digest operation) is satisfied by a TPM attestation key, a
  secure-element device key, or a software reference for development, so the same
  credential format serves every backend.
- **Lifecycle history in-credential.** Manufacture, commissioning, ownership
  transfer, and decommissioning are recorded as a lifecycle history on the
  identity, making provenance auditable.

---

## 2. Problem Statement

### 2.1 Robot identity today is proprietary or absent

Robots are identified by vendor serial numbers, cloud-account bindings, or
closed/state-run registries. None give a portable, cryptographically verifiable,
vendor-neutral identity that an arbitrary third party can check offline.

### 2.2 A software key alone can be copied to other hardware

If a robot's identity is just a software key, that key can be exfiltrated and run
on different hardware, impersonating the robot. Identity must be anchored to the
specific device.

### 2.3 No open binding between a verifiable credential and a hardware root

Verifiable Credentials and DIDs provide portable software identity; TPMs and
secure elements provide hardware anchoring. No open method binds the two so that
a robot's verifiable identity is provably resident on one device, with a
lifecycle history.

---

## 3. Solution (The Invention)

At commissioning, the robot mints a RobotIdentityCredential:

1. The robot's software signer computes its public key in multibase form and its
   DID.
2. The hardware root signs a canonical binding `B = JCS({"key": robotKeyMultibase,
   "robotDid": robotDid})`, producing an attestation signature.
3. The credential's subject carries `make`, `model`, `serial`, a `lifecycle`
   array, and a `hardwareRoot` block `{ kind, publicKeyMultibase, attestation }`.
4. The robot self-issues the credential with its software key (an eddsa-jcs-2022
   Data Integrity proof).

To verify, a party:

1. verifies the credential's Data Integrity proof against the robot's software
   public key,
2. decodes the hardware-root public key from `hardwareRoot.publicKeyMultibase`,
3. recomputes the binding `B` from the credential subject's DID and the software
   key, and
4. verifies the hardware-root attestation over `B`.

Acceptance requires both. Because the binding includes both the DID and the
software key, and the attestation is produced by a hardware-resident key, the
credential proves the software identity is anchored to that hardware. The
`HardwareRootOfTrust` interface (public key plus sign-over-digest) is satisfied by
a TPM attestation key, a secure element, or a software reference for testing.

---

## 4. Prior Art Differentiation

- **TPM remote attestation / DICE / IDevID (IEEE 802.1AR).** Provide hardware
  device identity but are not expressed as open, portable Verifiable Credentials
  carrying make/model/serial and a lifecycle history that any party can verify
  with the same tooling used for agent credentials.
- **Proprietary robot fleet identity (vendor clouds).** Closed and account-bound;
  not vendor-neutral or third-party-verifiable offline.
- **PAD-001 (Cryptographic Agent Identity).** Establishes software agent identity;
  the present method adds the hardware-root binding and the robot lifecycle
  profile, which PAD-001 does not cover.
- **DID methods (did:web, did:key).** Provide software-key identity but no binding
  to a hardware root or a device lifecycle.

---

## 5. Technical Implementation

A reference implementation provides `HardwareRootOfTrust` (the pluggable
interface), `SoftwareRootOfTrust` (development reference), `mint_robot_identity`,
`verify_robot_identity`, and `lifecycle_event`. A TPM or secure-element backend
subclasses the interface, signing the binding with its hardware-resident
attestation key without exposing the key. The binding and the credential reuse the
shared JCS canonicalization, multikey encoding, and eddsa-jcs-2022 proof, so the
robot identity verifies with the same cross-language SDKs as agent credentials. An
interop vector pins the binding bytes.

---

## 6. Claims Summary

1. A method for a robot's verifiable identity in which a hardware root of trust
   signs a canonical binding over the robot's decentralized identifier and its
   software identity public key, the attestation embedded in a Verifiable
   Credential, such that verification requires both the credential proof and the
   hardware attestation.
2. The method of claim 1 wherein the credential carries make, model, serial, and a
   lifecycle history of the robot.
3. The method of claim 1 wherein the hardware root is accessed through a single
   interface satisfied by a TPM attestation key, a secure-element device key, or a
   software reference.
4. The method of claim 1 wherein the binding includes both the identifier and the
   key, so the credential cannot be re-bound to a different key or device.
5. The method of claim 1 wherein the identity is an open, vendor-neutral Verifiable
   Credential profile verifiable by any party without a central registry.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the broader robotics community.
