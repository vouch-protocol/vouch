# PAD-065: Re-Signable Model-and-Config Provenance Attestation for Embodied Agents

**Identifier:** PAD-065  
**Title:** Method for a Signed, Chained Provenance Attestation of the Model, Weights Hash, Safety Policy, and Configuration Running on a Robot, Re-Signed on Each Over-the-Air Update  
**Publication Date:** June 14, 2026  
**Prior Art Effective Date:** June 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Model Provenance / AI Safety / Supply Chain / Verifiable Credentials  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-018 (Model Lineage Provenance), PAD-043 (Cryptographic Weight Binding), PAD-064 (Hardware-Rooted Robot Identity), PAD-068 (Kill-Switch Credential)  

---

## 1. Abstract

A method for attesting, in a signed and verifiable record, exactly which
Vision-Language-Action (VLA) model, model-weights hash, safety policy, and runtime
configuration are running on a physical robot at a given time, and for re-signing
that record on each over-the-air (OTA) update so that the sequence of attestations
forms a tamper-evident chain of what software the robot ran and when. The record
records the configuration as a hash of its canonical form, so a verifier can
confirm the exact configuration without the configuration's contents being
re-derived.

Key innovations:

- **Single attestation binds model, weights, policy, and config.** One signed
  record ties the model identity, the weights hash, the active safety policy, and
  the configuration hash to the robot's identity.
- **OTA re-signing with a supersedes link.** Each update issues a new attestation
  that references the attestation it replaces, so the chain answers "what was
  running at time T" for any past T.
- **Canonical config hashing.** The configuration hash is the multibase SHA-256 of
  the JCS-canonical configuration, reproducible by any verifier in any language.

---

## 2. Problem Statement

### 2.1 No verifiable record of what software a robot runs

After deployment and OTA updates, there is no standard, verifiable way to know
which model weights and safety policy a robot is actually running. Logs are
mutable and vendor-specific.

### 2.2 OTA updates erase history

An OTA update replaces the running software, and the prior state is typically
gone. For incident investigation and regulatory audit, the question "what model
and policy were active when this incident occurred" must be answerable after the
fact.

### 2.3 Config drift is invisible

A safety-relevant configuration parameter can change without a verifiable record,
so a robot's behavior can change without an auditable cause.

---

## 3. Solution (The Invention)

A ModelProvenanceAttestation is a Verifiable Credential whose subject carries a
`vla` block:

```
{ "modelName", "weightsHash", "safetyPolicy", "version", "configHash" }
```

where `weightsHash` is the multibase SHA-256 of the weights artifact (supplied by
the builder), `safetyPolicy` identifies or hashes the active policy, and
`configHash` is the multibase SHA-256 of the JCS-canonical runtime configuration,
computed by the issuer. The credential is signed (eddsa-jcs-2022).

On each OTA update, the deployer issues a new attestation whose subject includes a
`supersedes` reference to the prior attestation's identifier or hash, forming a
chain. A verifier confirms each attestation's proof, and may recompute the config
hash from a supplied configuration to confirm the exact configuration matches the
signed record. Following the supersedes links reconstructs the full history of
which software the robot ran and when.

---

## 4. Prior Art Differentiation

- **Software bill of materials (SBOM), in-toto, Sigstore.** Attest software supply
  chains at build time but are not a robot-resident, re-signable record of the
  running model, weights, policy, and config tied to the robot's identity and
  chained across OTA updates.
- **PAD-018 (Model Lineage Provenance) / PAD-043 (Cryptographic Weight Binding).**
  Address model lineage and weight binding; the present method adds the
  robot-resident, OTA-re-signable attestation that jointly binds model, weights,
  safety policy, and configuration to the robot, with a supersedes chain.
- **Secure boot / measured boot.** Attest the boot chain, not the
  application-level VLA model, safety policy, and configuration as a verifiable,
  queryable, re-signable credential.

---

## 5. Technical Implementation

A reference implementation provides `config_hash`, `build_provenance_attestation`
(with optional `supersedes`), and `verify_provenance_attestation` (with optional
config re-hash check). The attestation reuses the shared JCS and eddsa-jcs-2022
primitives, so it verifies cross-language, and an interop vector pins the config
hash.

---

## 6. Claims Summary

1. A method for attesting, in a signed Verifiable Credential bound to a robot's
   identity, the model name, weights hash, safety policy, and configuration hash
   of the software running on the robot.
2. The method of claim 1 wherein the configuration hash is the multibase SHA-256
   of the canonical configuration, reproducible by any verifier.
3. The method of claim 1 wherein each over-the-air update issues a new attestation
   referencing the attestation it supersedes, forming a tamper-evident chain.
4. The method of claim 3 wherein following the supersedes chain answers which
   model, policy, and configuration were active at any past time.
5. The method of claim 1 wherein a verifier recomputes the configuration hash from
   a supplied configuration to confirm an exact match with the signed record.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
