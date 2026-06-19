# PAD-043: Cryptographic Weight Binding for Model-Intrinsic AI Identity

**Identifier:** PAD-043  
**Title:** Method for Deriving an AI Agent's Cryptographic Identity Key Directly from a Cryptographic Hash of the Model's Tensor Weights  
**Publication Date:** April 29, 2026  
**Prior Art Effective Date:** April 29, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Identity / Model Provenance / Tensor Fingerprinting / Key Derivation / Open AI Standards  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-003 (Identity Sidecar), PAD-018 (Model Lineage Provenance), PAD-040 (Hybrid Composite Signature), PAD-042 (Metadata Schema)  

---

## 1. Abstract

A method for binding an AI agent's cryptographic signing identity
**physically and inseparably** to the parameters of its underlying
neural network. The core mechanism: the agent's Ed25519 (or ML-DSA-44
under the hybrid post-quantum profile) **private key seed is derived
deterministically from the cryptographic hash of the model's tensor
weight buffer**. If a single floating-point parameter in the neural
network changes (whether through fine-tuning, weight poisoning,
quantization, or malicious tampering), the model's intrinsic weight
hash changes, the key derivation produces a different keypair, and the
agent **permanently loses its Vouch identity** under the original DID.

This produces what we call **model-mind immutability**: the AI's
"mind" (its weight tensors) and its identity (its signing key) are the
same cryptographic object. Tampering with one breaks the other.

The mechanism is published openly as defensive prior art so that
open-source model authors can generate their identity natively, with
no dependency on paywall, central registry, or vendor signing
infrastructure. If model-intrinsic identity were behind a commercial
gate, the open-source AI ecosystem would build a parallel standard,
defeating Vouch's role as the default identity layer.

## 2. Problem Statement

Existing model-trust mechanisms operate at the metadata layer:

- **Model cards**: unstructured documentation, not cryptographically
  bound to the model.
- **Hugging Face binary hashes**: hash a specific file artifact, but
  do not produce a key, and break across formats (PyTorch vs
  SafeTensors vs GGUF).
- **C2PA model credentials (PAD-018)**: signed *attestations about*
  the model, attached externally. The attestation can be replaced or
  detached.
- **Watermarking**: embeds a signature *into* the weights, but
  requires modifying the weights, which is unacceptable for
  certified-deployment models.

None of these prevent the failure mode an enterprise actually fears:
**a bad actor downloads a trusted Llama-3 agent, fine-tunes a small
fraction of its weights to behave maliciously in narrow conditions
(e.g., always recommend a specific stock when asked about
investments), and deploys the modified model under the original DID**.
The metadata signature still verifies. The behavioral change is
undetectable until exploitation. Trust is silently broken.

What is needed is a mechanism where the agent's identity is
mechanically bound to the *exact* state of its weights, such that
any change to the weights immediately invalidates the identity.

## 3. The Novel Mechanism

### 3.1 Weight Hash as Identity Seed

The Vouch Identity Sidecar (PAD-003), upon agent initialization,
performs the following procedure:

1. **Locate the model file.** Read the `.safetensors`, `.gguf`,
   `.pt`, or equivalent tensor-weight container that the agent's
   inference runtime will load.
2. **Canonical serialization.** Walk the weight tensors in a
   deterministic canonical order: layer paths sorted in code-point
   order; per-tensor `(layer_path, shape, dtype, values)` emitted as
   little-endian bytes. Format-independent: PyTorch, SafeTensors, GGUF
   produce identical canonical bytes if the underlying weights are
   identical.
3. **Compute the Weight Hash.** Stream the canonical bytes through
   SHA-256 (and SHA-3-512 for the post-quantum hybrid profile). The
   resulting digest is the *Weight Hash*, a 32-byte (or 64-byte under
   PQ) cryptographic fingerprint of the model's parameters.
4. **Derive the keypair seed.** Use the Weight Hash as the input to a
   key derivation function (HKDF-SHA-256 with a Vouch-specific
   "info" tag), producing a deterministic 32-byte seed.
5. **Generate the keypair.** Feed the seed into Ed25519 key
   generation per RFC 8032 §5.1.5. The resulting (private_key,
   public_key) pair is **bit-for-bit determined** by the weight bytes.
6. **Bind the DID.** The agent's `did:web:` (or any DID method)
   verification method publishes the resulting public key. Anyone
   re-running the procedure on the same weights derives the same
   public key and confirms the agent is signing under the correct
   model.

### 3.2 The Mind-Identity Binding Property

The cryptographic consequence: **the agent's signing identity and the
model's tensor parameters are now the same cryptographic object.**
Specifically:

- Modifying a single floating-point parameter changes the canonical
  bytes.
- Changed canonical bytes change the Weight Hash.
- Changed Weight Hash changes the derived seed.
- Changed seed changes the Ed25519 keypair.
- The new keypair does not match the published public key in the
  agent's DID Document.
- All signatures issued by the modified model fail verification.

The agent **cannot sign as itself** after tampering. The published
DID is now orphaned: it points at a public key that no model in
existence holds the private counterpart to (since the original
model's weights would have to be reconstructed bit-for-bit to
recover the original key).

### 3.3 Hybrid Post-Quantum Variant

Under the `hybrid-eddsa-mldsa44-jcs-2026` cryptosuite (PAD-040), both
the Ed25519 and ML-DSA-44 keypairs are derived from the same Weight
Hash via HKDF, with separate "info" tags. The same mind-identity
binding property holds: any weight change invalidates both keys
simultaneously.

### 3.4 Detection at Inference Time

The Identity Sidecar's signing operation includes an inline
verification: before producing any Vouch Credential, the sidecar
recomputes the Weight Hash from the loaded model and confirms the
derived public key matches the DID Document. If the weights have been
altered (even via a hot-patch in memory by a compromised inference
runtime), the inline check fails and the sidecar refuses to sign.

### 3.5 Differential Weight Witnessing for Approved Updates

Legitimate fine-tunes produce a new model with a new identity. To
maintain a verifiable provenance chain, the original model's signer
issues a *Differential Weight Witness*: a signed credential
attesting "the model with Weight Hash B is the result of fine-tuning
the model with Weight Hash A under the following training protocol."
The new model's DID is published independently, but the lineage
chain (PAD-018) records the provenance.

## 4. Embodiments

**Embodiment 1: Open-source Llama-3 self-identification.** A
developer downloads `Llama-3.1-8B-Instruct.safetensors`, runs the
canonical-weight serializer, derives the keypair, and publishes
the public key under a `did:web:llama3-myinstance.example.com`. The
sidecar uses this keypair to sign every inference output. Anyone
verifying the agent's signatures can recompute the Weight Hash from
their own copy of the model and confirm identity.

**Embodiment 2: FDA-cleared medical AI.** A hospital deploys an
FDA-cleared diagnostic model. The vendor publishes both the model
weights and the resulting Vouch public key. The hospital's sidecar
recomputes the Weight Hash on every inference; any unauthorized
fine-tune (even by the vendor's own engineers) breaks signing and
fails the FDA-approval audit. The model and its FDA-approved
behavior are the same cryptographic object.

**Embodiment 3: Tamper-evident on-device AI.** An on-device AI
assistant on a phone has its weights bound to the device's Vouch
identity. If a malicious app patches the model in memory, the
sidecar's pre-signing verification fails and the agent stops issuing
credentials, alerting the user.

**Embodiment 4: Federated learning with verifiable contributions.**
Each participant in a federated round reports their pre-round and
post-round Weight Hashes, both signed under their respective derived
keys. The aggregator can verify each participant signed under the
weights they claimed to contribute, preventing weight-substitution
attacks.

**Embodiment 5: Hybrid PQ binding for long-retention contexts.**
Insurance underwriting agents whose decisions may be litigated decades
into the future derive both Ed25519 and ML-DSA-44 keys from the same
Weight Hash. Even after a quantum-capable adversary breaks Ed25519,
the ML-DSA-44 key still binds the agent to its weights.

## 5. Non-Obviousness

The non-obvious element is the deliberate inversion of the standard
key-generation flow. Conventional cryptographic identity uses a CSPRNG
to produce a random seed, then derives the keypair, then optionally
attests to which model uses the keypair. This disclosure reverses
that order: **the model's weights are themselves the source of
randomness, and the keypair is mechanically derived from them**. The
consequence is that the agent's identity cannot exist independently
of its model parameters, eliminating the metadata-detachment failure
mode that plagues every prior model-identity scheme.

The combination with the Vouch sidecar pattern (PAD-003) is also
non-obvious. A naive implementation would compute the Weight Hash
once and forget it; that defeats the purpose, since a runtime
hot-patch would not be detected. The novel element is *re-verification
at every signing call*, ensuring the loaded model still hashes to the
expected value before any credential is issued.

The mechanism is non-obvious relative to:

- Hugging Face binary hashing (file digest, not format-independent,
  not used for key derivation).
- Watermarking schemes (modify weights to embed signature; this
  disclosure does the opposite, deriving signature from unmodified
  weights).
- C2PA model credentials (external attestation, no key binding).
- Trusted Execution Environment (TEE) attestation (binds to hardware,
  not to model parameters).

## 6. Disclaimer

This disclosure is published as defensive prior art under the Apache
2.0 License. It is intended to prevent assertion of patents covering
the disclosed mechanism. The author claims no exclusive rights to the
described invention. The mechanism is published openly because the
default identity layer of the AI ecosystem must be available to
open-source models without paywall, central registry, or vendor
gatekeeping. If model-intrinsic identity were a closed standard, the
open-source AI community would build a parallel, fragmenting the
ecosystem.

---

*Published as prior art to ensure that the binding between an AI
agent's mind and its identity remains an open standard, accessible to
every open-source model author without gatekeeping.*
