# Vouch Protocol Overview

Vouch is an open protocol for AI agent identity and signed action.
Agents have DIDs (Decentralized Identifiers); every action they take
on a real system is issued as a Verifiable Credential signed by the
agent's key. Verifiers check the signature, the agent's authorization,
and the action's freshness before executing.

## What problem does Vouch solve?

LLM-based agents are increasingly making real-world decisions: opening
tickets, submitting claims, moving money, writing code. Today, the only
trace of "who did this" is a row in a database that says "the API key
named bot-prod did it." That key is shared, rotated rarely, and gives
zero attribution about which prompt or which orchestrator or which
agent generation produced the action.

Vouch replaces "bot-prod did it" with "did:web:claims-agent issued a
signed credential at 14:02:18 UTC, authorizing action=submit_claim,
target=HC-001, with a Hybrid Ed25519+ML-DSA-44 signature, verifiable
against the agent's published DID Document, with the issuer's DID
present in the registry of trusted principals and not revoked."

## Layers

1. **Credential layer**: Verifiable Credentials 2.0 with Vouch-specific
   intent fields. Signed with Ed25519 by default; hybrid post-quantum
   profile available for forward-looking deployments.
2. **State Verifiability layer**: SessionVoucher credentials that
   carry a decaying trust score. Agents renew with a Heartbeat
   Protocol that includes behavioral attestation and a canary
   commitment chain (silent-failure detection).
3. **Delegation layer**: chains of credentials proving an action was
   authorized down a chain of principals. Resource scope must narrow
   at each link; depth capped at five.
4. **Revocation layer**: DID-level revocation registry for whole-key
   kills; BitstringStatusList for surgical per-credential retraction.

## Cryptographic profile

- Default: Ed25519 with the `eddsa-jcs-2022` cryptosuite (JCS-canonicalized
  payload, Ed25519 signature, multibase base58btc proofValue).
- Hybrid PQ: `hybrid-eddsa-mldsa44-jcs-2026`, concatenated Ed25519 and
  ML-DSA-44 signatures. Both must verify in dual mode; either alone
  in transition modes.

## SDKs

One canonical Rust core (`vouch-core`) does the cryptography once, and every
platform is a thin wrapper over it, so a credential signed anywhere verifies
everywhere, byte for byte.

- Python: `pip install vouch-protocol`
- TypeScript and Go: the existing reference SDKs
- Browser and Node.js (WebAssembly): `npm install @vouch-protocol-official/core-wasm`
- Swift (iOS and macOS): the `VouchCore` Swift package, over the core via UniFFI
- JVM (Java and Kotlin): the `com.vouchprotocol:vouch-core` Gradle module
- .NET: `VouchProtocol.Core` on NuGet, over the C ABI
- C and C++: the C bindings shipped with the core (header plus prebuilt library)

Every implementation produces and verifies identical bytes and passes the same
shared test vectors. See language-sdks.md for what each one covers and how to
install it.

## Identity Sidecar

For LLM-driven agents, run the signer in a separate process. The LLM
process has no access to the private key; prompt injection cannot
exfiltrate what isn't there. Reference implementations exist in Go
(production) and Python (development).

## Repository

https://github.com/vouch-protocol/vouch

## Community

- Discord: https://discord.gg/mMqx5cG9Y
- Issues: https://github.com/vouch-protocol/vouch/issues
