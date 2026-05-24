# Credential Format Reference

A Vouch credential is a Verifiable Credential 2.0 JSON document with a
Data Integrity proof sibling. Human-readable; no opaque envelopes. It is
**not** a JWT or JWS — the proof attaches as a sibling `proof` object
using the `eddsa-jcs-2022` cryptosuite. (The legacy v0.x JWS token
format is deprecated; see "Why not JWS / JWT?" at the end of this doc.)

## Anatomy of a signed Vouch credential

```json
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://vouch-protocol.com/contexts/v1"
    ],
    "id": "urn:uuid:c87d3e92-...",
    "type": ["VerifiableCredential", "VouchCredential"],
    "issuer": "did:web:agent.example.com",
    "validFrom": "2026-05-13T10:00:00Z",
    "validUntil": "2026-05-13T10:05:00Z",
    "credentialSubject": {
        "id": "did:web:agent.example.com",
        "vouchVersion": "1.0",
        "intent": {
            "action": "submit_claim",
            "target": "claim:HC-001",
            "resource": "https://insurance.example.com/claims/HC-001"
        },
        "reputationScore": 85,
        "delegationChain": []
    },
    "credentialStatus": {
        "id": "https://issuer.example/status/1#42",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "42",
        "statusListCredential": "https://issuer.example/status/1"
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:web:agent.example.com#key-1",
        "proofPurpose": "assertionMethod",
        "created": "2026-05-13T10:00:00Z",
        "proofValue": "z3NkR..."
    }
}
```

## Field-by-field

| Field | Source | Notes |
|---|---|---|
| `@context` | VC 2.0 | First URI MUST be the VC 2.0 context. Vouch context follows. |
| `id` | Vouch | UUID URN, fresh per credential. Used for nonce tracking. |
| `type` | VC 2.0 + Vouch | `VerifiableCredential` first, then `VouchCredential` or `SessionVoucher`. |
| `issuer` | Vouch | The agent's DID (or list of validator DIDs for SessionVoucher). |
| `validFrom` / `validUntil` | VC 2.0 | ISO 8601 UTC. Default validity 300 seconds. |
| `credentialSubject.id` | VC 2.0 | The agent's DID (same as `issuer` for self-attested intent). |
| `credentialSubject.vouchVersion` | Vouch | Protocol version, "1.0" today. |
| `credentialSubject.intent` | Vouch | REQUIRED. `action`, `target`, `resource` all required. |
| `credentialSubject.reputationScore` | Vouch | Optional, [0, 100]. |
| `credentialSubject.delegationChain` | Vouch | Optional, ordered list of prior delegation links. |
| `credentialStatus` | VC + BitstringStatusList | Optional, for per-credential revocation. |
| `proof` | Data Integrity | Sibling object with signature. |

## The `intent` field

Required. Binds the credential to a specific action on a specific
resource:

```json
{
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001"
}
```

- `action`: what the agent is doing (verb, lowercase, snake_case by convention)
- `target`: what the agent is acting on (identifier within the resource)
- `resource`: the URL of the system being acted against

If any are missing or empty, the credential is invalid. The verifier
rejects with `intent_missing_field`.

You can add additional intent fields beyond these three (e.g.,
`reasoning`, `idempotency_key`); they pass through verification.

## The `proof` field

```json
{
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:web:agent.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "created": "2026-05-13T10:00:00Z",
    "proofValue": "z..."
}
```

- `type`: always `DataIntegrityProof`
- `cryptosuite`: `eddsa-jcs-2022` (default) or `hybrid-eddsa-mldsa44-jcs-2026` (post-quantum)
- `verificationMethod`: the DID Document `verificationMethod` ID (DID + `#fragment`)
- `proofPurpose`: `assertionMethod` for action credentials
- `created`: when the signature was made
- `proofValue`: multibase-encoded signature
  - For `eddsa-jcs-2022`: `z` prefix + base58btc of Ed25519 signature (64 bytes)
  - For `hybrid-eddsa-mldsa44-jcs-2026`: `z` prefix + base58btc of (Ed25519 sig || ML-DSA-44 sig)

## Signing algorithm (eddsa-jcs-2022)

1. Build the unsigned credential (no `proofValue` yet).
2. Add proof options (type, cryptosuite, verificationMethod, proofPurpose, created).
3. JCS-canonicalize the resulting object (RFC 8785).
4. SHA-256 the canonical bytes.
5. Ed25519-sign the digest.
6. base58btc-encode the signature, prepend `z`.
7. Store under `proof.proofValue`.

For hybrid, step 5-6 also include ML-DSA-44 signing over the same digest
and concatenation of the two raw signatures before base58btc.

## SessionVoucher type

Distinguished by `type: ["VerifiableCredential", "SessionVoucher"]`.
Issued by a validator (or quorum) to an agent. Carries trust decay
parameters:

```json
{
    "type": ["VerifiableCredential", "SessionVoucher"],
    "issuer": ["did:web:validator.example.com"],
    "credentialSubject": {
        "id": "did:web:agent.example.com",
        "decayLambda": 0.01,
        "initialTrust": 1.0,
        "maxTtl": 3600,
        "scope": ["read", "write"]
    }
}
```

Verifiers consume `decayLambda` to compute trust over time:

```
trust(t) = initialTrust * exp(-decayLambda * (now - issuedAt_seconds))
```

## DID Document layout

Companion to the credential. Resolves via `did:web` or `did:key`.

```json
{
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:web:agent.example.com",
    "verificationMethod": [
        {
            "id": "did:web:agent.example.com#key-1",
            "type": "Multikey",
            "controller": "did:web:agent.example.com",
            "publicKeyMultibase": "z6MkhaXg..."
        }
    ],
    "authentication": ["did:web:agent.example.com#key-1"],
    "assertionMethod": ["did:web:agent.example.com#key-1"]
}
```

For hybrid post-quantum, add a second `verificationMethod` with the
ML-DSA-44 Multikey (multicodec prefix `0x1207`):

```json
{
    "verificationMethod": [
        {
            "id": "did:web:agent.example.com#key-1",
            "type": "Multikey",
            "publicKeyMultibase": "z6Mkh..."  // Ed25519
        },
        {
            "id": "did:web:agent.example.com#key-pq",
            "type": "Multikey",
            "publicKeyMultibase": "u..."  // ML-DSA-44
        }
    ]
}
```

For `did:web`, serve this at `https://agent.example.com/.well-known/did.json`.

## Test vectors

Cross-language test vectors at `test-vectors/` in the repo:

- `test-vectors/jcs/` - JCS canonicalization edge cases
- `test-vectors/hybrid-eddsa-mldsa44/` - Full hybrid credential
- `test-vectors/bitstring-status-list/` - BitstringStatusList encoding

Each has a `generate.py` script that reproduces the vector deterministically.

## Common questions

**Q: Why not JWS / JWT?**
A: JWS Compact Serialization base64-wraps the credential. Vouch keeps it
as plain JSON so auditors and regulators can read it without decoding.
Earlier Vouch drafts used JWS; v1.0+ uses Data Integrity.

**Q: Why `did:web` over `did:key`?**
A: Organizations who own a domain get `did:web` for free. `did:key` is
for ephemeral or fully decentralized agents.

**Q: Why two `@context` URIs?**
A: The first is the canonical VC 2.0 context. The second is Vouch's
extension that defines the `intent` field shape.

**Q: Why is `validUntil` so short (5 minutes)?**
A: Short validity windows reduce the blast radius of a leaked credential.
For long-running agents, use the Heartbeat Protocol with renewing
SessionVouchers.
