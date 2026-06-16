# Hybrid Post-Quantum Reference

The hybrid profile signs every credential with BOTH Ed25519 and ML-DSA-44,
over the same canonical bytes. Verifiers pick the algorithm they trust.

## When to use it

- Regulated sectors with PQ migration mandates (NIST CNSA 2.0, NSM-10, CNSSP-15)
- Long-term audit trails (harvest-now-decrypt-later threats)
- Defense in depth: if Ed25519 cryptanalysis appears, ML-DSA-44 still holds

Costs: about 2.5 KB extra per credential, about 3 ms extra signing time
on M-series Apple silicon.

## Cryptosuite identifier

`hybrid-eddsa-mldsa44-jcs-2026`

Goes in `proof.cryptosuite`. Verifiers MUST recognize this identifier
and switch to hybrid validation.

## Wire format

```json
{
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "hybrid-eddsa-mldsa44-jcs-2026",
        "verificationMethod": "did:web:agent.example.com#key-1",
        "proofPurpose": "assertionMethod",
        "created": "2026-05-13T10:00:00Z",
        "proofValue": "z..."
    }
}
```

`proofValue` is `z` (multibase base58btc) followed by base58btc of:

```
ed25519_signature (64 bytes) || mldsa44_signature (2,420 bytes)
```

Total: 2,484 bytes raw, about 3,400 bytes base58btc-encoded.

## "Same canonical bytes" property

Both Ed25519 and ML-DSA-44 sign the SAME SHA-256 digest of the SAME
JCS-canonicalized credential. Documented as PAD-040. The same-bytes
property prevents an attacker from substituting a differently-encoded
payload between the two signatures.

## DID Document layout

Publish both keys side-by-side:

```json
{
    "id": "did:web:agent.example.com",
    "verificationMethod": [
        {
            "id": "did:web:agent.example.com#key-1",
            "type": "Multikey",
            "controller": "did:web:agent.example.com",
            "publicKeyMultibase": "z6Mkh..."
        },
        {
            "id": "did:web:agent.example.com#key-pq",
            "type": "Multikey",
            "controller": "did:web:agent.example.com",
            "publicKeyMultibase": "u..."
        }
    ],
    "assertionMethod": [
        "did:web:agent.example.com#key-1",
        "did:web:agent.example.com#key-pq"
    ]
}
```

Multibase prefixes for ML-DSA-44 use multicodec `0x1207`. The Vouch
`multikey` modules handle encoding and decoding.

## Three verifier modes

A verifier handling a hybrid-signed credential picks one of three modes:

| Mode | Behavior | When to use |
|---|---|---|
| Classical-only | Validate only the Ed25519 portion of `proofValue` | Default for non-regulated verifiers |
| PQ-only | Validate only the ML-DSA-44 portion | When you specifically need PQ assurance |
| Both-required | Validate both; fail if either is invalid | Highest assurance, regulated deployments |

The SDK's `Verifier` defaults to "both-required" when it sees the hybrid
cryptosuite. Override via config:

```python
verifier = Verifier(hybrid_mode="classical_only")  # or "pq_only", "both_required"
```

## Issuing hybrid credentials

### Python

```bash
pip install 'vouch-protocol[pq]'
```

```python
from vouch import generate_identity, Signer

keys = generate_identity("agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed = signer.sign_credential_hybrid(intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})
```

### TypeScript

```bash
npm install @vouch-protocol-official/sdk @noble/post-quantum
```

```ts
import { Signer, generateIdentity } from '@vouch-protocol-official/sdk';

const keys = await generateIdentity('agent.example.com');
const signer = new Signer({ privateKey: keys.privateKeyJwk, did: keys.did });
const signed = await signer.signCredentialHybrid({
  intent: {
    action: 'submit_claim',
    target: 'claim:HC-001',
    resource: 'https://insurance.example.com/claims/HC-001',
  },
});
```

### Go

Hybrid signing is built into the sidecar:

**macOS / Linux**

```bash
./vouch-sidecar --did did:web:agent.example.com --hybrid --port 8877
```

**Windows (PowerShell)**

```powershell
.\vouch-sidecar.exe --did did:web:agent.example.com --hybrid --port 8877
```

All `/sign` requests now produce hybrid credentials.

## Test vector

Canonical hybrid test vector at `test-vectors/hybrid-eddsa-mldsa44/vector.json`.
Python, TypeScript, and Go all verify the same vector byte-identically.
The vector includes the Ed25519 seed, ML-DSA-44 keypair, signed
credential, and expected SHA-256 of the canonical form.

To regenerate:

```bash
cd test-vectors/hybrid-eddsa-mldsa44
PYTHONPATH=../.. python generate.py
```

## Migration sequence

The hybrid profile is the middle step in a three-phase migration aligned
with NIST CNSA 2.0:

1. **Current**: Classical Ed25519 default, hybrid OPTIONAL
2. **As CNSA 2.0 phase-in advances**: hybrid becomes RECOMMENDED for regulated sectors
3. **Long-term**: classical-only signatures reach end-of-life; hybrid or pure-PQ REQUIRED

Implementers in regulated sectors should adopt hybrid TODAY for credentials
that need long retention (multi-year audit trails). Classical-only
remains fine for short-lived ephemeral credentials.

## Implementation files

| File | Language | Purpose |
|---|---|---|
| `vouch/data_integrity_hybrid.py` | Python | `build_hybrid_proof`, `verify_hybrid_proof` |
| `packages/sdk-ts/src/data-integrity-hybrid.ts` | TypeScript | Same surface |
| `go-sidecar/signer/data_integrity_hybrid.go` | Go | Same surface, uses Cloudflare CIRCL |

The full implementation guide is at `docs/hybrid-pq-implementation-guide.md`.

## Performance numbers

On Apple M2 (2024):

| Operation | Ed25519 only | Hybrid (Ed25519 + ML-DSA-44) |
|---|---|---|
| Sign | ~50 µs | ~3 ms |
| Verify | ~150 µs | ~3 ms |
| Credential size | ~700 bytes | ~3.2 KB |

Hybrid is ~20-60x slower for signing and ~5x bigger on the wire. For most
agent workflows (one credential per minute or less), this is acceptable.
For high-throughput inner loops (>100 credentials/second), consider
classical-only and rotate the underlying key more frequently.

## HTTP header size

A hybrid credential exceeds typical HTTP header size limits (8 KB).
Transmit credentials in the request body, not headers:

```
POST /api/action HTTP/1.1
Content-Type: application/vc+vouch

{...the full credential...}
```

The legacy v0.x flow used a `Vouch-Token` header; that is classical-only.
v1.0+ flows always send in the body.

## Common errors

- **`pip install vouch-protocol[pq]` fails on macOS**: the `pqcrypto`
  dependency needs `liboqs`. `brew install liboqs` and retry.
- **`pip install vouch-protocol[pq]` fails on Ubuntu**: needs
  `build-essential` and `libssl-dev`. `apt install build-essential libssl-dev`.
- **Verifier rejects hybrid signature with "unknown cryptosuite"**:
  the verifier is on an older version. Upgrade to v1.6+.
- **Verifier rejects with "second-preimage attack detected"**: extremely
  rare. If real, the two signatures don't agree on the same canonical
  bytes (PAD-040 invariant violated). Open an issue with the credential.
