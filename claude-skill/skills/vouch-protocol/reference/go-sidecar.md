# Go Sidecar Reference

Long-running daemon that holds private signing keys in its own process,
isolating them from the LLM. Other languages call it over HTTP.

## Install

```bash
go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest
```

Or build from source:

```bash
git clone https://github.com/vouch-protocol/vouch
cd vouch/go-sidecar
go build ./cmd/vouch-sidecar
```

## Run

**macOS / Linux**

```bash
./vouch-sidecar --did did:web:agent.example.com --port 8877
```

**Windows (PowerShell)**

```powershell
.\vouch-sidecar.exe --did did:web:agent.example.com --port 8877
```

Flags:

| Flag | Default | Notes |
|---|---|---|
| `--did` | required | The agent DID this sidecar represents |
| `--port` | 8877 | HTTP listen port |
| `--key` | platform key store | Path to JWK private key file (alternative to KMS) |
| `--hybrid` | off | Enable hybrid post-quantum signing (default plus ML-DSA-44) |
| `--sensitive` / `-s` | off | Wrap responses in JWE so credentials are encrypted in flight |
| `--verbose` | off | Detailed startup logs |

## HTTP API

### POST /sign

Sign a credential.

Request:
```json
{
    "intent": {
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001"
    },
    "validSeconds": 300,
    "reputationScore": 85,
    "delegationChain": [],
    "credentialStatus": null
}
```

Response (`200 OK`):
```json
{
    "@context": ["https://www.w3.org/ns/credentials/v2", "..."],
    "type": ["VerifiableCredential", "VouchCredential"],
    "issuer": "did:web:agent.example.com",
    "validFrom": "...",
    "validUntil": "...",
    "credentialSubject": {
        "id": "did:web:agent.example.com",
        "intent": {...}
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:web:agent.example.com#key-1",
        "proofPurpose": "assertionMethod",
        "created": "...",
        "proofValue": "z..."
    }
}
```

With `--hybrid`, `cryptosuite` is `hybrid-eddsa-mldsa44-jcs-2026` and
`proofValue` carries the concatenated Ed25519 + ML-DSA-44 signatures.

### Other endpoints

- `GET /health` - liveness check
- `GET /did` - return the configured DID and verification method
- `GET /pubkey` - return Multikey-encoded public key
- `POST /sign/hybrid` - explicit hybrid signing endpoint

## Calling from Python

```python
import httpx

resp = httpx.post(
    "http://localhost:8877/sign",
    json={
        "intent": {"action": "...", "target": "...", "resource": "..."},
        "validSeconds": 300,
    },
)
signed_credential = resp.json()
```

## Calling from TypeScript

```ts
const resp = await fetch('http://localhost:8877/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        intent: { action: '...', target: '...', resource: '...' },
        validSeconds: 300,
    }),
});
const signed = await resp.json();
```

Or use the `VouchClient` from `@vouch-protocol-official/sdk`.

## Why a sidecar?

Three reasons:

1. **Prompt injection cannot exfiltrate keys.** Even if the LLM is
   jailbroken to leak its context, the private key is in a separate
   process, not in the context.
2. **Polyglot stacks** can all share one signing service without each
   embedding a key.
3. **Key rotation** happens in one place, not N places.

## Deployment patterns

### Docker

```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /vouch-sidecar ./cmd/vouch-sidecar

FROM gcr.io/distroless/static
COPY --from=build /vouch-sidecar /vouch-sidecar
ENTRYPOINT ["/vouch-sidecar"]
```

### Kubernetes sidecar container

Run as a sidecar in the same pod as the LLM application container.
They share `localhost` so the LLM never reaches outside the pod for
signing. Mount the private key from a secret.

### KMS-backed

Pass a `--kms-config` flag pointing at an AWS / GCP / Azure KMS config.
The sidecar fetches signing capability from KMS without ever holding
the raw private key.

## Go API surface (for direct use)

If you embed the sidecar into another Go service:

```go
import "github.com/vouch-protocol/vouch/go-sidecar/signer"

s, _ := signer.New(signer.Config{
    DID: "did:web:agent.example.com",
    PrivateKeyJWK: "...",
})

cred, err := s.SignCredential(signer.SignCredentialOptions{
    Intent: map[string]any{
        "action":   "submit_claim",
        "target":   "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
    ValidSeconds: 300,
})
```

## Modules quick-map

| Package | Purpose |
|---|---|
| `signer` | Credential issuance and verification (Ed25519 + hybrid PQ) |
| `signer.NewStatusList`, etc. | BitstringStatusList primitives |
| `cmd/vouch-sidecar` | HTTP daemon entrypoint |
