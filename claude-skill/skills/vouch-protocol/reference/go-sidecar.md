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
./vouch-sidecar --did did:web:agent.example.com --port 8877 --dev
```

**Windows (PowerShell)**

```powershell
.\vouch-sidecar.exe --did did:web:agent.example.com --port 8877 --dev
```

Flags:

| Flag | Default | Notes |
|---|---|---|
| `--did` | the saved identity | The agent DID this sidecar signs as. Needed only when the keystore holds more than one identity, or with `--dev` |
| `--host` | 127.0.0.1 | Address to listen on. To listen beyond this machine, also set `VOUCH_SIDECAR_TOKEN`; `/sign` then requires `Authorization: Bearer <token>` |
| `--port` | 8877 | HTTP listen port |
| `--key` | the keystore | Path to a private Ed25519 JWK file or an identity file, in place of the identity `vouch init` saved under `~/.vouch/keys`. `VOUCH_ED25519_SEED` (64 hex characters) is the alternative |
| `--dev` | off | Local testing: use a random key that lasts for this run only |
| `--allowlist` | sign any action | Path to an allow-list JSON file such as the one `vouch onboard` writes. Only the actions it names are signed |
| `--default-validity` | 5m | How long a credential lasts when the caller sends no `validSeconds`. Also `VOUCH_SIDECAR_DEFAULT_VALIDITY` |
| `--max-validity` | 1h | Longest validity a caller may ask for. Also `VOUCH_SIDECAR_MAX_VALIDITY` |
| `--hybrid` | off | Enable post-quantum signing (the default proof plus an ML-DSA-44 proof), with the ML-DSA-44 key saved in the identity by `vouch init`. A key from `VOUCH_ED25519_SEED` or a bare JWK file carries no post-quantum key, so `--hybrid` needs the saved identity or its file |
| `--sensitive` / `-s` | off | Wrap responses in JWE so credentials are encrypted in flight |
| `--otel-endpoint` | off | OpenTelemetry collector address, such as `http://localhost:4318`. Each signing request becomes a trace span |
| `--verbose` | off | Log every request |

With no flags at all, `vouch-sidecar` signs as the identity `vouch init` saved.

The caller decides how long each credential lasts by sending `validSeconds`.
`--default-validity` is what a caller gets when it sends none, and
`--max-validity` is the ceiling. Change either by restarting the sidecar with a
new value.

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

With `--hybrid`, `proof` is an array of two proofs, one `eddsa-jcs-2022`
(`proofValue` in base58btc) and one `mldsa44-jcs-2024` (`proofValue` in
base64url-nopad multibase), over the same document.

### Other endpoints

- `GET /health` - readiness, the validity settings, and the time of the last signature
- `GET /did` - return the configured DID and verification method
- `GET /pubkey` - return the Multikey-encoded public keys
- `GET /.well-known/did.json` - the DID document for the signing key
- `POST /sign/hybrid` - explicit post-quantum signing endpoint

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

cred, err := s.Sign(signer.SignOptions{
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
| `signer` | Credential issuance and verification (Ed25519 and the post-quantum proof set) |
| `signer.NewStatusList`, etc. | BitstringStatusList primitives |
| `cmd/vouch-sidecar` | HTTP daemon entrypoint |
