# Quickstart

Sign your first Vouch credential in five minutes.

## Python

```bash
pip install vouch-protocol
```

```python
from vouch import Signer, Verifier, build_vouch_credential

# Generate or load a signer
signer = Signer.generate(did="did:web:agent.example.com")

# Build and sign a credential for an action
credential = build_vouch_credential(
    issuer_did="did:web:agent.example.com",
    intent={
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
)
signed = signer.sign_credential(credential)

# Verify
verifier = Verifier()
result = verifier.verify(signed)
assert result.ok
```

## TypeScript

```bash
npm install vouch-protocol
```

```ts
import { Signer, Verifier, buildVouchCredential } from 'vouch-protocol';

const signer = await Signer.generate({ did: 'did:web:agent.example.com' });

const credential = buildVouchCredential({
    issuerDid: 'did:web:agent.example.com',
    intent: {
        action: 'submit_claim',
        target: 'claim:HC-001',
        resource: 'https://insurance.example.com/claims/HC-001',
    },
});
const signed = await signer.signCredential(credential);

const verifier = new Verifier();
const result = await verifier.verify(signed);
console.assert(result.ok);
```

## Go (sidecar)

```bash
go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest
vouch-sidecar --did did:web:agent.example.com --port 8877
```

```bash
curl -X POST http://localhost:8877/sign \
    -H 'content-type: application/json' \
    -d '{
        "intent": {
            "action": "submit_claim",
            "target": "claim:HC-001",
            "resource": "https://insurance.example.com/claims/HC-001"
        }
    }'
```

## Hosting a did:web DID Document

Publish a JSON document at `https://your-domain.example.com/.well-known/did.json`
listing your verification methods. The SDK helper writes it for you:

```python
from vouch import publish_did_web

publish_did_web(signer, output_path="public/.well-known/did.json")
```

Then your domain's HTTPS server (Vercel, Netlify, GitHub Pages,
Cloudflare Workers) serves the file, and verifiers resolve it on demand.

## Next steps

- Read `credential-format.md` to understand the wire format.
- Read `delegation.md` to chain credentials across principals.
- Read `revocation.md` to handle key compromise and per-credential retraction.
- Read `post-quantum.md` if your deployment must be PQ-ready.
