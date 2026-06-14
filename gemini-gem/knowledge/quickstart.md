# Quickstart

Sign your first Vouch credential in five minutes.

## Python

```bash
pip install vouch-protocol
```

```python
from vouch import generate_identity, Signer, Verifier, build_vouch_credential

# Generate an identity, then build a signer from it
keys = generate_identity("agent.example.com")  # returns a KeyPair
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

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

# Verify. verify_credential returns a (is_valid, passport) tuple.
is_valid, passport = Verifier.verify_credential(signed, public_key=keys.public_key_jwk)
assert is_valid
```

## TypeScript

```bash
npm install @vouch-protocol-official/sdk
```

```ts
import { Signer, Verifier, generateIdentity } from '@vouch-protocol-official/sdk';

const keys = await generateIdentity('agent.example.com');
const signer = new Signer({ privateKey: keys.privateKeyJwk, did: keys.did });

// signCredential takes an options object whose required field is `intent`.
const signed = await signer.signCredential({
    intent: {
        action: 'submit_claim',
        target: 'claim:HC-001',
        resource: 'https://insurance.example.com/claims/HC-001',
    },
});

// verifyCredential returns { isValid, passport, error }.
const result = await Verifier.verifyCredential(signed);
console.assert(result.isValid);
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

## Other platforms

Beyond Python, TypeScript, and Go, the same protocol is available on more
platforms through one shared Rust core, so they all interop byte for byte:

```bash
# Browser and Node.js (WebAssembly)
npm install @vouch-protocol-official/core-wasm

# .NET
dotnet add package VouchProtocol.Core
```

Swift (iOS and macOS), JVM (Java and Kotlin), and C/C++ are also available. See
`language-sdks.md` for the full list, what each one covers, and how to add it.

## Next steps

- Read `language-sdks.md` for every platform and its install command.
- Read `credential-format.md` to understand the wire format.
- Read `delegation.md` to chain credentials across principals.
- Read `revocation.md` to handle key compromise and per-credential retraction.
- Read `post-quantum.md` if your deployment must be PQ-ready.
