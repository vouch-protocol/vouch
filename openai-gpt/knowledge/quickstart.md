# Quickstart

Make an agent sign every tool call in one line, or sign a single credential by
hand. Both take about five minutes.

## Fastest start, no code

If you just want Vouch working without writing any code:

```bash
# Install on Linux or macOS (on Windows: pip install vouch-protocol)
curl -fsSL https://vouch-protocol.com/install.sh | sh

# Run vouch with no arguments and choose from the menu
vouch
```

The menu covers the two common goals: signing your git commits (a verified badge
on GitHub) and giving an agent its own identity. For a full agent setup with
recommended defaults and no questions, run:

```bash
vouch onboard --quick
```

That writes a working identity, allow-list, verifier, and heartbeat config in one
command. When you are ready to write code against the SDK, continue below.

## Python: make an agent sign every tool call (one line)

```bash
pip install vouch-protocol
vouch init --yes        # provisions and saves an identity, prints the next line
```

```python
from vouch import protect, verify, current_credential

# Your normal tool. It says nothing about Vouch.
def charge_invoice(invoice_id, amount):
    return f"charged {amount} on {invoice_id}"

# The one line that adds Vouch: wrap your tools. Every call is now signed in
# Python before it runs. Identity is resolved automatically from the keystore
# that `vouch init` wrote (or from VOUCH_PRIVATE_KEY / VOUCH_DID).
agent_tools = protect([charge_invoice])

# When a tool runs, the signed credential is available without any plumbing.
agent_tools[0]("INV-42", 99.0)

# Receiving side: verify in one line (auto-resolves the issuer via did:web).
ok, passport = verify(current_credential())
assert ok
```

`protect` works for plain functions and for CrewAI, LangChain, AutoGen, AutoGPT,
Vertex AI, Google, and ADK tools. See `integrations.md` for per-framework
one-liners and `autosign()`.

## Python: sign a single credential by hand

```python
from vouch import generate_identity, Signer, Verifier

keys = generate_identity("agent.example.com")  # returns a KeyPair
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

# sign_credential takes the intent directly (action, target, resource required).
signed = signer.sign_credential(intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})

# verify_credential returns a (is_valid, passport) tuple.
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

**macOS / Linux**

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

**Windows (PowerShell)**

```powershell
$body = @{
    intent = @{
        action   = "submit_claim"
        target   = "claim:HC-001"
        resource = "https://insurance.example.com/claims/HC-001"
    }
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8877/sign" -ContentType "application/json" -Body $body
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
