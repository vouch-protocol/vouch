/**
 * Vouch Protocol Help Guides
 *
 * Long-form articles organized into sections. Each article is structured
 * so a returning user can skim section headings, jump to the part they
 * need, and recover working context after time away.
 *
 * Every article is grounded in shipped code, no aspirational steps.
 */

export interface HelpArticle {
  /** URL anchor */
  id: string;
  /** Short title shown in sidebar nav and article header */
  title: string;
  /** One-line summary for the section index */
  summary: string;
  /** Markdown-ish content body (see renderer for supported syntax) */
  body: string;
}

export interface HelpSection {
  id: string;
  title: string;
  description: string;
  /** Top-level agent domain for the page toggle. Defaults to 'agents' (software agents). */
  domain?: 'agents' | 'robotics';
  articles: HelpArticle[];
}

export const HELP_SECTIONS: HelpSection[] = [
  {
    id: 'getting-started',
    title: 'Getting Started',
    description: 'Pick a language, install the SDK, and prove the sign-and-verify loop works in your dev env (no domain, no hosting) in under five minutes. Each quickstart ends with the two-line change to graduate to production.',
    articles: [
      {
        id: 'quickstart-python',
        title: 'Python Quickstart',
        summary: 'Five-minute path from pip install to a sign-and-verify loop running entirely in your dev env.',
        body: `
## Install

\`\`\`bash
# Linux and macOS: one line (on Windows, use pip below)
curl -fsSL https://vouch-protocol.com/install.sh | sh

# Or with pip on any platform
pip install vouch-protocol
\`\`\`

The hybrid post-quantum profile (\`hybrid-eddsa-mldsa44-jcs-2026\`) is bundled by default; nothing else to install.

Not ready to write code yet? Run \`vouch\` with no arguments for a short menu (sign your git commits, or create an agent identity), or run \`vouch onboard --quick\` to generate a full agent setup with recommended defaults in one command.

## Step 1 - Sign and verify locally

Start in your dev env. No domain, no hosting, no internet. Everything runs in your own Python process:

\`\`\`python
from vouch.keys import generate_identity
from vouch.signer import Signer
from vouch.verifier import Verifier

# Generate an in-memory identity. The "domain" string is just a label
# inside the DID; nothing is published anywhere yet.
identity = generate_identity(domain="localhost")

signer = Signer(
    private_key=identity.private_key_jwk,
    did=identity.did,
)

token = signer.sign({
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})

# trusted_roots is the local-dev escape hatch: in production the verifier
# fetches did.json from the issuer's domain instead.
verifier = Verifier(
    trusted_roots={identity.did: identity.public_key_jwk},
    allow_did_resolution=False,
)
ok, passport = verifier.check_vouch(token)
assert ok
print("verified intent:", passport.payload)
\`\`\`

That round-trip is the entire credential layer: keypair, signed action, verified action, all in your own process. No webserver, no public DNS, no .well-known path.

## Step 2 - Switch to the modern VC + Data Integrity proof

The legacy JWS form above stays for backward compatibility. New code should prefer the W3C Verifiable Credential form with a Data Integrity proof (\`eddsa-jcs-2022\`):

\`\`\`python
# sign takes the intent directly (action, target, resource required).
signed = signer.sign(
    intent={
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
    valid_seconds=300,
)
print(signed["proof"]["proofValue"])
\`\`\`

Verify it with the same Verifier (the credential carries its issuer DID, the Verifier looks up the key in \`trusted_roots\`):

\`\`\`python
import asyncio
from vouch import Verifier

verifier = Verifier(
    trusted_roots={identity.did: identity.public_key_jwk},
    allow_did_resolution=False,
)
result = asyncio.run(verifier.verify(signed))
print(result.valid, result.reasons)
\`\`\`

For the hybrid post-quantum profile, swap \`sign\` for \`sign_hybrid\`. The required \`pqcrypto\` library is already bundled with \`vouch-protocol\`, so nothing else to install. Everything else stays the same.

## Step 3 - When you are ready to publish

The local trial used \`did:web:localhost\` and an in-memory keypair. Taking an agent to production is a two-line change:

1. Replace \`domain="localhost"\` with a real domain you control.
2. Publish the DID Document at \`https://your-domain/.well-known/did.json\` so any verifier on the internet can resolve it.

Then drop \`trusted_roots\` from your Verifier:

\`\`\`python
# Production: verifier resolves the DID over HTTPS at verification time.
verifier = Verifier()
ok, passport = verifier.check_vouch(token)
\`\`\`

Generate the production keypair and DID Document with the CLI:

\`\`\`bash
vouch init --domain agent.example.com
\`\`\`

That writes the private key into your platform's secure key store (Keychain on macOS, DPAPI on Windows, secret-service on Linux) and emits a did.json you can publish.

## What you have now

- A signed-and-verified credential running entirely in a Python REPL
- A modern VC + Data Integrity form, ready for the wire
- A clear two-line upgrade path when you decide to expose the agent to the public internet

Next: try [signing with the hybrid post-quantum profile](#hybrid-pq) or [adding a delegation chain](#delegation-chains).
`,
      },
      {
        id: 'quickstart-typescript',
        title: 'TypeScript Quickstart',
        summary: 'Same flow in Node. No domain, no hosting; cross-verifies with Python-signed credentials.',
        body: `
## Install

\`\`\`bash
npm install @vouch-protocol-official/sdk
\`\`\`

## Step 1 - Sign and verify locally

Start in Node. No webserver, no domain, no internet. Save as \`try-vouch.ts\` and run with \`tsx try-vouch.ts\` (or compile and run with \`node\`):

\`\`\`ts
import {
  Signer,
  Verifier,
  generateIdentity,
} from '@vouch-protocol-official/sdk';

async function main() {
  // Generate an in-memory identity. The "domain" string is just a label
  // inside the DID; nothing is published anywhere yet.
  const identity = await generateIdentity('localhost');

  const signer = new Signer({
    privateKey: identity.privateKeyJwk,
    did: identity.did!,
  });

  // sign takes the intent directly (action, target, resource).
  const signed = await signer.sign({
    intent: {
      action: 'submit_claim',
      target: 'claim:HC-001',
      resource: 'https://insurance.example.com/claims/HC-001',
    },
    validSeconds: 300,
  });
  console.log('signed proof value:', signed.proof.proofValue);

  // trustedRoots is the local-dev escape hatch: in production the verifier
  // fetches did.json from the issuer's domain instead.
  const verifier = new Verifier({
    trustedRoots: { [identity.did!]: identity.publicKeyJwk },
    allowDidResolution: false,
  });
  const result = await verifier.verify(signed);
  console.log('valid:', result.valid, 'reasons:', result.reasons);
}

main().catch(console.error);
\`\`\`

That round-trip is the entire credential layer: keypair, signed credential with a Data Integrity proof (\`eddsa-jcs-2022\`), and verification, all in one Node process.

## Step 2 - When you are ready to publish

The local trial used \`did:web:localhost\` and an in-memory keypair. To take an agent to production:

1. Pass your real domain to \`generateIdentity\` (or generate once with the Python CLI and import the JWK).
2. Publish the DID Document at \`https://your-domain/.well-known/did.json\`.

Then drop \`trustedRoots\` and \`allowDidResolution\`:

\`\`\`ts
const verifier = new Verifier();              // resolves did:web over HTTPS
const result = await verifier.verify(signed);
\`\`\`

## Cross-language interop

A credential signed in Python verifies byte-identically in TypeScript and vice versa, thanks to RFC 8785 JCS canonicalization. The test vectors at [test-vectors/hybrid-eddsa-mldsa44/](https://github.com/vouch-protocol/vouch/tree/main/test-vectors/hybrid-eddsa-mldsa44) exercise this.

## Browser vs Node

The TypeScript SDK works in both. In Node, the example above runs as-is. In the browser, key storage falls back to IndexedDB (with optional WebAuthn-gated unlock) rather than a platform key store; the sign/verify APIs are otherwise identical.
`,
      },
      {
        id: 'quickstart-go',
        title: 'Go Sidecar Quickstart',
        summary: 'Run the signing daemon on your laptop. Sign credentials from any language over localhost HTTP.',
        body: `
## Step 1 - Build and run on localhost

Build the binary from source:

\`\`\`bash
git clone https://github.com/vouch-protocol/vouch
cd vouch/go-sidecar
go build ./cmd/vouch-sidecar
\`\`\`

Or via go install:

\`\`\`bash
go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest
\`\`\`

Run it locally with a placeholder DID. The sidecar binds to localhost only by default; no inbound firewall change is needed:

\`\`\`bash
./vouch-sidecar --did did:web:localhost --port 8877
\`\`\`

\`\`\`powershell
.\\vouch-sidecar.exe --did did:web:localhost --port 8877
\`\`\`

Optional flags:

- \`--sensitive\` or \`-s\` - wrap the response in a JWE so the credential is encrypted in flight
- \`--hybrid\` - use the W3C-aligned hybrid post-quantum cryptosuite (\`hybrid-eddsa-mldsa44-jcs-2026\`)
- \`--verbose\` - detailed startup logs

## Step 2 - Sign a credential over localhost

Any language can sign by POSTing to the sidecar on \`127.0.0.1\`:

\`\`\`bash
curl -X POST http://localhost:8877/sign \\
  -H 'Content-Type: application/json' \\
  -d '{
    "subjectDid": "did:web:localhost",
    "intent": {
      "action": "submit_claim",
      "target": "claim:HC-001",
      "resource": "https://insurance.example.com/claims/HC-001"
    },
    "validSeconds": 300
  }'
\`\`\`

\`\`\`powershell
$body = @{
  subjectDid = "did:web:localhost"
  intent = @{
    action   = "submit_claim"
    target   = "claim:HC-001"
    resource = "https://insurance.example.com/claims/HC-001"
  }
  validSeconds = 300
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8877/sign -ContentType 'application/json' -Body $body
\`\`\`

The response is the full signed Verifiable Credential. Pipe it into your Python or TypeScript verifier (configured with \`trusted_roots\` / \`trustedRoots\` pointing at the sidecar's public key, fetched from \`GET http://localhost:8877/.well-known/did.json\`) to close the loop.

## Step 3 - When you are ready to publish

Three things change when you graduate to production:

1. Replace \`did:web:localhost\` with the DID anchored at your real domain.
2. Run the sidecar on your service network (not localhost) and front it with mTLS or your platform's internal-call auth.
3. Verifiers stop using \`trustedRoots\` and resolve the DID over HTTPS instead.

The signing code in your agent does not change. Only the URL the sidecar exposes and the DID string change.

## Why a sidecar?

The Identity Sidecar pattern keeps the private signing key out of the LLM's process. The LLM emits a tool-call object; the orchestration layer (your Python or TypeScript code) asks the sidecar to sign on the agent's behalf; the sidecar returns a credential bound to the action.

This makes prompt-injection key-exfiltration impossible: even if the LLM is jailbroken to leak its context, the key is not in that context. The local-dev sidecar gives you the exact same isolation boundary on your laptop that you will have in production.
`,
      },
      {
        id: 'quickstart-swift',
        title: 'Swift Quickstart',
        summary: 'Add the VouchCore Swift package and run a canonicalize-and-verify loop on iOS or macOS. A thin wrapper over the one Rust core.',
        body: `
## Install

VouchCore ships through Swift Package Manager from its own repository, \`vouch-protocol/vouch-swift\` (SwiftPM resolves a package from the repository root). The native code is a prebuilt XCFramework hosted on the \`swift-v0.1.0\` release, so you do not need a Mac toolchain to build the Rust core yourself.

In Xcode use File then Add Package Dependencies and paste \`https://github.com/vouch-protocol/vouch-swift.git\`, or add it to your \`Package.swift\`:

\`\`\`swift
.package(url: "https://github.com/vouch-protocol/vouch-swift", from: "0.1.0"),
// then depend on the product:
.product(name: "VouchCore", package: "vouch-swift"),
\`\`\`

Supports iOS 13+ and macOS 12+.

VouchCore is listed on the [Swift Package Index](https://swiftpackageindex.com/vouch-protocol/vouch-swift), where you can browse the generated documentation and the platform compatibility matrix.

## Canonicalize and verify

Everything runs on device. The \`Vouch\` facade gathers the lower-level UniFFI functions behind a discoverable surface:

\`\`\`swift
import VouchCore

// RFC 8785 (JCS) canonicalization. Byte-identical to every other Vouch SDK.
let canon = try Vouch.canonicalize(#"{"b":1,"a":2}"#)   // {"a":2,"b":1}

// Verify a Data Integrity proof (eddsa-jcs-2022) on a signed credential.
let ok = try Vouch.verifyProof(signedCredentialJson, publicKey: publicKey)

// Proof plus validity window in one call.
let result = try Vouch.verify(signedCredentialJson, publicKey: publicKey, now: "2026-04-26T10:02:00Z")
\`\`\`

\`Vouch.generateEd25519()\` returns a key pair and \`Vouch.sign(...)\` attaches the proof. VouchCore is a thin layer over the canonical Rust core via UniFFI, so a credential verified on iOS matches the exact bytes from every other SDK.
`,
      },
      {
        id: 'quickstart-jvm',
        title: 'JVM (Java and Kotlin) Quickstart',
        summary: 'One Gradle coordinate, then canonicalize and verify from Java or Kotlin over the shared Rust core.',
        body: `
## Install

\`\`\`kotlin
// build.gradle.kts
dependencies { implementation("com.vouchprotocol:vouch-core:0.1.0") }
\`\`\`

The host native library is bundled inside the jar, so it loads with no extra setup.

## Java

The \`Vouch\` class is a thin JNA layer over the core's C ABI. Binary values are base64 strings; credentials and proofs are JSON strings:

\`\`\`java
import com.vouchprotocol.core.Vouch;

String canon = Vouch.canonicalize("{\\"b\\":1,\\"a\\":2}");   // {"a":2,"b":1}
String kp = Vouch.generateEd25519();                       // {seed_b64, public_b64, multikey, did_key}
String signed = Vouch.sign(credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
boolean ok = Vouch.verifyProof(signed, publicB64);
\`\`\`

## Kotlin

Kotlin can call the same Java class, or use the generated UniFFI binding bundled in the module, which takes native \`ByteArray\` keys instead of base64. Both delegate to the canonical Rust core, so the JVM verifies with the exact same bytes as every other SDK.
`,
      },
      {
        id: 'quickstart-dotnet',
        title: '.NET Quickstart',
        summary: 'dotnet add package, then canonicalize and verify from C# over the shared Rust core.',
        body: `
## Install

\`\`\`bash
dotnet add package VouchProtocol.Core
\`\`\`

## Canonicalize, sign, verify

The static \`Vouch\` class is a P/Invoke wrapper over the canonical Rust core. Binary values are base64 strings; credentials and proofs are JSON strings:

\`\`\`csharp
using VouchProtocol.Core;

string canon = Vouch.Canonicalize("{\\"b\\":1,\\"a\\":2}");   // {"a":2,"b":1}
string kp = Vouch.GenerateEd25519();
string signed = Vouch.Sign(credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
bool ok = Vouch.VerifyProof(signed, publicB64);
\`\`\`

On error the core returns null and the wrapper throws a \`VouchException\`; the native string is freed for you. .NET verifies with the exact same bytes as every other SDK.
`,
      },
      {
        id: 'quickstart-c',
        title: 'C and C++ Quickstart',
        summary: 'Link the C bindings shipped with the core. Every returned string is freed with vouch_string_free.',
        body: `
## What you get

These are the C bindings shipped with the core, not a reimplementation. The canonical Rust core exposes a plain C ABI through a cbindgen header. The package gives you \`include/vouch_core.h\`, a prebuilt \`lib/libvouch_core_uniffi.so\`, an \`examples/example.c\` with a \`Makefile\`, and a \`CMakeLists.txt\`. Anything that can call C links against it, including C++ and .NET P/Invoke.

## Build

\`\`\`bash
make run     # compiles example.c against ../lib and runs it
# flags: -I../include  -L../lib -lvouch_core_uniffi
\`\`\`

## Canonicalize and verify in C

Every value crossing the ABI is a NUL-terminated UTF-8 string: JSON for credentials and proofs, base64 for binary. Returned strings are heap allocated and must be freed with \`vouch_string_free\`. On error a function returns NULL and writes a message into \`err_out\`:

\`\`\`c
#include "vouch_core.h"

char *err = NULL;
char *canon = vouch_canonicalize("{\\"b\\":1,\\"a\\":2}", &err);   // {"a":2,"b":1}
vouch_string_free(canon);

char *res = vouch_verify_proof(signed_credential_json, public_key_b64, &err);  // "true"/"false"
if (res) vouch_string_free(res); else vouch_string_free(err);
\`\`\`

The header also exposes \`vouch_sign\`, \`vouch_verify\`, delegation, dual-proof ML-DSA-44 verify, and BitstringStatusList revocation. A credential verified from C matches the exact bytes of every other SDK.
`,
      },
      {
        id: 'quickstart-wasm',
        title: 'Browser and Node Quickstart (WebAssembly)',
        summary: 'npm install the WASM core, initialize it once, then canonicalize and verify in the browser or Node.',
        body: `
## Install

\`\`\`bash
npm install @vouch-protocol-official/core-wasm
\`\`\`

This is the canonical Rust core compiled to WebAssembly. Binary values are base64 strings; credentials and proofs are JSON strings.

## Browser

\`\`\`js
import init, * as core from '@vouch-protocol-official/core-wasm';
await init(); // fetches the .wasm next to the module

core.canonicalize('{"b":1,"a":2}');   // {"a":2,"b":1}
const kp = JSON.parse(core.generateEd25519());
const signed = core.sign(JSON.stringify(myCredential), kp.seed_b64, kp.did_key + '#key-1', '2026-04-26T10:00:00Z');
const ok = core.verifyProof(signed, kp.public_b64);   // true
\`\`\`

## Node.js (ESM)

There is no fetch in Node, so pass the wasm bytes to \`init\`. Key generation and ML-DSA signing also need a CSPRNG; under Node ESM make Web Crypto global first (verification does not need it):

\`\`\`js
import init, * as core from '@vouch-protocol-official/core-wasm';
import { readFileSync } from 'fs';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
await init({ module_or_path: readFileSync(new URL('@vouch-protocol-official/core-wasm/vouch_core_wasm_bg.wasm', import.meta.url)) });
\`\`\`

With Next.js App Router, call \`init()\` in a client component before using the API. The WASM build verifies with the exact same bytes as every other SDK.
`,
      },
      {
        id: 'agent-trust-index',
        title: 'The Agent Trust Index',
        summary: 'An open benchmark that scans public AI agents and scores whether each one can prove its identity. The first sweep found 98.7 percent cannot.',
        body: `
## What it is

The Agent Trust Index is an open benchmark. It scans public AI agents and scores a single question for each: can this agent prove who it is? Not whether it is good, safe, or useful, just whether it has a cryptographic identity (a \`did:web\`) that resolves to a document carrying a real public key. It measures adoption of provable identity in the wild, not a self-declared registry field.

## The first sweep

The first sweep drew its agents from the public Model Context Protocol registry on 10 June 2026:

- **11,680** unique agents scanned
- **157** publish a resolvable \`did:web\` identity, about **1.3 percent**
- **98.7 percent** cannot prove who they are at all
- **69** of those 157 also carry a usable public key, a full **grade A**

The handful that can prove themselves are mostly finance and oracle agents, which fits: the agents that handle money are the first to bother with identity.

## How scoring works

Each agent is scored out of 100: **60 points** for a resolvable identity, **40 points** for that identity carrying a usable public key. A is 90 or above, then B, C, D, and F below 40. An agent with nothing scores zero. The 88 agents that resolve a DID but carry no usable key land around a C.

The full method is published at [/agent-trust-index/methodology](/agent-trust-index/methodology/). The data is real and the scan is reproducible.
`,
      },
    ],
  },

  {
    id: 'identity-and-signing',
    title: 'Identity & Signing',
    description: 'Manage your agent\'s identity and keys, sign with post-quantum crypto, and build delegation chains.',
    articles: [
      {
        id: 'did-management',
        title: 'Managing DIDs and Keys',
        summary: 'did:web vs did:key, where keys live, how to rotate.',
        body: `
## did:web vs did:key

**did:web** resolves over HTTPS to a DID Document at \`https://{domain}/.well-known/did.json\` (or a path-based variant). Good for production agents owned by an organization; the domain anchors trust.

**did:key** contains the public key inside the identifier itself. Self-resolving, no infrastructure. Good for ephemeral or fully decentralized agents.

Both are well-established DID methods. Vouch supports both natively.

## Key storage

The Python SDK uses your platform's secure key store by default (Keychain on macOS, DPAPI on Windows, secretstore on Linux). For server deployments, use the KMS abstraction at \`vouch/kms.py\`:

- AWS KMS (via boto3)
- GCP KMS (via google-cloud-kms)
- Azure Key Vault
- Local encrypted file with optional passphrase

## Key rotation

\`vouch/kms.py\` exposes \`RotatingKeyProvider\`. Configure the rotation window:

\`\`\`python
from vouch.kms import RotatingKeyProvider, KeyConfig
from datetime import timedelta

provider = RotatingKeyProvider(
  backend="aws-kms",
  key_id="alias/vouch-agent",
  rotation_period=timedelta(days=90),
)
\`\`\`

The DID Document publishes both the current and the previous keys during the overlap window, so in-flight credentials remain verifiable.
`,
      },
      {
        id: 'hybrid-pq',
        title: 'Signing with Post-Quantum Crypto',
        summary: 'How to make your signatures safe today and ready for the day quantum computers break Ed25519.',
        body: `
## Install dependencies

Python:

\`\`\`bash
pip install vouch-protocol
\`\`\`

(\`pqcrypto\` is bundled by default. It provides ML-DSA-44 via the PQClean reference and ships prebuilt wheels for all mainstream Python + platform combinations, so no compiler is needed.)

TypeScript:

\`\`\`bash
npm install @noble/post-quantum
\`\`\`

Go:

The Cloudflare circl dependency is already transitive in the sidecar.

## Sign

Python:

\`\`\`python
from vouch import Signer, generate_identity

keys = generate_identity("agent.example.com")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)
signed = signer.sign_hybrid(intent={
    "action": "submit_claim", "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
})
\`\`\`

TypeScript:

\`\`\`ts
import { Signer } from '@vouch-protocol-official/sdk';

const signer = await Signer.fromDidWithHybrid('did:web:agent.example.com');
const signed = await signer.signHybrid(credential);
\`\`\`

Go sidecar: pass \`--hybrid\` when starting the daemon.

## What the wire format looks like

The credential's \`proof\` field is an array of two Data Integrity proofs:

\`\`\`json
{
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "verificationMethod": "did:web:agent.example.com#key-ed25519",
      "proofPurpose": "assertionMethod",
      "proofValue": "z<base58btc(ed25519_sig)>"
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "mldsa44-jcs-2026",
      "verificationMethod": "did:web:agent.example.com#key-mldsa44",
      "proofPurpose": "assertionMethod",
      "proofValue": "z<base58btc(mldsa44_sig)>"
    }
  ]
}
\`\`\`

Both proofs cover the **same** JCS-canonicalized credential bytes (PAD-040 §3.3a same-bytes property under the dual-proof carrier).

> **v1.6.x transitional note.** The v1.6.x reference implementations emit a single composite proof with cryptosuite \`hybrid-eddsa-mldsa44-jcs-2026\` and a concatenated proofValue (\`base58btc(ed25519_sig || mldsa44_sig)\`). Verifiers that need to interoperate with v1.6.x credentials should accept that form. The v1.7 rewrite emits dual proofs as shown above.

## Verifier modes

A verifier can be configured for three modes:

- **Mode A (classical-only)** - iterate the \`proof\` array, validate the \`eddsa-jcs-2022\` proof, ignore the rest
- **Mode B (PQ-only)** - validate the \`mldsa44-jcs-2026\` proof, ignore the rest
- **Mode C (both required)** - validate every proof in the array, fail if any one is invalid

Mode C is the strictest. Mode A is useful for verifiers that have not yet been upgraded to support ML-DSA-44 (graceful downgrade during migration).

## DID Document layout

A hybrid agent publishes both keys in its DID Document:

\`\`\`json
{
  "id": "did:web:agent.example.com",
  "verificationMethod": [
    { "id": "...#key-ed25519", "type": "Multikey", "publicKeyMultibase": "z6Mk..." },
    { "id": "...#key-mldsa44", "type": "Multikey", "publicKeyMultibase": "z87..." }
  ]
}
\`\`\`

The verifier picks the appropriate verification method based on the credential's cryptosuite.

## Size and performance

| Property | Ed25519 only | Hybrid |
|---|---|---|
| Signature size | 64 bytes | 2,484 bytes |
| Credential size (typical) | ~700 B | ~3.2 KB |
| Sign time (M2) | ~50µs | ~3ms |
| Verify time (M2) | ~150µs | ~3ms |

Hybrid credentials exceed typical HTTP header size limits, so transmit them in the request body (Specification §13.4).
`,
      },
      {
        id: 'delegation-chains',
        title: 'Building Permission Chains',
        summary: 'When a human delegates to an agent that delegates to a sub-agent: how to track each step cryptographically.',
        body: `
## Why chains

When a human principal delegates to an agent that delegates to a sub-agent, you need a verifiable audit trail. The delegation chain answers: who authorized this action, and what was the scope at each step?

See it in the browser: the [interactive demos](/demos/#caveats) show a delegation chain whose caveats block an out-of-envelope action two hops down, and an irreversible action you can veto during a challenge window.

## Three rules

1. Each link is a signed Vouch credential where the **issuer** is the **subject** of the previous link.
2. Each link's \`resource\` MUST be a subset of the previous link's. You cannot delegate authority you do not have.
3. The chain must terminate at a principal (typically a human, or a system root).

## Build a chain in Python

Each credential chains under its parent with \`parent_credential=\`, which appends a delegation link and enforces resource narrowing automatically:

\`\`\`python
from vouch import Signer

principal = Signer(private_key=principal_priv_jwk, did="did:web:principal.example.com")
agent = Signer(private_key=agent_priv_jwk, did="did:web:agent.example.com")
sub_agent = Signer(private_key=sub_agent_priv_jwk, did="did:web:sub-agent.example.com")

# Principal delegates broad authority to the agent.
principal_link = principal.sign(
  intent={"action": "*", "target": "*", "resource": "claims"},
  valid_seconds=3600,
)

# Agent narrows and re-delegates to the sub-agent.
agent_link = agent.sign(
  intent={"action": "read", "target": "claim:HC-001", "resource": "claims/HC-001"},
  valid_seconds=300,
  parent_credential=principal_link,
)

# Sub-agent signs its actual action under the chain.
action = sub_agent.sign(
  intent={"action": "read", "target": "claim:HC-001", "resource": "claims/HC-001"},
  valid_seconds=60,
  parent_credential=agent_link,
)
\`\`\`

For the one-line path, the principal can issue the grant with \`vouch.delegate(...)\` and the agent's tools can be wrapped with \`vouch.protect([...], parent=grant)\`.

## Verify

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify_delegation_chain([principal_link, agent_link, action])
\`\`\`

The verifier walks every link, validates each signature, and confirms resource narrowing.
`,
      },
      {
        id: 'cross-device-identity',
        title: 'One Identity Across Your Devices',
        summary: 'Use the same identity on many devices without ever copying your private key: per-device keys, delegation, revocation, and recovery.',
        body: `
## The idea

Each device makes its own key and keeps it local. Your root identity signs a scoped permission slip (a delegation grant) for each device. A verifier ties any device's action back to your trusted root. Lose a device and you revoke it; lose all of them and you rebuild the root from recovery shares. What moves between devices is authority, never key material.

## Enroll a device

Each device mints its own key. The root delegates a scope to that device's DID.

\`\`\`python
from vouch import Agent, enroll_device

root = Agent("alice.example")
trusted_roots = {root.did: root.public_key_jwk}

phone = Agent()  # a did:key minted on the phone
grant = enroll_device(
    root,
    device_did=phone.did,
    action="charge",
    target="api.bank",
    resource="https://api.bank/invoices",
)
\`\`\`

## Sign and verify

The device signs with its own key, chained under the grant. A verifier checks the whole chain back to the trusted root.

\`\`\`python
from vouch import verify_delegated_chain

action = phone.sign(
    action="charge", target="api.bank",
    resource="https://api.bank/invoices/42", parent_credential=grant,
)
result = verify_delegated_chain([grant, action], trusted_roots=trusted_roots)
assert result.ok
\`\`\`

## Revoke a lost device

Track devices with a \`DeviceRegistry\` and revoke one when it is lost. Its actions stop verifying; other devices are unaffected.

\`\`\`python
from vouch import DeviceRegistry

registry = DeviceRegistry()
registry.enroll(phone.did, grant)
registry.revoke(phone.did)

result = verify_delegated_chain(
    [grant, action], trusted_roots=trusted_roots, revoked=registry.is_revoked
)
assert not result.ok
\`\`\`

## Recover the root

Split the root into shares so any threshold rebuild it. Distribute the shares to guardians or separate locations. Fewer than the threshold reveal nothing.

\`\`\`python
from vouch import split_identity, recover_identity, Signer

# Splitting needs the root's key, so create the root with allow_key_export=True.
root = Agent("alice.example", allow_key_export=True)
shares = split_identity(root, threshold=2, shares=3)

recovered = recover_identity([shares[0], shares[2]], did=root.did)
signer = Signer.from_keypair(recovered)
\`\`\`

The TypeScript SDK exposes the same helpers with camelCase names. See the runnable example in \`examples/cross_device_identity.py\`.
`,
      },
    ],
  },

  {
    id: 'deployment',
    title: 'Production Deployment',
    description: 'How to run Vouch reliably at scale: the sidecar, your KMS, revocation registries, metrics, rate limits.',
    articles: [
      {
        id: 'sidecar-deployment',
        title: 'Deploying the Vouch Sidecar',
        summary: 'Run the Vouch signing daemon in production: container, key provisioning, health checks, scaling.',
        body: `
## Build container

The Go binary is statically linked; you can put it in a scratch image.

\`\`\`dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /vouch-sidecar ./go-sidecar/cmd/vouch-sidecar

FROM scratch
COPY --from=build /vouch-sidecar /vouch-sidecar
ENTRYPOINT ["/vouch-sidecar"]
\`\`\`

## Key provisioning

Three options in order of recommendation:

1. **Cloud KMS** - mount KMS credentials, configure the sidecar with the key alias
2. **Init container** - provision keys via Vault or AWS Secrets Manager, write to a tmpfs volume
3. **Direct env var** - acceptable for development only

## Health check

\`GET /health\` returns 200 OK with a JSON body indicating ready state and last successful signature.

## Observability

The sidecar emits structured JSON logs on stdout. For metrics, run it alongside the Python verifier's Prometheus exporter, or use the OpenTelemetry exporter (\`--otel-endpoint\`) for distributed tracing.

## Scaling

The sidecar is stateless. Horizontally scale by running multiple instances behind a load balancer. Each instance needs access to the same KMS key (or its own replica of the agent's key for hot-standby).
`,
      },
      {
        id: 'kms-integration',
        title: 'Connecting Your KMS',
        summary: 'How to keep production signing keys in AWS, GCP, Azure, or an encrypted local file.',
        body: `
## AWS KMS

\`\`\`python
from vouch.kms import RotatingKeyProvider

provider = RotatingKeyProvider(
  backend="aws-kms",
  key_id="alias/vouch-agent-prod",
  region="us-east-1",
)
\`\`\`

Requires \`boto3\` and IAM permissions \`kms:Sign\` and \`kms:GetPublicKey\` on the key.

## GCP KMS

\`\`\`python
provider = RotatingKeyProvider(
  backend="gcp-kms",
  key_id="projects/my-proj/locations/global/keyRings/vouch/cryptoKeys/agent",
)
\`\`\`

Requires \`google-cloud-kms\` and the \`roles/cloudkms.signer\` IAM role.

## Azure Key Vault

\`\`\`python
provider = RotatingKeyProvider(
  backend="azure-kv",
  key_id="https://vouch-kv.vault.azure.net/keys/agent/abc123",
)
\`\`\`

Requires \`azure-keyvault-keys\` and the Key Vault Crypto Officer role.

## Local file (development only)

\`\`\`python
provider = RotatingKeyProvider(
  backend="local-file",
  key_id="/etc/vouch/agent.jwk",
  passphrase=os.environ["VOUCH_KEY_PASSPHRASE"],
)
\`\`\`
`,
      },
      {
        id: 'reputation',
        title: 'Tracking Agent Reputation',
        summary: 'How to score, decay, and slash reputations across a fleet of agents using Memory, Redis, or Kafka.',
        body: `
## What the engine does

\`vouch/reputation.py\` (711 lines) tracks an integer reputation score per DID. The score is shaped by:

- Action deltas: success \`+1\`, failure \`-2\`, slash and boost configurable
- Exponential decay toward baseline (default \`base=50\`, rate \`0.1/day\`, kicks in after 7 days of inactivity)
- Tier classification:
  - \`exceptional\` for score ≥ 90
  - \`trusted\` for ≥ 75
  - \`neutral\` for ≥ 50
  - \`cautionary\` for ≥ 25
  - \`untrusted\` otherwise

## Memory backend (dev)

\`\`\`python
from vouch.reputation import ReputationEngine, MemoryReputationStore

engine = ReputationEngine(store=MemoryReputationStore())
\`\`\`

## Redis backend (single-region production)

\`\`\`python
from vouch.reputation import RedisReputationStore
engine = ReputationEngine(store=RedisReputationStore(url="redis://prod:6379/0"))
\`\`\`

## Kafka backend (event-sourced)

\`\`\`python
from vouch.reputation import KafkaReputationStore
engine = ReputationEngine(store=KafkaReputationStore(
  bootstrap_servers="kafka:9092",
  topic="vouch-reputation-events",
))
\`\`\`

Reputation events are appended to the topic. Downstream services can replay the topic to reconstruct state, derive analytics, or feed into a downstream auditor.

## HTTP backend (cross-org)

\`\`\`python
from vouch.reputation import HTTPReputationStore
engine = ReputationEngine(store=HTTPReputationStore(
  base_url="https://reputation.consortium.example/v1",
  api_key=os.environ["REPUTATION_API_KEY"],
))
\`\`\`

For consortium deployments where reputation is shared across organizations.

## Scope note

The Specification says specific reputation scoring **algorithms** are non-normative; the shipped engine is a reference implementation. Implementers MAY swap in their own algorithm by implementing the \`ReputationStoreInterface\`.
`,
      },
      {
        id: 'outcome-evidence',
        title: 'Proving an Agent Track Record',
        summary: 'Commit a verdict before its outcome, settle it later, and get a record that cannot be backdated or cherry-picked.',
        body: `
## What it is

Identity proves who acted. Outcome evidence proves that an agent's verdict, prediction, or recommendation was fixed before its result was known, so a track record cannot be backdated or cherry-picked. It ships as \`vouch.accountability\`.

Two credential types:

- \`OutcomeCommitmentCredential\`: the call, committed and signed before the outcome. It carries a salted SHA-256 digest of the claim, so the call can stay private until settlement yet is provably fixed.
- \`OutcomeAttestationCredential\`: the settlement, signed by whoever observed the result, which can be a neutral third party. It reveals the call and binds the real outcome back to the commitment.

## Commit the verdict before the outcome

\`\`\`python
from vouch import Signer, generate_identity
from vouch.accountability import commit_outcome, verify_commitment

keys = generate_identity("agent.example.com")
agent = Signer(private_key=keys.private_key_jwk, did=keys.did)

commitment, secret = commit_outcome(
    agent,
    claim={"asset": "XYZ", "direction": "up", "horizon": "2026-07-01"},
    settlement={
        "method": "market-settlement",
        "locator": "https://example.com/markets/42",
        "resolutionCriteria": "settled price at expiry versus strike",
    },
    private=True,  # publish only the digest; keep secret to settle later
)
\`\`\`

Keep \`secret\` (the call and its salt). You need it to settle a private commitment.

## Settle it once the result is known

\`\`\`python
from vouch.accountability import attest_outcome, verify_attestation

attestation = attest_outcome(
    settler,  # a Signer; can be a neutral third party
    commitment=commitment,
    outcome={"result": "up", "evidence": "https://example.com/markets/42/settle"},
    secret=secret,
    matches=True,
)

ok, subject = verify_attestation(
    attestation,
    settler_keys.public_key_jwk,
    commitment=commitment,
    committer_public_key=agent_keys.public_key_jwk,
)
\`\`\`

Verification recomputes the fingerprint from the revealed call, confirms it matches the commitment, and rejects any settlement timestamped before the commitment. A winning call cannot be minted with hindsight, and a losing one is a visible gap rather than a silent absence.

## Where it sits

This is the per-verdict evidence layer underneath reputation. Vouch reputation aggregates settled attestations and other signed receipts into a score anyone can recompute, covered in Evidence-Backed Reputation below. Full demo: \`python examples/accountability_demo.py\`. Defensive disclosure: PAD-071.
`,
      },
      {
        id: 'reputation-evidence',
        title: 'Evidence-Backed Reputation',
        summary: 'Compute an agent reputation from signed receipts with a public function, so anyone can recompute it instead of trusting a server.',
        body: `
## What it is

Reputation is a verifiable aggregate of signed, interaction-bound receipts, keyed to the agent DID and computed by a public deterministic function. A consumer trusts the signatures and the math, not a server's stored number.

## The signals (objective first)

The relying party the agent acted on signs the result of an action (a StateReceipt), a settled prediction signs whether it came true (an OutcomeAttestationCredential), and an authority signs a violation (a PenaltyReceipt). A human ReviewCredential counts only when bound to proof the rater used the agent, and carries low weight.

## How it works

A ReputationLedger verifies each receipt before admitting it and keeps them in a Merkle log, so a consumer can recompute the score from the receipts and inclusion proofs rather than trust the registry signed snapshot. evaluate_reputation gates a decision against a policy of minimum composite, per-dimension minimums, and freshness. build_reputation_proof proves the agent clears a threshold without revealing its score, and apply_resolution drops a receipt an arbiter has ruled invalid.

## Demo

Run python examples/reputation_demo.py for the full path: receipts to ledger to signed snapshot to policy gate to threshold proof to dispute. The formats and the aggregation function are open; a hosted registry is a separate commercial layer.
`,
      },
      {
        id: 'revocation',
        title: 'Revoking an Entire Agent',
        summary: 'When a key is compromised or an agent is decommissioned: invalidate every credential it ever signed in one operation.',
        body: `
## When to use DID-level revocation

DID-level revocation invalidates **all** credentials ever issued under a given DID. Use it when:

- A signing key is suspected compromised
- An agent is being decommissioned
- An organizational principal needs to break the entire chain of credentials it ever authorized

For revoking individual credentials without affecting the rest of an agent's history, use BitstringStatusList instead (see [Credential Status](#credential-status)). The two mechanisms compose: many production deployments run both.

## Backends

Memory and Redis ship today. The \`RevocationStoreInterface\` is abstract so custom backends (HTTP remote registries, distributed key-value stores) are straightforward.

\`\`\`python
from vouch.revocation import RevocationRegistry, RedisRevocationStore

registry = RevocationRegistry(store=RedisRevocationStore(url="redis://prod:6379/1"))

# Revoke a DID
await registry.revoke(
  did="did:web:compromised-agent.example.com",
  reason="key_compromise",
  revoked_by="did:web:security-team.example.com",
)

# Check status
is_revoked = await registry.is_revoked("did:web:compromised-agent.example.com")
\`\`\`

## How the verifier uses it

The verifier consults the revocation registry on every verification. If the issuing DID is revoked, the credential fails with reason \`issuer_revoked\`. Cache TTL is configurable (default 60 seconds) to balance freshness with verifier throughput.
`,
      },
      {
        id: 'credential-status',
        title: 'Revoking Individual Credentials',
        summary: 'How to revoke or suspend a single credential without invalidating everything else the agent ever signed.',
        body: `
## What this gives you

BitstringStatusList (\`vc-bitstring-status-list\`) lets an issuer revoke or suspend an **individual** credential without invalidating other credentials issued by the same DID. It's the right tool when one specific action needs to be retracted but the rest of the agent's history should remain valid.

Vouch ships a cross-language reference implementation:

- Python: \`vouch.status_list\` and \`vouch.status_list_fetcher\`
- TypeScript: \`@vouch-protocol-official/sdk\` exports \`StatusList\`, \`buildStatusListCredential\`, \`buildStatusListEntry\`, \`verifyStatus\`
- Go: \`go-sidecar/signer\` exports \`StatusList\`, \`BuildStatusListCredential\`, \`BuildStatusListEntry\`, \`VerifyStatus\`

All three share a single canonical encoding (gzip + base64url multibase, 131,072-bit minimum bitstring) and a cross-language test vector at \`test-vectors/bitstring-status-list/\`.

## Issuer flow

The issuer maintains one or more \`StatusList\` instances (one per status purpose; typically one for revocation and optionally one for suspension). Each new credential is assigned the next available bit index in the list. To revoke a credential, the issuer flips its bit, re-signs the \`BitstringStatusListCredential\`, and republishes it at its stable URL.

\`\`\`python
from vouch import (
  Signer, StatusList, FilesystemStatusListStore,
  build_status_list_credential, build_status_list_entry,
  generate_identity,
)

# Load or create the status list. Persisted state survives restarts.
store = FilesystemStatusListStore("/var/lib/vouch/status-1.json")
try:
  status_list = store.load()
except FileNotFoundError:
  status_list = StatusList(status_list_id="https://issuer.example/status/1")

keys = generate_identity("issuer.example")
signer = Signer(private_key=keys.private_key_jwk, did=keys.did)

# ---- Issue a credential with a credentialStatus entry ----
index = status_list.allocate_index()
store.save(status_list) # persist the new cursor

# Pass the status entry to sign so the proof covers it.
signed_credential = signer.sign(
  intent={"action": "submit_claim", "target": "claim:HC-001",
      "resource": "https://insurance.example/claims/HC-001"},
  credential_status=build_status_list_entry(
    status_list_credential="https://issuer.example/status/1",
    status_list_index=index,
  ),
)

# ---- Later, revoke that credential ----
status_list.revoke(index)
store.save(status_list)

# Re-sign and republish the status list credential at its stable URL.
status_credential = build_status_list_credential(
  issuer_did="did:web:issuer.example",
  status_list=status_list,
)
signed_status_credential = signer.sign(status_credential)
\`\`\`

## Verifier flow

Verifiers fetch the published status list credential and look up the credential's bit. The \`StatusListFetcher\` provides an in-memory TTL cache, conditional GETs, and HTTPS enforcement.

\`\`\`python
from vouch import StatusListFetcher, verify_status

fetcher = StatusListFetcher(cache_ttl_seconds=300)

status_credential = fetcher.get(
  signed_credential["credentialStatus"]["statusListCredential"]
)

is_revoked = verify_status(
  credential_status=signed_credential["credentialStatus"],
  status_list_credential=status_credential,
)
\`\`\`

On verification failure, set \`force_refresh=True\` so the verifier bypasses cached state and picks up the latest list. This is the recommended way to handle stale caches.

## Why persistence matters

\`StatusList\` keeps two pieces of state: the bitstring (which bits are set) and the allocation cursor (\`next_index\`, the next unused index). The bitstring is recoverable from the published \`encodedList\`, but the cursor is NOT. Without persisting the cursor, an issuer restart would re-allocate already-used indices and silently overwrite prior revocations.

\`to_state_dict()\` returns a JSON-serializable dict carrying both:

\`\`\`json
{
 "version": 1,
 "status_list_id": "https://issuer.example/status/1",
 "status_purpose": "revocation",
 "length": 131072,
 "next_index": 1024,
 "encoded_list": "uH4sIAAAAAAAC_-3Z..."
}
\`\`\`

\`FilesystemStatusListStore\` is a reference store with atomic writes (temp file + rename). For production, swap in Redis (\`SET status:1 <state-json>\`), Postgres (one row, \`UPDATE\` under \`SELECT FOR UPDATE\`), or S3 (with ETag-based optimistic concurrency). The state-dict API is backend-agnostic.

## TypeScript and Go

The TypeScript and Go APIs mirror Python. Examples:

\`\`\`typescript
import {
  StatusList, buildStatusListCredential, buildStatusListEntry,
  verifyStatus, buildVouchCredential,
} from '@vouch-protocol-official/sdk';

const statusList = new StatusList({ statusListId: 'https://issuer.example/status/1' });
const index = statusList.allocateIndex();

const credential = buildVouchCredential({
  issuerDid: 'did:web:issuer.example',
  intent: { action: 'submit_claim', target: 'claim:HC-001',
       resource: 'https://insurance.example/claims/HC-001' },
  credentialStatus: buildStatusListEntry({
    statusListCredential: 'https://issuer.example/status/1',
    statusListIndex: index,
  }),
});
\`\`\`

\`\`\`go
import "github.com/vouch-protocol/vouch/go-sidecar/signer"

sl, _ := signer.NewStatusList("https://issuer.example/status/1", "", 0)
idx, _ := sl.AllocateIndex()

entry, _ := signer.BuildStatusListEntry(signer.BuildStatusListEntryOptions{
  StatusListCredential: "https://issuer.example/status/1",
  StatusListIndex:   idx,
})

// Pass via SignOptions.CredentialStatus to Signer.Sign.
\`\`\`

TypeScript and Go callers fetch the published status credential using their platform's HTTP client (\`fetch()\` / \`net/http.Get()\`) and call \`verifyStatus\` / \`VerifyStatus\` with the result.

## Cross-language interop

Python and TypeScript produce byte-identical encoded output (both use zlib's DEFLATE encoder). Go's \`compress/flate\` produces a valid DEFLATE stream that decodes to the same bitstring; BitstringStatusList §4.2 requires equivalence of the **decompressed** bitstring, not the gzip envelope, so all three implementations interop cleanly. The canonical test vector at \`test-vectors/bitstring-status-list/vector.json\` is exercised by all three test suites.

## Sizing

The protocol minimum bitstring length is 131,072 bits (16 KiB uncompressed; ~50 bytes compressed when empty). That holds 131,072 credentials per status list. For larger issuers, allocate a new status list as you approach exhaustion; the \`credentialStatus.statusListCredential\` URL on each credential identifies which list it belongs to.

## Composition with DID-level revocation

BitstringStatusList and the DID-level revocation registry (\`vouch.revocation\`) compose cleanly:

- **DID-level**: "this entire identity is compromised, kill everything." One operation, instant blanket effect.
- **Credential-level (BitstringStatusList)**: "this specific action was retracted, but the rest of this identity's history remains valid." Surgical.

A verifier that runs both consults the DID registry first (cheap), then the status list (HTTP fetch, cached). If either returns "revoked," the credential is rejected with a specific reason code.
`,
      },
      {
        id: 'metrics-and-observability',
        title: 'Metrics & Observability',
        summary: 'What Vouch emits to Prometheus and OpenTelemetry, plus what is worth alerting on.',
        body: `
## Prometheus metrics

\`vouch/metrics.py\` exposes:

\`\`\`
vouch_signatures_total      counter
vouch_verifications_total     counter
vouch_verification_success_rate  gauge
vouch_verification_latency_seconds histogram
vouch_cache_hits         counter
vouch_cache_misses        counter
vouch_credential_issuances    counter
vouch_reputation_lookups     counter
vouch_revocation_checks      counter
\`\`\`

Mount the exporter on \`/metrics\` of your verifier service.

## OpenTelemetry

Install the OTel extra:

\`\`\`bash
pip install 'vouch-protocol[otel]'
\`\`\`

Then point at your collector via \`OTEL_EXPORTER_OTLP_ENDPOINT\`. Verifier spans include credential ID, DID, and outcome.

## What to alert on

- \`vouch_verification_success_rate\` dropping below 0.99 over a 5-minute window
- \`vouch_verification_latency_seconds\` p99 exceeding your SLO (typical: 50ms with caching)
- \`vouch_revocation_checks\` increasing without a corresponding rise in \`vouch_verifications_total\` (suggests a verifier loop is consulting the registry inefficiently)
`,
      },
    ],
  },

  {
    id: 'integrations',
    title: 'Framework Integrations',
    description: 'Wire Vouch into the framework you already use, or into your GitHub workflow.',
    articles: [
      {
        id: 'integrations',
        title: 'Which AI Frameworks Vouch Plugs Into',
        summary: 'Ready-made integrations for LangChain, LangGraph, CrewAI, Goose, AutoGPT, AutoGen, MCP, Vertex AI, and more.',
        body: `
## Python integrations

All under \`vouch/integrations/\`:

| Framework | File | What it does |
|---|---|---|
| LangChain | \`langchain/tool.py\` | Wraps a LangChain Tool so its inputs are signed before execution |
| LangGraph | \`langgraph.py\` | Signs LangGraph tool calls and graph nodes across a graph |
| CrewAI | \`crewai/tool.py\` | Same pattern for crew-style multi-agent flows |
| AutoGPT | \`autogpt/commands.py\` | Command integration for AutoGPT plugins |
| AutoGen | \`autogen/tool.py\` | Tool wrapper for AutoGen conversational agents |
| Streamlit | \`streamlit/seal.py\` | Media-sealing UI helper for Streamlit apps |
| Vertex AI | \`vertex_ai/tool.py\` | Google Vertex AI tool integration |
| Google ADK | \`adk.py\` | Agent Development Kit integration |
| Google APIs | \`google.py\` | Generic Sheets/Docs/Drive integration |
| n8n | \`n8n.py\` | n8n workflow automation node |
| Hasura | \`hasura/webhook.py\` | GraphQL webhook handler |
| MCP | \`mcp/server.py\` | Reference Model Context Protocol server |
| Goose | \`goose.py\` | Registers the Vouch MCP server as an extension for Block's Goose agent |
| Amnesia | \`amnesia.py\` | Wraps an Amnesia egress decision in a Verifiable Credential for a replayable audit trail |

End-to-end examples are at [examples/05_integrations/](https://github.com/vouch-protocol/vouch/tree/main/examples/05_integrations).

## Standalone framework packages (new in v1.6.2)

Installable on their own, so the framework adapters no longer need the full SDK import path:

| Package | Install | What it does |
|---|---|---|
| \`vouch-langchain\` | \`pip install vouch-langchain\` | A LangChain tool that signs each tool call before it leaves the agent |
| \`vouch-crewai\` | \`pip install vouch-crewai\` | A CrewAI tool with supervisor-to-worker delegation that can only narrow authority |
| \`vouch-a2a\` | \`pip install vouch-a2a\` | Binds an A2A (Agent2Agent) Agent Card to a Vouch identity so two agents can verify each other |
| \`vouch-mlflow\` | \`pip install vouch-mlflow\` | Signs an MLflow model artifact at registration time, bound to its content digest |
| \`vouch-safetensors\` | \`pip install vouch-safetensors\` | Embeds a credential in a .safetensors header, complementary to OpenSSF Model Signing |

Each issues a verifiable credential per call, with optional delegation back to a human principal. The \`vouch-mcp\` server ships alongside them (see below).

## TypeScript integrations

Currently one: \`packages/sdk-ts/src/integrations/amnesia.ts\` for the Amnesia egress-decision bridge.

## Vouch Shield (sibling repo)

[vouch-protocol/vouch-shield](https://github.com/vouch-protocol/vouch-shield) is a TypeScript runtime middleware that intercepts tool calls and enforces signature verification, allowlist, capability permissions, and audit logging. Treat it as the enforcement layer that consumes Vouch credentials at execution time.

## No framework? Use the standalone packages

The framework adapters above are conveniences, not requirements. If you are not on one of these frameworks, integrate Vouch directly.

The signing and verification core ships as an installable package in every major language: \`pip install vouch-protocol\`, \`npm i @vouch-protocol-official/sdk\`, plus Rust (\`vouch-core\`), JVM (\`com.vouchprotocol:vouch-core\`), .NET (\`VouchProtocol.Core\`), Swift (\`VouchCore\`), C, and WebAssembly. See the [Tools page](/tools/) for the full list and install commands.

For a language-agnostic drop-in, three standalone services need no framework and no SDK:

- **\`vouch-mcp\`** a Model Context Protocol server any MCP client (Claude Desktop, Cursor, any agent) can call to create identities, sign, verify, and scan.
- **\`vouch-bridge\`** an HTTP server for media provenance: C2PA image signing, QR badge overlay, and audio watermarking.
- **\`vouch-sidecar\`** the Go signing daemon that mints credentials over localhost for any language, keeping the key out of the model's process.
`,
      },
      {
        id: 'github-app',
        title: 'The Vouch Gatekeeper GitHub App',
        summary: 'Block unsigned commits and enforce your team policy on every pull request, with one click to install.',
        body: `
## What it does

Vouch Gatekeeper listens for \`pull_request.opened\` and \`pull_request.synchronize\` events. For each PR, it verifies commit signatures with GitHub's SSH/GPG infrastructure first, and falls back to the Vouch Registry if a commit is not signed via those mechanisms.

## Zero-config policy

Org member with a signed commit = allow. That is the default; no configuration needed.

## Custom policy

Add \`.github/vouch-policy.yml\` to your repo:

\`\`\`yaml
allowlist:
  - did:web:alice.example.com
  - did:key:z6Mk...
blocklist: []
require_signed_commits: true
require_co_authored_with_did: false
\`\`\`

## Install

GitHub App URL: [github.com/apps/vouch-gatekeeper](https://github.com/apps/vouch-gatekeeper) (see the live install in the repo's \`github-app/app-manifest.json\`).

The app auto-opens a PR on installation to add the protection badge to your README:

\`\`\`md
![Vouch Protected](https://api.vouch-protocol.com/api/badge/{owner}/{repo})
\`\`\`

## Architecture

FastAPI service (\`github-app/main.py\`, ~1000 lines). Webhook endpoint at \`/webhook\`, badge endpoint at \`/api/badge/{owner}/{repo}\`. Setup flow at \`/setup\` redirects through GitHub OAuth and back to \`/setup/callback\`.
`,
      },
      {
        id: 'vouch-shield',
        title: 'Adding Vouch Shield to Your Agent',
        summary: 'Drop a small middleware in front of your agent so every tool call gets checked before it runs.',
        body: `
## Install

\`\`\`bash
npm install @vouch-protocol/shield
\`\`\`

## Basic usage

\`\`\`ts
import { VouchShield, generateKeypair, signPayload } from '@vouch-protocol/shield';

const shield = new VouchShield({ strictMode: true });

// Trust a specific identity
const identity = generateKeypair();
shield.registerPublicKey(identity.did, identity.publicKey);
shield.trustDid(identity.did);
shield.setCapabilities(identity.did, {
  filesystem: 'read',
  network: 'outbound',
  shell: 'none',
});

// Before executing a tool call, intercept
const signedRequest = signPayload(
  { file: '/data/input.txt' },
  identity.secretKey,
  identity.did,
);

const result = shield.interceptToolCall({
  tool: 'read_file',
  args: { file: '/data/input.txt' },
  signedPayload: signedRequest,
});

if (result.allowed) {
  // Execute the tool
} else {
  console.error('Blocked:', result.reason);
}
\`\`\`

## Where Shield sits

Between your framework's tool-call event and the actual tool function. If you use LangChain in TypeScript, intercept in the \`AgentExecutor\` callback. If you use a custom orchestrator, intercept in your tool-dispatch loop.

## Audit trail

The \`FlightRecorder\` logs every allowed and blocked call. Pipe it to your SIEM or store it locally for after-the-fact audit.
`,
      },
    ],
  },

  {
    id: 'cli',
    title: 'CLI Reference',
    description: 'Every command, every flag, with copy-pasteable examples.',
    articles: [
      {
        id: 'cli-reference',
        title: 'The vouch Command Reference',
        summary: 'Every subcommand of the vouch CLI, what it does, and a copy-pasteable example.',
        body: `
The \`vouch\` command ships with the \`vouch-protocol\` Python package. It groups into five areas: identity, git, media, scan, and attribution. A global \`-v\` / \`--verbose\` flag works on any command.

## Identity and tokens

### vouch init

Generate a new agent identity (a did:vouch DID plus an Ed25519 keypair). By default it prompts for a passphrase, saves the encrypted identity to your local keystore, and prints the public key to put in your vouch.json.

- \`--domain <D>\` domain to base the DID on (defaults to example.com)
- \`--env\` print the identity as export VOUCH_DID / VOUCH_PRIVATE_KEY instead of saving to the keystore

### vouch sign "<message>"

Sign a message and print a Vouch-Token. With no key flags it loads your stored identity (prompting for the passphrase if encrypted); otherwise it reads VOUCH_PRIVATE_KEY / VOUCH_DID from the environment.

- \`<message>\` the message to sign (positional)
- \`--json\` parse the message as a JSON payload instead of wrapping it as a string
- \`--key <JWK>\` private key as JWK JSON
- \`--did <DID>\` agent DID
- \`--header\` prefix the output with \`Vouch-Token: \`

### vouch verify <token>

Verify a Vouch-Token. With a public key it checks the signature; without one it validates structure only and warns the signature was not verified.

- \`<token>\` the token to verify (positional)
- \`--key <JWK>\` public key as JWK JSON
- \`--json\` output as JSON

## Git

### vouch git init

Export your Vouch identity to an SSH signing key, configure git to sign commits (commit.gpgsign=true, gpg.format=ssh), upload the key to GitHub, and optionally install a commit-trailer hook and README badge.

- \`--no-trailer\` skip the prepare-commit-msg trailer hook
- \`--no-badge\` skip the README badge prompt

### vouch git status

Show the current Vouch git signing setup: SSH key and fingerprint, the relevant git config, and whether the commit hook is installed.

### vouch git verify [commit]

Verify commit signatures match their Vouch-DID trailers. With no argument it checks recent commits; commits without a trailer are skipped.

- \`[commit]\` a specific commit hash (optional positional)
- \`-n\`, \`--count <N>\` number of recent commits to verify (default: 10)
- \`--strict\` exit non-zero if any commit fails

## Media

### vouch media sign <image>

Sign an image. Native Vouch signing by default (no certificates), writing a _signed copy plus a sidecar.

- \`<image>\` path to the image (positional)
- \`-o, --output <path>\`, \`-n, --name <name>\`, \`-e, --email <email>\`, \`--did <DID>\`, \`--key <JWK>\`, \`--title <title>\`
- \`--pro\` mark the credential PRO (otherwise FREE)
- \`--c2pa\` use the C2PA industry standard instead of native signing

### vouch media verify <image>

Verify an image's signature. \`--json\` for JSON, \`--c2pa\` to verify a C2PA manifest instead.

## Scan

### vouch scan [path]

Scan a file or directory for Vouch-shaped private key material (the OSS detection stage of PAD-058). A missing path exits with status 2.

- \`[path]\` file or directory (default: current directory)
- \`--json\` findings as JSON
- \`--exit-nonzero-on <critical|high|medium|low>\` exit non-zero at or above this severity (default: critical)

## Attribution

\`vouch attribute\` records per-region human/AI code authorship and produces a signed manifest (PAD-061). Subcommands: \`record\`, \`hook\`, \`finalize\`, \`blame\`, \`verify\`; most accept \`--session <id>\`.

- \`vouch attribute record <path>\` record a single AI edit
- \`vouch attribute hook\` read a Claude Code PostToolUse event from stdin and record the edit
- \`vouch attribute finalize\` sign the manifest for the session
- \`vouch attribute blame <path>\` show per-line authorship (AI / human / prior)
- \`vouch attribute verify\` verify a manifest's signatures and region completeness

## Helper binaries

Separate executables, run directly (not as vouch subcommands):

- \`vouch-mcp\` Model Context Protocol server, exposes Vouch signing and verification to MCP-aware agents
- \`vouch-bridge\` local media HTTP server for the media flow
- \`vouch-sidecar\` Go Identity Sidecar. Install with \`go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest\`
`,
      },
    ],
  },

  // =====================================================================
  // STATE VERIFIABILITY RUNTIME (concrete, runnable quickstart)
  // =====================================================================
  {
    id: 'state-verifiability',
    title: 'State Verifiability Runtime',
    description: 'Hands-on quickstart for the Heartbeat Protocol, trust entropy decay, behavioral attestation, canary commitments, and validator quorum.',
    articles: [
      {
        id: 'state-verifiability-quickstart',
        title: 'Heartbeat Quickstart',
        summary: 'Stand up a heartbeat-renewing agent against a validator in under ten minutes.',
        body: `
The State Verifiability runtime ships in the Python SDK today. This quickstart wires the four primitives together: trust entropy, behavioral attestation, canary commitments, and validator quorum.

## Install

\`\`\`bash
pip install vouch-protocol
\`\`\`

## Agent side: build a heartbeat session

\`\`\`python
from vouch import HeartbeatSession, HeartbeatScheduler, BehavioralCollector
from vouch.behavioral_attestation import ewma_drift_scorer
import asyncio
import httpx

session = HeartbeatSession(subject_did="did:web:agent.example.com")
session.collector = BehavioralCollector(intent_drift_scorer=ewma_drift_scorer(alpha=0.3))

# As the agent runs, record its activity
session.record_action(b"submit_claim:HC-001")
session.collector.record_api_call("https://api.example.com/orders", tokens=120)
session.collector.record_resource_access("order:42")
\`\`\`

## Submit each heartbeat to the validator

\`\`\`python
VALIDATOR_URL = "https://validator.example.com/heartbeat"

async def submit(request):
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(VALIDATOR_URL, json=request.to_dict())
        resp.raise_for_status()
        return resp.json()  # the new SessionVoucher

scheduler = HeartbeatScheduler(
    session=session,
    interval_seconds=60,
    submit_callback=submit,
)
scheduler.start()

# ... agent runs as normal ...

await scheduler.stop()
\`\`\`

The scheduler pulls the current behavioral digest from the collector, advances the canary commit/reveal chain, and includes the running Merkle root of actions performed since the last heartbeat. The validator's response is a fresh SessionVoucher with decayed-but-renewed trust.

## Validator side: accept and renew

\`\`\`python
from vouch import HeartbeatValidator, MemoryHeartbeatStore

validator = HeartbeatValidator(
    validator_did="did:web:validator.example.com",
    initial_trust=1.0,
    decay_lambda=0.01,
    voucher_valid_seconds=120,
    scope=["agent_actions"],
    store=MemoryHeartbeatStore(),  # swap for RedisHeartbeatStore in production
)

def handle_heartbeat(request_dict):
    result = validator.validate(request_dict)
    if result.ok:
        return result.session_voucher
    return {"error": "rejected", "reasons": result.reasons}
\`\`\`

The validator checks schema, behavioral digest structure, canary chain integrity, and interval-index monotonicity. A broken canary chain or stale interval index returns a structured rejection, so the agent does not get a new voucher and its existing one expires.

## Trust entropy: gate actions by current trust

Each SessionVoucher carries \`initialTrust\` and \`decayLambda\`. The effective trust at time \`t\` is:

\`\`\`
trust(t) = initialTrust * exp(-decayLambda * (now - issuedAt_seconds))
\`\`\`

Gate sensitive actions by checking the current trust:

\`\`\`python
from vouch import compute_trust_at, check_trust_threshold
from vouch.trust_entropy import (
    TRUST_THRESHOLD_HIGH_STAKES,    # 0.9
    TRUST_THRESHOLD_MEDIUM_STAKES,  # 0.75
    TRUST_THRESHOLD_LOW_STAKES,     # 0.5
)
from datetime import datetime, timezone

now = datetime.now(timezone.utc)

if check_trust_threshold(session_voucher, TRUST_THRESHOLD_HIGH_STAKES, at_time=now):
    allow_financial_transfer()
elif check_trust_threshold(session_voucher, TRUST_THRESHOLD_MEDIUM_STAKES, at_time=now):
    allow_phi_read()
elif check_trust_threshold(session_voucher, TRUST_THRESHOLD_LOW_STAKES, at_time=now):
    allow_status_query()
else:
    reject_action()
\`\`\`

Set your heartbeat interval to less than half the trust half-life so renewal stays ahead of decay. Half-life is \`ln(2) / decay_lambda\`.

## Validator quorum: M-of-N approval

A single validator is a single point of failure. For regulated deployments, require multiple validators with different responsibilities to approve each heartbeat:

\`\`\`python
from vouch import HeartbeatQuorum, QuorumValidator, ROLE_POLICY, ROLE_BEHAVIORAL, ROLE_BUDGET

quorum = HeartbeatQuorum(
    validators=[
        QuorumValidator(validator=policy_validator,     role=ROLE_POLICY),
        QuorumValidator(validator=behavioral_validator, role=ROLE_BEHAVIORAL),
        QuorumValidator(validator=budget_validator,     role=ROLE_BUDGET),
    ],
    threshold=2,
)

result = quorum.validate(heartbeat_request_dict)
if result.ok:
    voucher = result.session_voucher
    # voucher.issuer lists all approving validator DIDs
\`\`\`

Trust parameter aggregation is configurable. Defaults: \`initial_trust\` takes the minimum, \`decay_lambda\` takes the maximum, \`scope\` is the intersection of all approving validators' scopes.

## Canary commitments: detect a silent failure

The heartbeat carries a fresh canary commitment plus the prior commitment's reveal. If the agent skips a beat or sends a wrong reveal, the chain breaks and no subsequent heartbeat can resume it. Silent failure becomes loud.

The \`HeartbeatSession\` and \`HeartbeatValidator\` manage this automatically. To use the primitive directly:

\`\`\`python
from vouch import CanaryChain, CanaryVerifier

chain = CanaryChain()
msg = chain.next_heartbeat()
# msg.commitment is what to send this interval
# msg.reveal is the previous secret (None on first interval)

verifier = CanaryVerifier()
ok = verifier.observe(msg.commitment, msg.reveal)
if not ok:
    revoke_session_voucher()
\`\`\`

Validator state is small (one string per agent), so it survives restarts via \`last_commitment\` persistence in your chosen \`HeartbeatStoreInterface\` backend.

## What's not in this quickstart

- TypeScript and Go ports of the runtime modules: data formats are cross-language; the orchestration is Python-only today.
- Concrete persistence backends beyond \`MemoryHeartbeatStore\` (Redis, Postgres, S3): ship in the commercial Pro tier.
- Custom drift scorers beyond \`mean_drift_scorer\`, \`max_drift_scorer\`, \`ewma_drift_scorer\`: subclass \`BehavioralCollector\` to add your own.

See [PAD-016](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-016-dynamic-credential-renewal.md) for the full Heartbeat Protocol disclosure and [PAD-022](https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/PAD-022-swarm-limits-protocol.md) for the rate-limiting companion.
`,
      },
    ],
  },

  // =====================================================================
  // ACCOUNTABLE AUTONOMY: bound and record what an authorized agent does
  // =====================================================================
  {
    id: 'accountable-autonomy',
    title: 'Accountable Autonomy',
    description:
      'Five modules that bound and record what an already-authorized agent does: reasoned actions, deliberation windows, executable caveats, inference provenance, and an append-only transparency log.',
    articles: [
      {
        id: 'accountable-autonomy-overview',
        title: 'The Accountable-Autonomy Runtime',
        summary:
          'Make an authorized agent state its reason, wait out a veto, stay inside its envelope, prove its output, and land in a public log.',
        body: `
Identity and delegation prove who acted and under what authority. They do not, on their own, bound what an already-authorized agent may do, slow down an irreversible action, prove why the agent acted, or make the record public. Five Python SDK modules add exactly that. Each is an ordinary \`eddsa-jcs-2022\` Verifiable Credential, so it verifies across the language SDKs, and each has a runnable example in the repo and a live section on the [interactive demos](/demos/).

## Reasoned Action Proofs

\`vouch.reasoning\` has the agent state its justification before acting, tie each reason to a real artifact by that artifact's hash, and escrow the justification before execution. An auditor proves the reasoning was not fabricated (\`evidence_unresolved\`, \`evidence_hash_mismatch\`), not rewritten (\`justification_digest_mismatch\`), and committed before the action (\`escrow_after_execution\`).

\`\`\`python
from vouch.reasoning import build_justification, evidence_anchor, sign_reasoned_action, verify_justification

just = build_justification(intent, [evidence_anchor("user asked", ref="msg:1", evidence=user_message)])
cred = sign_reasoned_action(agent, intent=intent, justification=just)
ok, subject = verify_reasoned_action(cred, agent_pub)
good, reason = verify_justification(just, subject, resolver=lookup)
\`\`\`

See \`examples/reasoned_action_demo.py\` and the [reasoned-action demo](/demos/#reasoned-action).

## Proof of Deliberation

\`vouch.deliberation\` gates irreversible actions. The agent commits and broadcasts a signed intent with a challenge window and named objectors, waits out the window, and survives any veto before a verifier accepts the execute credential. The agent cannot shorten the window (\`challenge_window_not_elapsed\`) or clear its own veto (\`vetoed\`). Reversible actions run with no delay. See \`examples/deliberation_demo.py\` and the [deliberation demo](/demos/#deliberation).

## Executable Caveats

\`vouch.caveats\` attaches live conditions to a delegation link ("only for shipped orders", "under the lifetime spend", "business hours"). Caveats accumulate down the chain and cannot be dropped by a descendant (the verifier requires the chain to root at the grantor, else \`unrooted_capability\`), and every verifier must evaluate every accumulated caveat. A standard caveat library evaluates identically across languages; a custom module-hash caveat is the escape hatch. See \`examples/caveats_demo.py\` and the [caveats demo](/demos/#caveats).

## Inference Provenance

\`vouch.provenance\` binds an output to a fingerprint of the model weights and a Merkle root over the retrieved context, plus the sampler settings. An auditor re-fetches the sources to reproduce the context root (\`context_root_mismatch\` on a substituted context) and re-runs the model on the same seed to byte-compare the output (\`output_mismatch\`, \`weights_mismatch\`). See \`examples/provenance_demo.py\` and the [provenance demo](/demos/#provenance).

## Action Transparency

\`vouch.transparency\` submits consequential actions to an append-only RFC 6962 Merkle log that signs its size and root as a Signed Tree Head. A verifier demands an inclusion proof that an action is in the log (\`inclusion_failed\`), and a monitor demands a consistency proof that an older tree head is a strict prefix of a newer one (\`consistency_failed\`, \`tree_shrank\`), so the log cannot omit or rewrite an action. See \`examples/transparency_demo.py\`.

## How they compose

None of these verify an agent's mind. Together they make harm hard to hide even for a misaligned agent: it must state a reason on the record, wait out a window a human can veto, stay inside an authority that cannot be broadened, against a decision that is reproducible, in front of a public append-only log.
`,
      },
    ],
  },

  // =====================================================================
  // AI ASSISTANTS: walkthroughs for each surface
  // =====================================================================
  {
    id: 'ai-assistants',
    title: 'AI Assistants',
    description: 'Install and use the Claude Skill, OpenAI Custom GPT, Gemini Gem, and the Vouch Assistant on this website.',
    articles: [
      {
        id: 'claude-skill-install',
        title: 'Installing the Claude Skill',
        summary: 'Drop-in skill that teaches Claude Code the Vouch SDK shapes, DID conventions, and integration patterns.',
        body: `
## Install (recommended): the marketplace

Add the Vouch marketplace once, then install the plugin:

\`\`\`
/plugin marketplace add vouch-protocol/vouch
/plugin install vouch-protocol@vouch
\`\`\`

Run \`/plugin\` to confirm it is enabled. The skill loads automatically when you mention Vouch topics, so there is nothing else to do.

## Install (manual)

Prefer to drop it in by hand? Copy the skill folder into your skills directory.

\`\`\`bash
git clone https://github.com/vouch-protocol/vouch
cp -r vouch/claude-skill/skills/vouch-protocol ~/.claude/skills/vouch-protocol
\`\`\`

\`\`\`powershell
git clone https://github.com/vouch-protocol/vouch
Copy-Item -Recurse vouch\\claude-skill\\skills\\vouch-protocol "$env:USERPROFILE\\.claude\\skills\\vouch-protocol"
\`\`\`

Restart Claude Code and run \`/skills\`. You should see \`vouch-protocol\` listed.

## What triggers it

The skill loads when your prompt mentions \`vouch-protocol\`, \`did:web\`, \`eddsa-jcs-2022\`, \`hybrid-eddsa-mldsa44-jcs-2026\`, \`BitstringStatusList\`, \`SessionVoucher\`, \`Heartbeat Protocol\`, or natural-language variants like "sign a credential with Vouch" or "verify a Vouch credential."

## What's inside

The plugin lives at \`claude-skill/\`: \`SKILL.md\` (the skill) under \`skills/vouch-protocol/\`, a \`.claude-plugin/plugin.json\` manifest, and a \`reference/\` folder covering the language SDKs, the credential format, delegation, post-quantum, revocation, state verifiability, integrations, and troubleshooting.

## Updating

If you installed from the marketplace:

\`\`\`
/plugin marketplace update vouch
\`\`\`

If you installed manually, pull the repo and re-copy the folder. The skill versions with the protocol, so update whenever Vouch ships a new cryptosuite or SDK shape.

## Customising for your team

Fork the \`claude-skill/\` folder and edit references to add your DID prefix, your verifier hostname, your team's action vocabulary. Update \`SKILL.md\`'s description so it triggers on your terminology too.

## What if I use Claude Desktop or the web app

Skills are a Claude Code (CLI) feature. On Desktop or the web app, paste the contents of \`SKILL.md\` and the relevant \`reference/*.md\` files into your project's Custom Instructions.
`,
      },
      {
        id: 'openai-gpt-build',
        title: 'Building the OpenAI Custom GPT',
        summary: 'Configuration to build your own Vouch Protocol Assistant in ChatGPT.',
        body: `
We do not host a shared Custom GPT. Build your own from the configuration in \`openai-gpt/\` in the repo.

## Build steps

1. Open https://chatgpt.com/gpts/editor and click Create.
2. Switch to the Configure tab.
3. Paste each field from its file:
   - **Name** ← \`name.txt\`
   - **Description** ← \`description.txt\`
   - **Instructions** ← \`instructions.md\` (the whole file)
   - **Conversation starters** ← one line per starter from \`conversation-starters.md\`
4. Upload all files in \`openai-gpt/knowledge/\` to the Knowledge section.
5. Enable Web Browsing and Code Interpreter. Leave DALL-E off.
6. Optionally add Actions: paste \`actions.yaml\`, configure auth per \`actions-auth.md\`. This lets the GPT call the hosted Vouch Assistant to sign for you.
7. Save as "Only me" first. Test in the preview pane. Promote to "Anyone with the link" or "Public" when you are satisfied.

## Why we publish the config instead of a shared GPT

Custom GPTs are tied to one OpenAI account, change owner with acquisitions, and cannot be forked. Publishing the source of truth in the repo lets your team build a version it controls, audits, and updates.

## Updating

When Vouch ships a new SDK shape or cryptosuite, pull the latest \`openai-gpt/\` from the repo. In the GPT editor, replace the knowledge files (the builder deduplicates by filename) and bump the version note in the Instructions.
`,
      },
      {
        id: 'gemini-gem-create',
        title: 'Creating the Gemini Gem',
        summary: 'Configuration to build your own Vouch Protocol Helper in Google Gemini.',
        body: `
## Build steps

Gemini Advanced or Google AI Pro for the full ten-file corpus; the free tier supports a smaller attachment.

1. Open https://gemini.google.com/gems/create.
2. Click New Gem.
3. Paste \`gemini-gem/name.txt\`, \`description.txt\`, and \`instructions.md\`.
4. Upload all files in \`gemini-gem/knowledge/\`.
5. Add the prompts from \`examples.md\` as the Gem's Examples.
6. Click Preview and run a test prompt.
7. Save & share (Private / Anyone with the link / Workspace org).

## Workspace integration

Because Gems live inside Gemini, they automatically have access to Google Workspace tools. The Vouch Gem is instructed to:

- Confirm before creating any Doc, Sheet, or email.
- Use Google Search when you ask about current GitHub state.

## Free tier vs Advanced

Free tier: trim the corpus to four files (\`overview.md\`, \`quickstart.md\`, \`credential-format.md\`, \`troubleshooting.md\`). Gemini Advanced and Workspace plans support the full ten-file corpus and long context.

## Sharing inside your Workspace org

In the Gem's Save dialog, choose "Visible to anyone in [your org]". Workspace admins can install Gems for all users from the admin console.
`,
      },
      {
        id: 'assistant-local',
        title: 'Running the Vouch Assistant locally',
        summary: 'Three processes: dev sidecar, agent backend, chat widget. Browse to localhost:3200.',
        body: `
The chat helper on vouch-protocol.com is open source under \`website-agent/\` in the repo. You can self-host it.

## Three processes, three terminals

### 1. Dev sidecar (ephemeral Ed25519 key, dev only)

\`\`\`bash
cd ~/vouch-protocol/website-agent/backend
python -m vouch_agent.dev_sidecar --did did:web:agent.example.com --port 8877
\`\`\`

### 2. Agent backend (FastAPI + RAG + signer client)

\`\`\`bash
cd ~/vouch-protocol/website-agent/backend
cp ../.env.example ../.env
# edit ../.env to add your LLM key
uvicorn vouch_agent.main:app --host 127.0.0.1 --port 8000
\`\`\`

### 3. Chat widget (standalone Next.js harness)

\`\`\`bash
cd ~/vouch-protocol/website-agent/standalone
npm install
npm run dev    # http://localhost:3200
\`\`\`

Open **http://localhost:3200**. The status strip shows backend OK, sidecar OK, and the number of knowledge chunks indexed.

## Pick an LLM provider

The backend supports three:

\`\`\`bash
# Anthropic (default)
export VOUCH_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
export VOUCH_LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# Google Gemini
export VOUCH_LLM_PROVIDER=gemini
export GEMINI_API_KEY=...
\`\`\`

\`\`\`powershell
# Anthropic (default)
$env:VOUCH_LLM_PROVIDER = "anthropic"
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# OpenAI
$env:VOUCH_LLM_PROVIDER = "openai"
$env:OPENAI_API_KEY = "sk-..."

# Google Gemini
$env:VOUCH_LLM_PROVIDER = "gemini"
$env:GEMINI_API_KEY = "..."
\`\`\`

Or set them in \`website-agent/.env\` (auto-loaded on backend start).

## Production deployment

For production, replace the dev sidecar with the Go sidecar (\`vouch-sidecar\`) backed by KMS, and run the agent backend behind a reverse proxy with TLS. The backend is self-contained; everything else (LLM provider, sidecar URL, CORS allow-list) is environment-driven.
`,
      },
      {
        id: 'sidecar-tiers',
        title: 'Choosing a sidecar tier',
        summary: 'Go for production, Python or TypeScript for lightweight self-hosting, Python `dev_sidecar` for local development.',
        body: `
Three reference sidecars ship with the protocol. They are not interchangeable in production. Pick by use case, not language preference.

## Tier table

| Tier | Language | Use case | Key storage |
|---|---|---|---|
| **Production** | Go (\`go-sidecar/\`) | Audited, regulated, high-throughput | KMS / HSM / file |
| **Lightweight** | Python (\`vouch.sidecar.*\`) | Self-hosted Python stacks | File or env |
| **Lightweight** | TypeScript (\`packages/sdk-ts/sidecar/\`) | Self-hosted Node stacks | File or env |
| **Development** | Python \`dev_sidecar\` | Local dev only | Ephemeral, in-memory |

**Rule of thumb**: if your auditor will ask about the sidecar, run the Go one.

## Why the lightweight tier is lightweight on purpose

The sidecar is security-critical, so smaller code surface is safer. The Python and TS sidecars intentionally omit:

- Hybrid post-quantum signing (\`hybrid-eddsa-mldsa44-jcs-2026\`)
- KMS / HSM integration
- Sensitive-mode JWE wrapping
- Heartbeat session validation
- Multi-tenancy

When you need any of those, switch to the Go sidecar. The wire format is identical, so the client only changes one environment variable.

## Cross-language equivalence

All three sidecars expose the same HTTP API:

- \`GET /health\`: liveness probe
- \`GET /did\`: the sidecar's DID
- \`GET /.well-known/did.json\`: DID Document (optional)
- \`POST /sign\`: sign an intent, return a Vouch credential

A shared contract test suite at \`test-vectors/sidecar-contract/\` verifies that each implementation accepts and rejects the same inputs and emits semantically equivalent credentials.

## Switching tiers

The HTTP API is identical:

\`\`\`bash
export VOUCH_SIDECAR_URL=http://localhost:8877
\`\`\`

The agent code does not change. What changes is the DID (production agents use a real did:web on your domain) and the key material (production loads from KMS).
`,
      },
    ],
  },
  {
    id: 'conformance',
    title: 'Conformance',
    description:
      'Test whether an implementation, an SDK, fork, or port, produces byte-correct protocol output and supports the required feature sets, graded L1 to L3.',
    articles: [
      {
        id: 'test-your-implementation',
        title: 'Test your conformance level',
        summary:
          'Run the reference conformance runner against your implementation and read the highest level it passes.',
        body: `
## What conformance checks

Conformance grades an implementation in three cumulative levels. A level is achieved only when every check at that level and all lower levels passes.

- **L1 Credential**: RFC 8785 JCS canonicalization, \`eddsa-jcs-2022\` sign and verify, the validity window (an expired credential is rejected), and nonce replay resistance.
- **L2 Structural-Security**: everything in L1, plus BitstringStatusList revocation, delegation narrowing with the five-link depth bound, the Identity Sidecar allow and deny behaviour, and a hash-linked audit trail.
- **L3 State Verifiable plus Post-Quantum**: everything in L2, plus the hybrid dual-proof (\`eddsa-jcs-2022\` and \`mldsa44-jcs-2026\` over the same JCS bytes), the Heartbeat renewal chain, and an M-of-N validator quorum.

Robotics is a separate profile, Robotics Conformant, not part of L1 to L3.

## Run the self-test

\`\`\`bash
python -m vouch.conformance
\`\`\`

It runs the checks in-process against the SDK and prints a per-check pass or fail, then the highest fully-passing level:

\`\`\`
L1
  [PASS] canonicalization: 13 vectors
  [PASS] sign_verify: round-trip and tamper rejection
  ...
Highest fully-passing level: L3
\`\`\`

## The verified badge (coming)

The self-test proves conformance to yourself. A hosted verifier is coming that issues fresh random challenges, re-checks every response server-side with the canonical core, and mints a signed \`VouchConformanceCredential\` unique to your implementation. Because it recomputes every expected answer, a pass cannot be faked by replaying the public test vectors, and anyone can re-verify Vouch's signature and re-run the challenges. Until it is live, the [conformance page](/conformance) carries a self-declaration and shows what a verified pass earns.
`,
      },
    ],
  },
  {
    id: 'robotics',
    title: 'Robotics: getting started',
    domain: 'robotics',
    description: 'Pick a language and run the robot identity sign-and-verify loop in your dev env. The six capabilities are byte-identical across every SDK, so a robot credential signed in one verifies in all the others.',
    articles: [
      {
        id: 'robotics-quickstart-python',
        title: 'Robotics Quickstart (Python)',
        summary: 'Mint a hardware-attested robot identity and verify it, entirely in your dev env.',
        body: `
## Install

\`\`\`bash
pip install vouch-protocol
\`\`\`

## Mint and verify a robot identity

A robot self-issues its identity with its own key; a hardware root (a TPM or secure element) signs a binding tying that key to the device. In development, \`SoftwareRootOfTrust\` stands in for the TPM.

\`\`\`python
from vouch.keys import generate_identity
from vouch.signer import Signer
from vouch.robotics import identity

robot = Signer.from_identity(generate_identity(domain="robot.example.com"))
root = identity.SoftwareRootOfTrust(kind="TPM")        # production uses the real TPM

cred = identity.mint_robot_identity(robot, root,
    make="Acme Robotics", model="AR-7", serial="SN-000123",
    owner="did:web:owner.example.com")

ok, subject = identity.verify_robot_identity(cred, robot.public_key())
assert ok and subject["make"] == "Acme Robotics"
\`\`\`

Verification checks both the credential proof and the hardware attestation, so an identity copied to different hardware fails. From here, the other five capabilities (\`provenance\`, \`capability\`, \`handshake\`, \`blackbox\`, \`passport\`) follow the same import-and-call shape; see the Robotics: capabilities guides.
`,
      },
      {
        id: 'robotics-quickstart-typescript',
        title: 'Robotics Quickstart (TypeScript)',
        summary: 'The same robot identity loop in TypeScript, for Node or the browser.',
        body: `
## Install

\`\`\`bash
npm install @vouch-protocol-official/sdk
\`\`\`

## Mint and verify a robot identity

\`\`\`ts
import { Signer, generateIdentity } from '@vouch-protocol-official/sdk';
import { SoftwareRootOfTrust, mintRobotIdentity, verifyRobotIdentity } from '@vouch-protocol-official/sdk';

const robot = await Signer.fromIdentity(generateIdentity('robot.example.com'));
const root = new SoftwareRootOfTrust('TPM');

const cred = await mintRobotIdentity(robot, root, {
  make: 'Acme Robotics', model: 'AR-7', serial: 'SN-000123',
  owner: 'did:web:owner.example.com',
});

const { ok, subject } = verifyRobotIdentity(cred, robot.publicKey());
\`\`\`

Function names are camelCase; everything else matches the Python and Go SDKs byte for byte.
`,
      },
      {
        id: 'robotics-quickstart-go',
        title: 'Robotics Quickstart (Go)',
        summary: 'The robot identity loop in Go, the language of the Identity Sidecar.',
        body: `
## Get the module

\`\`\`bash
go get github.com/vouch-protocol/vouch/go-sidecar
\`\`\`

## Mint and verify a robot identity

\`\`\`go
root, _ := robotics.NewSoftwareRoot(seed, "TPM")
cred, _ := robotics.MintRobotIdentity(robotSigner, root, robotics.MintOptions{
    Make: "Acme Robotics", Model: "AR-7", Serial: "SN-000123",
    Owner: "did:web:owner.example.com",
})
ok, subject := robotics.VerifyRobotIdentity(cred, robotSigner.PublicKeyEd25519())
\`\`\`

Go uses PascalCase and an options struct; the credential bytes are identical to Python and TypeScript.
`,
      },
      {
        id: 'robotics-quickstart-languages',
        title: 'Robotics Quickstart (Swift, Kotlin, JVM, .NET, C, WebAssembly)',
        summary: 'The robotics surface over the shared core, JSON in and JSON out, for the wrapper languages.',
        body: `
The robotics capabilities are implemented once in the Rust core and exposed through the same UniFFI and WebAssembly wrappers as the rest of Vouch. The wrapper functions are JSON-in / JSON-out: keys cross as bytes, everything else as a JSON string, and binary fields (the hardware attestation, the config hash) cross as multibase strings.

## Browser and Node (WebAssembly)

\`\`\`js
import init, { roboticsMintIdentity, roboticsVerifyIdentity } from '@vouch-protocol-official/core-wasm';
await init();

const params = JSON.stringify({
  robotDid: 'did:web:robot.example.com', make: 'Acme Robotics', model: 'AR-7',
  serial: 'SN-000123', rootKind: 'TPM', rootPublicMultibase: rootMultibase,
  attestation: attestationMultibase, validFrom: new Date().toISOString(),
});
const credJson = roboticsMintIdentity(seedBytesB64, params);
const subjectJson = roboticsVerifyIdentity(credJson, robotPublicKeyB64);  // "null" if invalid
\`\`\`

## Swift, Kotlin/Java, .NET, C and C++

The same functions are generated for each platform from the core's UniFFI interface and C header. The names match the WebAssembly build (\`roboticsMintIdentity\`, \`roboticsVerifyIdentity\`, \`roboticsBuildScope\`, \`roboticsCheckAction\`, \`roboticsBuildHello\`, and so on), and every capability is present. Pass the same JSON params and key bytes; a credential built here verifies in Python, TypeScript, and Go.
`,
      },
    ],
  },
  {
    id: 'robotics-capabilities',
    title: 'Robotics: capabilities',
    domain: 'robotics',
    description: 'One guide per robotics capability: what it is, the problem it closes, how it works, the API, a worked example, and exactly what verification checks.',
    articles: [
      {
        id: 'robotics-identity',
        title: 'Hardware-rooted identity',
        summary: 'Bind a robot identity to a TPM or secure element so it cannot be cloned to other hardware.',
        body: `
A \`RobotIdentityCredential\` binds a robot's software identity key to a physical hardware root of trust, alongside its make, model, serial, owner, and lifecycle history.

The problem it closes: a software-only identity in a config file can be copied to a cloned robot. Hardware rooting makes the identity non-transferable: it is provably tied to one piece of silicon.

How it works: the robot self-issues the credential with its own Ed25519 key. The hardware root signs a binding, the JCS canonical bytes of \`{key, robotDid}\`, embedded as \`hardwareRoot.attestation\`. Verification checks two independent signatures: the credential proof and the hardware attestation.

\`\`\`python
from vouch.robotics import identity

root = identity.SoftwareRootOfTrust(kind="TPM")        # production uses the real TPM
cred = identity.mint_robot_identity(robot_signer, root,
    make="Acme Robotics", model="AR-7", serial="SN-000123",
    owner="did:web:owner.example.com")
ok, subject = identity.verify_robot_identity(cred, robot_signer.public_key())
\`\`\`

Security boundary: verification fails closed on a wrong type, an invalid proof, a missing or non-Ed25519 hardware key, or an attestation that does not match the binding. An attacker who swaps in their own hardware key and re-signs the credential still fails, because the attestation no longer matches \`{key, robotDid}\`.
`,
      },
      {
        id: 'robotics-provenance',
        title: 'Model and config provenance',
        summary: 'Prove which model, weights, safety policy, and config a robot ran, even after an OTA update.',
        body: `
A \`ModelProvenanceAttestation\` records the vision-language-action model name, weights hash, safety policy, and a hash of the running configuration.

The problem it closes: after an incident, logs alone cannot prove what software and safety policy were running. Provenance makes it cryptographic, and it survives over-the-air updates.

How it works: the \`vla\` block carries \`modelName\`, \`weightsHash\`, \`safetyPolicy\`, and a \`configHash\` (the multibase SHA-256 of the JCS-canonical config, reproducible by any verifier). On an OTA update the robot re-signs a new attestation with a \`supersedes\` link to the previous one, forming a chain.

\`\`\`python
from vouch.robotics import provenance

att = provenance.build_provenance_attestation(signer, robot_did=robot_did,
    model_name="openvla-7b", weights_hash="u...",
    safety_policy="did:web:authority#policy-v3",
    config={"temperature": 0.0, "max_torque": 12.5, "guardrails": ["no_humans_zone"]})
ok, subject = provenance.verify_provenance_attestation(att, signer.public_key(), config)
\`\`\`

Security boundary: verification fails on a wrong type, an invalid proof, or, when a config is supplied, a \`configHash\` that does not reproduce. A robot running a different config than the one attested is detectable by anyone holding the expected config.
`,
      },
      {
        id: 'robotics-capability',
        title: 'Physical capability scope',
        summary: 'Force, speed, near-humans, zone, and shift-window limits, checked before each actuation.',
        body: `
A \`PhysicalCapabilityScope\` credential carries physical limits, max force, max speed, a tighter cap near humans, allowed zones, and shift windows, that a controller checks before every actuation.

The problem it closes: a permission like "operate the arm" says nothing about how hard or how fast. Physical scope makes the bound enforceable and makes delegated authority shrink-only.

How it works: a controller calls the check function with a proposed action and gets back whether it is allowed plus a reason for each violated dimension. Delegation is governed by an attenuation rule: a child scope is valid only if every numeric cap is less than or equal to the parent, every zone is a subset, and every window fits inside a parent window.

\`\`\`python
from vouch.robotics import capability

scope = cred["credentialSubject"]["physicalScope"]
res = capability.check_physical_action(scope,
    capability.PhysicalAction(speed_mps=1.5, near_humans=True))
# res.ok is False: the near-humans speed cap is 0.5 m/s
\`\`\`

Security boundary: the runtime check rejects an action exceeding any granted dimension (an absent dimension is unconstrained by design). \`attenuates(parent, child)\` is the escalation guard: a child that raises a cap, drops a cap, adds a zone outside the parent set, or widens a window is rejected.
`,
      },
      {
        id: 'robotics-handshake',
        title: 'Robot-to-robot handshake',
        summary: 'Two robots from different fleets authenticate and agree a bounded cooperation session.',
        body: `
A three-message exchange (HELLO, ACCEPT, CONFIRM) by which two robots in different trust domains authenticate each other and agree a bounded cooperation session.

The problem it closes: when robots from different fleets meet and must cooperate, each needs to know the other is who it claims and agree on a safe, limited set of shared actions, with no central broker.

How it works: the initiator signs a HELLO proposing a scope and a fresh nonce. The responder verifies the HELLO signature, checks the initiator's \`did:web\` domain against its trust policy, and signs an ACCEPT whose \`boundedScope\` is the intersection of the proposed scope and what the responder offers, never the union. The initiator verifies the ACCEPT, confirms the nonce echoes its HELLO, and signs a CONFIRM.

\`\`\`python
from vouch.robotics import handshake

policy = handshake.TrustPolicy(trusted_domains={"robot-a.example.com"})
hello = handshake.build_hello(a_signer, proposed_scope=["lift", "carry", "scan"])
accept = handshake.build_accept(b_signer, hello, a_signer.public_key(), policy,
    offered_scope=["carry", "scan", "weld"])
ok, session = handshake.verify_accept(accept, b_signer.public_key(),
    expected_nonce=hello["nonce"])
# session.scope == ["carry", "scan"]  (the intersection)
\`\`\`

Security boundary: the responder signs an acceptance only if the HELLO signature verifies and the initiator's domain passes the policy. The session scope is the intersection of both offers, so neither side can widen the other's grant. The nonce binds the acceptance to its HELLO, and a tampered message fails verification.
`,
      },
      {
        id: 'robotics-blackbox',
        title: 'Black box and kill switch',
        summary: 'An encrypted, tamper-evident flight recorder, and a verifiable emergency stop.',
        body: `
Two related capabilities ship together.

The black box is an append-only, AES-256-GCM-encrypted, hash-linked flight recorder. Each entry encrypts its payload under a 32-byte key; the chain is tamper-evident without the key (any altered field breaks its \`entryHash\`, any reorder breaks \`prevHash\`), and the payloads open only with the key. An auditor can prove nothing was changed without being able to read the contents.

The kill switch is a verifiable emergency stop. A \`KillSwitchCredential\` proves who issued the stop, over what scope, and why. With an attested-authority allowlist, verification rejects any issuer not on the list.

\`\`\`python
from vouch.robotics import blackbox

log = blackbox.BlackBoxLog(key)                       # 32-byte AES key
entry = log.append("motion", {"speed": 1.5, "joint": "elbow"})
assert blackbox.verify_blackbox_chain(log.entries()).ok
payload = log.open_entry(entry)                       # only the key holder can read this

stop = blackbox.build_killswitch_credential(authority, target=robot_did,
    reason="human in path", scope=["arm", "drive"])
ok, subject = blackbox.verify_killswitch_credential(stop, authority.public_key(),
    trusted_authorities={authority.did})
\`\`\`

Security boundary: chain verification fails on a seq gap, a broken \`prevHash\` link, or a recomputed \`entryHash\` that does not match. Decryption fails under the wrong key. The kill switch fails on a wrong type, an invalid proof, or an issuer that is not an attested authority.
`,
      },
      {
        id: 'robotics-passport',
        title: 'Scannable passport',
        summary: 'A signed passport in a QR or NFC tag that anyone can verify offline.',
        body: `
A compact, signed \`RobotPassport\` encoded into a \`vouch-passport:\` URI for a QR code or NFC tag, so anyone can check a robot's owner, authorized actions, certification, and current standing offline, with no network call.

The problem it closes: a person standing in front of a robot needs to know it is legitimate and what it is allowed to do, often with no connectivity.

How it works: the passport credential carries the robot's identity summary and a \`status\` (active, suspended, or decommissioned). \`encode_passport\` serializes the JCS-canonical credential into a deterministic multibase payload behind the \`vouch-passport:\` scheme, so a scanner verifies the signature locally.

\`\`\`python
from vouch.robotics import passport

p = passport.build_passport(signer, robot_did=robot_did, make="Acme Robotics",
    model="AR-7", owner="did:web:owner.example.com",
    authorized_actions=["lift", "carry"], certification="ISO-10218")
uri = passport.encode_passport(p)                     # "vouch-passport:u..."
ok, summary = passport.verify_passport(passport.decode_passport(uri), signer.public_key())
\`\`\`

Security boundary: verification is fully offline (the verifier supplies the issuer key). An expired passport fails. A suspended or decommissioned passport still verifies but the status is surfaced, so a scanner refuses cooperation rather than treating it as silently inactive. A tampered passport or a wrong type is rejected.
`,
      },
      {
        id: 'robotics-liveness',
        title: 'Living trust heartbeat',
        summary: 'A robot heartbeats with a signed motion summary; trust holds only while it stays fresh and in-envelope.',
        body: `
A \`RobotHeartbeatCredential\` makes robot trust living: the robot periodically self-signs a summary of what it physically did, and a verifier trusts it only while a fresh, in-envelope heartbeat keeps arriving.

The problem it closes: an identity or capability credential, minted once, stays valid until something revokes it. A robot that drifted, was tampered with, or went dark should lose trust on its own.

How it works: a \`MotionCollector\` records each commanded motion (force, speed, near-humans, zone) and produces a motion digest of the interval (peak force, peak speed, peak speed near humans, zone breaches, breach count, and a \`withinEnvelope\` flag) by checking each sample against the signed \`PhysicalCapabilityScope\`. \`is_live\` returns true only when the heartbeat is recent (within a grace window of the declared interval) and the digest reports \`withinEnvelope\`.

\`\`\`python
from vouch.robotics import liveness

col = liveness.MotionCollector(scope=scope["physicalScope"])
col.record(force_n=12.0, speed_mps=0.4, near_humans=True, zone="cell-3")
hb = liveness.build_robot_heartbeat(robot_signer, session_id="sess-1",
    interval_index=0, motion_digest=col.digest(), interval_seconds=30)
ok, subject = liveness.verify_robot_heartbeat(hb, robot_signer.public_key())
live = liveness.is_live(hb)                            # fresh AND in-envelope
\`\`\`

Security boundary: \`verify_robot_heartbeat\` fails closed on a wrong type, an invalid proof, or a malformed digest. \`is_live\` returns false on a stale heartbeat, an envelope breach, or a future-dated heartbeat beyond one interval of clock skew, so neither going dark nor exceeding the envelope leaves a robot trusted.
`,
      },
      {
        id: 'robotics-revocation',
        title: 'Credential revocation',
        summary: 'Surgically revoke one robot credential via a status list, or kill a whole robot identity at the DID level.',
        body: `
Robot credentials get the same two-level revocation as the rest of Vouch: a surgical per-credential status, and a whole-DID kill.

The problem it closes: the kill switch stops one running robot locally, but a compromised capability grant or a leaked identity key needs to be invalidated for every verifier, not just stopped once.

How it works: \`attach_credential_status\` adds a BitstringStatusList \`credentialStatus\` entry to a robot credential and re-signs it; flipping the bit in the published status list revokes it, and \`check_credential_status\` reports the result. For key compromise or a captured robot, the existing \`RevocationRegistry\` (re-exported from \`vouch.robotics\`) revokes the robot DID wholesale.

\`\`\`python
from vouch.robotics import revocation

cred = revocation.attach_credential_status(scope_cred, robot_signer,
    status_list_credential="https://fleet.example/status/1", status_list_index=42)
revoked = revocation.check_credential_status(cred, status_list_cred)   # bit lookup

reg = revocation.RevocationRegistry(check_remote=False)
await reg.revoke(robot_did, reason="hardware captured")               # whole-DID kill
\`\`\`

Security boundary: \`check_credential_status\` returns true only when the credential's status entry matches the fetched list (id and purpose) and the bit is set; the caller verifies the status list credential's own proof first. A robot DID is an ordinary DID, so the registry and the \`.well-known\` distribution path apply unchanged.
`,
      },
      {
        id: 'robotics-safety-record',
        title: 'Accountable safety record',
        summary: 'A tamper-evident incident ledger plus a portable signed record of a robot safety standing.',
        body: `
A \`SafetyEventLog\` is an append-only, hash-linked ledger of a robot's safety events, and a \`RobotSafetyRecordCredential\` is the portable signed summary that travels with the robot.

The problem it closes: a robot's safety history lives in scattered, mutable logs that an owner can quietly edit. Insurers, regulators, and new owners need a record they can trust without trusting the operator's word.

How it works: each safety event (incident, near-miss, manual override, kill-switch trigger, envelope breach) is appended with a severity and hash-linked to the previous entry, so the chain is tamper-evident (\`verify_safety_log\`). \`build_safety_record\` summarizes a stretch of the ledger into counts by event type and by severity, the period, and the ledger head hash that anchors it.

\`\`\`python
from vouch.robotics import safety_record

log = safety_record.SafetyEventLog()
log.append("near_miss", severity="low", details={"zone": "cell-3"})
log.append("envelope_breach", severity="high")
rec = safety_record.build_safety_record(authority_signer, robot_did=robot_did,
    summary=log.summarize())
ok, subject = safety_record.verify_safety_record(rec, authority_signer.public_key())
\`\`\`

Security boundary: \`verify_safety_log\` detects any altered or removed entry (the hash chain breaks). The record summary is anchored to the ledger head, so a summary that understates the log no longer matches its chain. \`verify_safety_record\` fails closed on a wrong type, an invalid proof, or a malformed summary.
`,
      },
      {
        id: 'robotics-perception',
        title: 'Perception provenance',
        summary: 'Sign what a robot sensor captured so it can prove what it saw and a substituted frame is detectable.',
        body: `
A \`PerceptionProvenanceCredential\` lets a robot prove what its sensors captured: the robot signs, at capture time, a record binding the frame's hash, the sensor, the modality, and the time to its DID.

The problem it closes: a robot acts on what its sensors report, and that evidence is exactly what gets spoofed or disputed after the fact. Signing the frame's provenance at capture makes "this is what I saw" verifiable, and makes a substituted or edited frame detectable.

How it works: \`hash_frame\` computes the multibase SHA-256 of the raw frame. A \`PerceptionLog\` hash-links each frame-provenance record into an append-only chain (the same chain the black box uses), so the sequence of perceived frames is tamper-evident. \`build_perception_attestation\` signs an attestation for a frame, optionally carrying the log head to anchor a whole segment. Only frame hashes are stored, never the raw frames.

\`\`\`python
from vouch.robotics import perception

log = perception.PerceptionLog()
entry = log.record(sensor_id="cam-front", modality="camera", frame=frame_bytes)
att = perception.build_perception_attestation(robot_signer, robot_did=robot_did,
    sensor_id="cam-front", modality="camera", frame_hash=entry["frameHash"],
    log_head=log.head())
ok, subject = perception.verify_perception_attestation(att, robot_signer.public_key(),
    frame=frame_bytes)                                # recomputes and compares the hash
\`\`\`

Security boundary: \`verify_perception_attestation\` fails closed on a wrong type, an invalid proof, an unknown modality, or, when the frame is supplied, a hash that does not reproduce. \`verify_perception_log\` detects any altered or dropped frame in the chain. The open layer signs frame hashes in software, so it proves authorship and integrity of the recorded frame, not that the frame is a live hardware capture.
`,
      },
      {
        id: 'robotics-lease',
        title: 'Offline delegation lease',
        summary: 'A short-lived, scope-bounded grant a disconnected robot verifies and acts on with no network call.',
        body: `
A \`DelegationLeaseCredential\` is a self-contained grant of authority a robot can verify and act on entirely offline, for places with no connectivity.

The problem it closes: a robot in a warehouse aisle, a field, or a tunnel cannot call home to check whether it is still allowed to do something. A lease bounds what it may physically do for a fixed, short window, and it carries everything needed to verify that, so the robot needs no network.

How it works: \`build_delegation_lease\` issues a lease bounding a physical capability scope (force, speed, near-humans, zones) with a validFrom and a short validUntil. \`verify_delegation_lease\` checks the signature, that the window is current, and, when a parent scope is supplied, that the lease attenuates it. Leases nest, each sub-grant only narrowing the one above, which forms the open cross-vendor chain.

\`\`\`python
from vouch.robotics import build_delegation_lease, verify_delegation_lease, lease_permits, PhysicalAction

lease = build_delegation_lease(authority_signer, robot_did=robot_did, lease_id="shift-42",
    scope={"maxForceN": 80.0, "allowedZones": ["cell-3"]}, valid_seconds=3600)
ok, subject = verify_delegation_lease(lease, authority_signer.public_key())   # offline
allowed = lease_permits(subject, PhysicalAction(force_n=10.0, zone="cell-3"), lease)
\`\`\`

Security boundary: verification is fully offline. An expired or not-yet-valid lease fails. A sub-lease that widens any dimension of its parent (more force, a new zone, a wider window) is rejected by the attenuation check, so authority can only narrow down a chain, never grow.
`,
      },
      {
        id: 'robotics-quorum',
        title: 'Physical quorum',
        summary: 'A cryptographic two-person rule: M of N attested approvers must sign off before a high-consequence action.',
        body: `
A physical quorum requires several independent approvals before a robot performs a high-consequence action, such as applying large force near a person or an irreversible move.

The problem it closes: some actions are serious enough that no single authority should be able to order them alone. A quorum makes the two-person rule cryptographic rather than procedural.

How it works: each approver signs a \`PhysicalActionApprovalCredential\` over the same action id and robot. \`verify_action_authorization\` counts the DISTINCT valid approvers from an attested approver set and authorizes the action only when at least the threshold number have approved.

\`\`\`python
from vouch.robotics import build_action_approval, verify_action_authorization

approvals = [build_action_approval(a, action_id="weld-7", robot_did=robot_did) for a in approvers]
authorized, who = verify_action_authorization(approvals, action_id="weld-7", robot_did=robot_did,
    approver_keys=approver_public_keys, threshold=2)
\`\`\`

Security boundary: only distinct approvers from the attested set count, so one approver cannot reach the threshold by signing twice. Approvals for a different action or robot, from outside the approver set, with an invalid proof, out of date, or carrying a reject decision are all ignored.
`,
      },
      {
        id: 'robotics-lifecycle',
        title: 'Lifecycle and decommissioning',
        summary: 'Cryptographically accountable ownership transfer, key rotation, and retirement for a robot over its whole life.',
        body: `
A robot is commissioned, resold, repurposed, and eventually scrapped. This makes each of those transitions verifiable: a chain of custody, a key history, and an end-of-life record.

The problem it closes: a robot outlives its first owner, and today there is no cryptographic way to prove who owns it now, which keys it has used, or that it was properly retired.

How it works: \`build_ownership_transfer\` lets the current owner hand the robot to a new owner, and linking each transfer forms a chain that \`verify_custody_chain\` walks. \`build_key_rotation\` lets the current key authorize a successor, forming a key history (\`verify_key_history\`). \`build_decommission\` retires the robot, after which a verifier should refuse to trust it.

\`\`\`python
from vouch.robotics import build_ownership_transfer, build_key_rotation, build_decommission

transfer = build_ownership_transfer(seller_signer, robot_did=robot, to_owner=buyer_did)
rotation = build_key_rotation(robot_signer, robot_did=robot, new_key_multibase=new_key)
retired  = build_decommission(authority_signer, robot_did=robot, reason="end of service life",
                              final_disposition="recycled")
\`\`\`

Security boundary: a transfer verifies only when its issuer is the current owner, so no one but the owner can hand the robot on. A key rotation must be signed by the key it rotates from, so the chain of trust is unbroken. A decommission can be restricted to an attested authority set. The open layer records these as plain signed credentials; a verifier decides how strictly to enforce them.
`,
      },
      {
        id: 'robotics-conformance',
        title: 'Regulatory conformance',
        summary: 'Map a robot credentials to safety and AI regulations, check coverage, and sign an attestation an auditor can consume.',
        body: `
A conformance profile is a machine-checkable mapping from a robot's Vouch credentials to the clauses of a public safety or AI regulation. Instead of a static certificate on paper, conformance becomes something a verifier can check from the credentials the robot actually holds.

The problem it closes: regulators and operators need to know a robot meets ISO 10218, ISO/TS 15066, the EU Machinery Regulation, the EU AI Act, or UL 3300, and today that lives in documents no machine can check.

How it works: \`check_conformance(credentials, profile_id)\` walks the named profile and reports, for each requirement, whether the presented credentials satisfy it, citing the clause. An assessing party then signs an attestation over that report.

\`\`\`python
from vouch.robotics import check_conformance, build_conformance_attestation

report = check_conformance([identity, provenance, scope, safety_record], "eu-ai-act-high-risk")
print(report["conforms"], report["satisfiedCount"], "/", report["totalCount"])

attestation = build_conformance_attestation(assessor_signer, robot_did=robot, report=report)
\`\`\`

Built-in reference profiles: \`iso-10218\`, \`iso-ts-15066\`, \`eu-machinery-2023-1230\`, \`eu-ai-act-high-risk\`, and \`ul-3300\`.

Security boundary: the report is deterministic, so any language reproduces it from the same credentials. The attestation embeds the report and binds it by digest, so \`verify_conformance_attestation\` rejects a report that was altered after signing. The profiles are a reference crosswalk, not legal advice; a deployment confirms each mapping against the current regulation text for its market.
`,
      },
      {
        id: 'robotics-pq',
        title: 'Post-quantum signing',
        summary: 'Sign robot credentials with a hybrid classical and post-quantum signature so they stay unforgeable across a robot decade-long life.',
        body: `
A robot fielded today runs for ten to twenty years, longer than classical Ed25519 is expected to stay safe. This signs robot credentials with the hybrid post-quantum cryptosuite so a robot identity signed now cannot be forged once a quantum computer arrives.

The problem it closes: a long-lived robot signed with a classical-only key could have its identity forged decades into its service life, when the classical signature no longer holds.

How it works: \`sign_pq\` attaches a hybrid proof, a classical Ed25519 signature alongside an ML-DSA-44 post-quantum signature, under \`hybrid-eddsa-mldsa44-jcs-2026\`. \`verify_robot_credential\` verifies a robot credential whether it carries a classical or a hybrid proof, detected from the credential, so a fleet moves to post-quantum gradually. \`migrate_to_pq\` re-signs a fielded robot's classical credential under a post-quantum key.

\`\`\`python
from vouch.robotics import sign_pq, verify_robot_credential, mint_robot_identity

identity = sign_pq(mint_robot_identity(robot, root, make="Acme", model="AR-7", serial="SN-1"), robot)
ok = verify_robot_credential(identity, robot_ed25519_public_key,
                             mldsa44_public_key=robot.public_key_mldsa44_multikey())
\`\`\`

Security boundary: a hybrid credential passes only when both the classical and the post-quantum signature validate, so it is at least as strong as the classical signature and stays safe once classical signatures do not. Verifying a hybrid credential needs the ML-DSA-44 public key. The open layer is software signing, backward-compatible verification, and a software re-sign migration; managed post-quantum key custody and fleet migration are commercial.
`,
      },
      {
        id: 'robotics-wrapper-sdks',
        title: 'Robotics from the C, C++, .NET, JVM, and Swift SDKs',
        summary: 'Verify and integrate robot credentials from the wrapper SDKs through a curated VouchRobotics surface over the same Rust core.',
        body: `
The reference SDKs (Python, TypeScript, Go, and the Rust core) carry the full robotics surface. The C, C++, .NET, JVM (Java and Kotlin), and Swift wrappers expose a curated consumer surface over the same core, the same way they expose the agent operations, so an application in those languages can verify and integrate robot credentials without leaving its stack.

The curated surface: \`verify_robot_credential\` (verify a classical or a hybrid post-quantum proof, auto-detected), \`mint_identity\` and \`verify_identity\`, \`check_conformance\` with \`build_conformance_attestation\` and \`verify_conformance_attestation\`, \`verify_passport\`, \`check_action\`, and \`sign_pq\`. In .NET, JVM, and Swift these are a \`VouchRobotics\` class; in C++ a \`vouch::robotics\` namespace.

\`\`\`csharp
using VouchProtocol.Core;

bool ok = VouchRobotics.VerifyRobotCredential(credentialJson, ed25519PublicB64);
string report = VouchRobotics.CheckConformance(credentialsJson, "eu-ai-act-high-risk");
\`\`\`

Output is byte-identical to the reference SDKs, so a robot credential produced in one language verifies in every other. The producer-side operations (handshakes, the black box, physical quorum, the liveness heartbeat) stay in the reference SDKs; a wrapper application that needs one of those calls a reference SDK or a service built on it.
`,
      },
      {
        id: 'robotics-embodiment',
        title: 'Cross-embodiment identity continuity',
        summary: 'Let one accountable AI agent move between robot bodies with a verifiable continuity chain, and detect a fork if it is ever in two bodies at once.',
        body: `
An AI agent, a mind with its own Vouch identity, can run on one robot body today and a different body tomorrow. This makes that continuous and accountable.

The problem it closes: as agent minds get decoupled from bodies, there is no cryptographic way to prove that the accountable agent on body B is the same one that was on body A, or to stop the same mind running on two bodies at once.

How it works: \`build_embodiment\` binds the agent to a body and that body's hardware root for a period, signed by the agent's own key. Each embodiment names the body it left (\`fromBody\`), so \`verify_continuity_chain\` walks the links, confirms every one is signed by the same agent key, and returns the current body. \`check_no_fork\` confirms no two embodiments place the agent in different bodies with overlapping active windows. It is the inverse of the ownership custody chain: there one body passes between owners, here one mind passes between bodies.

\`\`\`python
from vouch.robotics import build_embodiment, verify_continuity_chain, check_no_fork

a = build_embodiment(agent, agent_did=agent_did, body_did="body-a", body_hardware_root="uA", valid_seconds=3600)
b = build_embodiment(agent, agent_did=agent_did, body_did="body-b", body_hardware_root="uB", from_body="body-a")
ok, current_body = verify_continuity_chain([a, b], agent_public_key)
no_fork, _ = check_no_fork([a, b])
\`\`\`

Security boundary: the whole chain is signed by one persistent agent key, so a link signed by any other key breaks the continuity, and re-binding to each body's hardware root ties the mind to real hardware at each step. This is the open layer, signed credentials and software verification; managed key custody and fleet migration are commercial.
`,
      },
      {
        id: 'robotics-custody',
        title: 'Physical custody handoff',
        summary: 'Trace a task or object as it passes between human and robot actors, and localize damage to the hop responsible.',
        body: `
A physical task or object passes across a chain of actors, human and robot: a person picks an item, hands it to a robot, that robot hands it to another robot. This makes each handoff accountable.

The problem it closes: when a shared physical workflow crosses people and machines, an incident (a lost tote, a damaged item, a mis-delivery) has no cryptographic way to point at the exact hop and actor responsible.

How it works: \`build_handoff\` records that a receiving actor accepted custody of a task from a releasing actor, signed by the receiver, so the party taking responsibility signs for it. Each receiver becomes the next releaser, so \`verify_handoff_chain\` walks the chain and \`holder_at\` returns who held the task at a given time. A condition attested at each handoff lets \`locate_condition_change\` name the hop where a physical state change happened.

\`\`\`python
from vouch.robotics import build_handoff, verify_handoff_chain, holder_at, locate_condition_change

h1 = build_handoff(robot_a, task_id="tote-42", from_actor=picker_did, to_actor=robot_a_did, condition="intact")
h2 = build_handoff(robot_b, task_id="tote-42", from_actor=robot_a_did, to_actor=robot_b_did, condition="damaged")
ok, current_holder = verify_handoff_chain([h1, h2], {robot_a_did: a_key, robot_b_did: b_key})
change = locate_condition_change([h1, h2])   # responsible holder is robot A
\`\`\`

Security boundary: each handoff is signed by the receiver, so an actor attests its own acceptance of custody, and the chain is only valid when each receiver is the next releaser. This is the open layer of signed credentials and software verification; managed logistics custody orchestration and fleet tracking are commercial.
`,
      },
      {
        id: 'robotics-access',
        title: 'Infrastructure access',
        summary: 'Give a robot bounded, revocable, offline-verifiable access to physical infrastructure like doors, elevators, and chargers.',
        body: `
A robot in a warehouse, hospital, or building needs to open doors, call elevators, dock at chargers, and operate machines. This gives it a bounded, revocable, auditable way to do so.

The problem it closes: physical access today is a shared credential (a badge, a key, a fixed code) that cannot be scoped to one robot, one resource, and one time window, and leaves no attributable record of who did what.

How it works: the operator signs an \`InfrastructureAccessGrant\` with \`build_access_grant\`, naming the resource, the permitted operations, an optional zone, and a time window. The robot signs an \`InfrastructureAccessRequest\` for one operation with \`build_access_request\`. The resource runs \`authorize_access\` offline and allows the operation only when the grant verifies under the operator key and is in window, the request verifies under the robot key, the grant and request name the same robot and resource, and the operation is permitted. \`attenuates_grant\` confirms a sub-grant only narrows what it inherits.

\`\`\`python
from vouch.robotics import build_access_grant, build_access_request, authorize_access

grant = build_access_grant(operator, robot_did=robot_did, resource="door-3", operations=["open", "close"], zone="cell-3", valid_seconds=3600)
request = build_access_request(robot, robot_did=robot_did, resource="door-3", operation="open")
result = authorize_access(grant, request, operator_key, robot_key)   # result.ok is True
\`\`\`

Security boundary: the grant is signed by the operator and the request by the robot, so the pair is a tamper-evident, attributable record and the decision is made offline at the resource. This is the open layer of signed grants and requests, offline authorization, and shrink-only attenuation; hardware-enforced actuation at the resource and managed fleet access-policy orchestration are commercial.
`,
      },
      {
        id: 'robotics-fusion',
        title: 'Fused-sensor provenance',
        summary: 'Bind a robot\'s fused world model to the exact sensor frames that produced it, so a manipulated fusion result or a dropped input is detectable.',
        body: `
A robot rarely acts on a single frame. It fuses camera, lidar, and radar into one world model, an object set, an occupancy grid, or a pose, and acts on that. This binds the fused output to the exact inputs that produced it.

The problem it closes: perception provenance signs individual frames, but the thing a robot acts on is the fusion of many frames. A manipulated fusion result, or a fused output that quietly dropped or swapped an input, has no signed record tying the output back to its true inputs.

How it works: \`build_fused_attestation\` signs a \`FusedPerceptionAttestation\` binding the fused output's hash to the ordered list of input frame hashes, a digest over those inputs, and a fusion method identifier. \`verify_fused_attestation\` checks the proof and reproduces the input digest, so the attestation commits to exactly those inputs and that output. \`verify_fusion_inputs\` checks each named input against the robot's signed perception log and returns any that were never recorded.

\`\`\`python
from vouch.robotics import build_fused_attestation, verify_fused_attestation, verify_fusion_inputs, hash_frame

inputs = [hash_frame(cam), hash_frame(lidar), hash_frame(radar)]
att = build_fused_attestation(robot, robot_did=robot_did, fusion_method="occupancy-grid-v1", input_frame_hashes=inputs, fused_output=world_model)
ok, subject = verify_fused_attestation(att, robot_key, fused_output=world_model)
inputs_ok, missing = verify_fusion_inputs(att, perception_log.entries())
\`\`\`

Security boundary: the robot signs the binding of a fused output to its inputs, and the input digest makes the set of inputs tamper-evident. This is the open layer of software-signed provenance reusing the perception frame hashes; hardware sensor attestation and managed sensor-fusion orchestration are commercial.
`,
      },
      {
        id: 'robotics-wear',
        title: 'Wear and degradation',
        summary: 'A robot signs its own wear over time and automatically narrows its capability envelope as it degrades.',
        body: `
A robot does not stay as capable as it left the factory: actuators wear, joints develop backlash, sensors drift out of calibration, and error rates creep up. This lets a robot attest its own degradation and operate inside a tighter envelope as it ages.

The problem it closes: a robot's physical limits are usually the static caps it shipped with, and there is no signed, verifiable link between how worn a robot is and how much it is still allowed to do.

How it works: \`build_wear_attestation\` signs a \`RobotWearAttestation\` carrying a normalized wear level (0 for as-new, 1 for fully worn) and optional metrics, bound to the robot's identity. Each attestation links to the previous one by its proof, so \`verify_wear_chain\` walks a tamper-evident wear history. \`attenuate_for_wear\` derives a physical scope whose force and speed caps are scaled down by the wear level, and the result is a valid attenuation of the original.

\`\`\`python
from vouch.robotics import build_wear_attestation, verify_wear_chain, attenuate_for_wear

w1 = build_wear_attestation(robot, robot_did=robot_did, wear_level=0.1)
w2 = build_wear_attestation(robot, robot_did=robot_did, wear_level=0.3, prev_proof=w1["proof"]["proofValue"])
ok, latest = verify_wear_chain([w1, w2], robot_key)
narrowed = attenuate_for_wear(full_scope, latest["wearLevel"])   # caps scaled to 0.7 of original
\`\`\`

Security boundary: the robot signs its wear state and derives the narrowed scope credential in software. Firmware-level enforcement of the narrowed envelope and managed predictive-maintenance modeling are commercial.
`,
      },
    ],
  },
  {
    id: 'community',
    title: 'Community',
    description: 'Contribute to the protocol and earn a signed Vouch Verified Contributor credential.',
    articles: [
      {
        id: 'verified-contributor',
        title: 'Become a Vouch Verified Contributor',
        summary: 'Land a merged pull request and receive a real, signed Verified Contributor credential, published to a certificate page and the contributors list.',
        body: `
## What it is

When you land a merged pull request on the [repository](https://github.com/vouch-protocol/vouch), an automated workflow mints a **Vouch Verified Contributor** credential for you. It is a real Verifiable Credential, not a decorative image: the project signs it with its own protocol.

## What you receive

- A certificate page at \`vouch-protocol.com/c/<your-handle>/<pr>\`.
- A listing on the [contributors page](https://vouch-protocol.com/contributors).
- A comment on your pull request with the badge, a copy-paste snippet, and the full credential inline.

## The credential

- Signed with the \`eddsa-jcs-2022\` cryptosuite, the same default format every Vouch SDK produces.
- Issued by \`did:web:vouch-protocol.com:contributors\`, chained back to the project root identity \`did:web:vouch-protocol.com\`.
- The subject is the author of the merged commits, so credit stays correct even when a maintainer relays a contribution for someone else.

## Verify it

Because it is a normal Vouch credential, anyone can verify it with the SDK or the hosted verifier:

\`\`\`python
from vouch import Verifier

is_valid, passport = Verifier.verify_credential(credential, public_key=issuer_public_jwk)
print(is_valid, passport.subject_did)
\`\`\`

## Getting started

New to the project? Pick up a [good first issue](https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). The badge is offered, never required.
`,
      },
    ],
  },
];
