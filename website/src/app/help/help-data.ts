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
pip install vouch-protocol
\`\`\`

The hybrid post-quantum profile (\`hybrid-eddsa-mldsa44-jcs-2026\`) is bundled by default; nothing else to install.

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
from vouch import build_vouch_credential

credential = build_vouch_credential(
    subject_did=identity.did,
    intent={
        "action": "submit_claim",
        "target": "claim:HC-001",
        "resource": "https://insurance.example.com/claims/HC-001",
    },
    valid_seconds=300,
)

signed = signer.sign_credential(credential)
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
result = asyncio.run(verifier.verify_credential(signed))
print(result.valid, result.reasons)
\`\`\`

For the hybrid post-quantum profile, swap \`sign_credential\` for \`sign_credential_hybrid\`. The required \`pqcrypto\` library is already bundled with \`vouch-protocol\`, so nothing else to install. Everything else stays the same.

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
  buildVouchCredential,
} from '@vouch-protocol-official/sdk';

async function main() {
  // Generate an in-memory identity. The "domain" string is just a label
  // inside the DID; nothing is published anywhere yet.
  const identity = await generateIdentity('localhost');

  const signer = new Signer({
    privateKey: identity.privateKeyJwk,
    did: identity.did!,
  });

  const credential = buildVouchCredential({
    subjectDid: identity.did!,
    intent: {
      action: 'submit_claim',
      target: 'claim:HC-001',
      resource: 'https://insurance.example.com/claims/HC-001',
    },
    validSeconds: 300,
  });

  const signed = await signer.signCredential(credential);
  console.log('signed proof value:', signed.proof.proofValue);

  // trustedRoots is the local-dev escape hatch: in production the verifier
  // fetches did.json from the issuer's domain instead.
  const verifier = new Verifier({
    trustedRoots: { [identity.did!]: identity.publicKeyJwk },
    allowDidResolution: false,
  });
  const result = await verifier.verifyCredential(signed);
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
const result = await verifier.verifyCredential(signed);
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

VouchCore ships through Swift Package Manager. The native code is a prebuilt XCFramework hosted on the \`swift-v0.1.0\` release, so you do not need a Mac toolchain to build the Rust core yourself.

In Xcode use File then Add Package Dependencies and paste the repo URL, or add it to your \`Package.swift\`:

\`\`\`swift
.package(url: "https://github.com/vouch-protocol/vouch", from: "swift-v0.1.0"),
// then depend on the product:
.product(name: "VouchCore", package: "vouch"),
\`\`\`

Supports iOS 13+ and macOS 12+.

## Canonicalize and verify

Everything runs on device. The \`Vouch\` facade gathers the lower-level UniFFI functions behind a discoverable surface:

\`\`\`swift
import VouchCore

// RFC 8785 (JCS) canonicalization. Byte-identical to every other Vouch SDK.
let canon = try Vouch.canonicalize(#"{"b":1,"a":2}"#)   // {"a":2,"b":1}

// Verify a Data Integrity proof (eddsa-jcs-2022) on a signed credential.
let ok = try Vouch.verifyProof(signedCredentialJson, publicKey: publicKey)

// Proof plus validity window in one call.
let result = try Vouch.verifyCredential(signedCredentialJson, publicKey: publicKey, now: "2026-04-26T10:02:00Z")
\`\`\`

\`Vouch.generateEd25519()\` returns a key pair and \`Vouch.signCredential(...)\` attaches the proof. VouchCore is a thin layer over the canonical Rust core via UniFFI, so a credential verified on iOS matches the exact bytes from every other SDK.
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
String signed = Vouch.signCredential(credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
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
string signed = Vouch.SignCredential(credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
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

The header also exposes \`vouch_sign_credential\`, \`vouch_verify_credential\`, delegation, dual-proof ML-DSA-44 verify, and BitstringStatusList revocation. A credential verified from C matches the exact bytes of every other SDK.
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
const signed = core.signCredential(JSON.stringify(myCredential), kp.seed_b64, kp.did_key + '#key-1', '2026-04-26T10:00:00Z');
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
from vouch import Signer

signer = Signer.from_did_with_hybrid("did:web:agent.example.com")
signed = signer.sign_credential_hybrid(credential)
\`\`\`

TypeScript:

\`\`\`ts
import { Signer } from '@vouch-protocol-official/sdk';

const signer = await Signer.fromDidWithHybrid('did:web:agent.example.com');
const signed = await signer.signCredentialHybrid(credential);
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

## Three rules

1. Each link is a signed Vouch credential where the **issuer** is the **subject** of the previous link.
2. Each link's \`resource\` MUST be a subset of the previous link's. You cannot delegate authority you do not have.
3. The chain must terminate at a principal (typically a human, or a system root).

## Build a chain in Python

\`\`\`python
from vouch import Signer, build_vouch_credential

principal = Signer.from_did("did:web:principal.example.com")
agent = Signer.from_did("did:web:agent.example.com")
sub_agent = Signer.from_did("did:web:sub-agent.example.com")

# Principal delegates to agent
principal_link = principal.sign_credential(build_vouch_credential(
  subject_did=agent.did,
  intent={"action": "*", "target": "*", "resource": "https://insurance.example.com/claims/*"},
  valid_seconds=3600,
))

# Agent narrows and delegates to sub-agent
agent_link = agent.sign_credential(build_vouch_credential(
  subject_did=sub_agent.did,
  intent={"action": "read", "target": "claim:HC-001", "resource": "https://insurance.example.com/claims/HC-001"},
  valid_seconds=300,
  delegated_from=[principal_link],
))

# Sub-agent signs its actual action
action = sub_agent.sign_credential(build_vouch_credential(
  subject_did=sub_agent.did,
  intent={"action": "read", "target": "claim:HC-001", "resource": "https://insurance.example.com/claims/HC-001"},
  valid_seconds=60,
  delegated_from=[principal_link, agent_link],
))
\`\`\`

## Verify

\`\`\`python
from vouch import Verifier
verifier = Verifier()
result = await verifier.verify_delegation_chain([principal_link, agent_link, action])
\`\`\`

The verifier walks every link, validates each signature, and confirms resource narrowing.
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
  build_vouch_credential,
)

# Load or create the status list. Persisted state survives restarts.
store = FilesystemStatusListStore("/var/lib/vouch/status-1.json")
try:
  status_list = store.load()
except FileNotFoundError:
  status_list = StatusList(status_list_id="https://issuer.example/status/1")

signer = Signer.from_did("did:web:issuer.example")

# ---- Issue a credential with a credentialStatus entry ----
index = status_list.allocate_index()
store.save(status_list) # persist the new cursor

credential = build_vouch_credential(
  issuer_did="did:web:issuer.example",
  intent={"action": "submit_claim", "target": "claim:HC-001",
      "resource": "https://insurance.example/claims/HC-001"},
  credential_status=build_status_list_entry(
    status_list_credential="https://issuer.example/status/1",
    status_list_index=index,
  ),
)
signed_credential = signer.sign_credential(credential)

# ---- Later, revoke that credential ----
status_list.revoke(index)
store.save(status_list)

# Re-sign and republish the status list credential at its stable URL.
status_credential = build_status_list_credential(
  issuer_did="did:web:issuer.example",
  status_list=status_list,
)
signed_status_credential = signer.sign_credential(status_credential)
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

// Pass via SignCredentialOptions.CredentialStatus to Signer.SignCredential.
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
        summary: 'Ready-made integrations for LangChain, CrewAI, AutoGPT, AutoGen, MCP, Vertex AI, and more.',
        body: `
## Python integrations

All under \`vouch/integrations/\`:

| Framework | File | What it does |
|---|---|---|
| LangChain | \`langchain/tool.py\` | Wraps a LangChain Tool so its inputs are signed before execution |
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

End-to-end examples are at [examples/05_integrations/](https://github.com/vouch-protocol/vouch/tree/main/examples/05_integrations).

## Companion products

These are separate products that build on Vouch, not part of the protocol itself. Vouch does not require them, and they keep their own repositories and docs. Each consumes or produces Vouch credentials at a different point in the stack.

- **Vouch Shield** ([vouch-protocol/vouch-shield](https://github.com/vouch-protocol/vouch-shield)) a runtime middleware that intercepts tool calls and enforces signature verification, allow-list, capability permissions, and audit logging. The enforcement layer that consumes Vouch credentials at execution time.
- **Amnesia** an egress-control product. An optional, one-directional bridge wraps an Amnesia egress decision in a Verifiable Credential, so the decision becomes a replayable, verifiable audit artifact. The bridge ships at \`vouch/integrations/amnesia.py\` (Python) and \`packages/sdk-ts/src/integrations/amnesia.ts\` (TypeScript).

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
  // STATE VERIFIABILITY RUNTIME (concrete quickstart, not just concepts)
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

The validator checks schema, behavioral digest structure, canary chain integrity, and interval-index monotonicity. A broken canary chain or stale interval index returns a structured rejection — the agent does not get a new voucher and its existing one expires.

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
  // AI ASSISTANTS — walkthroughs for each surface
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

Linux / macOS / WSL:

\`\`\`bash
git clone https://github.com/vouch-protocol/vouch
cp -r vouch/claude-skill/skills/vouch-protocol ~/.claude/skills/vouch-protocol
\`\`\`

Windows PowerShell:

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

### 1. Dev sidecar (ephemeral Ed25519 key — dev only)

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

- \`GET /health\` — liveness probe
- \`GET /did\` — the sidecar's DID
- \`GET /.well-known/did.json\` — DID Document (optional)
- \`POST /sign\` — sign an intent, return a Vouch credential

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
];
