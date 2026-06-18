import Link from 'next/link';
import CodeBlock from '@/components/CodeBlock';
import LangCodeBlock from '@/components/LangCodeBlock';

const FEATURES: Array<{ num: string; title: string; body: string; spec: string; href?: string }> = [
  {
    num: 'i.',
    title: 'Cryptographic Agent Identity',
    body: 'Every agent holds a Decentralized Identifier (did:web or did:key) backed by an Ed25519 keypair. No API keys, no shared secrets, no bearer tokens.',
    spec: '§6 Identity Model',
  },
  {
    num: 'ii.',
    title: 'Intent-bound Credentials',
    body: 'Every action is signed as a Verifiable Credential with Data Integrity proofs. The credential binds identity, action, target, and resource so nothing replays elsewhere.',
    spec: '§5 Credential Format',
  },
  {
    num: 'iii.',
    title: 'Resource-scoped Delegation',
    body: 'Multi-agent systems gain verifiable principal-to-sub-agent chains. Each link narrows the resource scope. No more "the agent did it" black boxes.',
    spec: '§9 Delegation Chains',
  },
  {
    num: 'iv.',
    title: 'Identity Sidecar Pattern',
    body: 'Private keys never enter the LLM context window. A separate Go binary (vouch-sidecar) signs on behalf of the agent over a local IPC channel.',
    spec: '§10 Identity Sidecar',
  },
  {
    num: 'v.',
    title: 'Continuous Trust via Heartbeat',
    body: 'Long-running agents renew SessionVoucher credentials on a periodic schedule. The trust model inverts from "trusted until revoked" to "untrusted until renewed."',
    spec: '§11 Heartbeat Protocol',
  },
  {
    num: 'vi.',
    title: 'Post-Quantum Ready',
    body: 'Attach two Data Integrity proofs to a credential, one Ed25519, one ML-DSA-44, both signing the same JCS bytes. Graceful verifier downgrade with no bespoke composite cryptosuite required.',
    spec: '§13 Crypto-Agility',
  },
  {
    num: 'vii.',
    title: 'Robots & Embodied Agents',
    body: 'A robot identity rooted in a TPM or secure element, a signed record of the model and safety policy it runs (re-signed on every update), physical limits enforced as cryptographic capability (force, speed near humans, zones), a kill-switch credential only an attested authority can trigger, and a scannable QR/NFC passport.',
    spec: 'Robotics profile',
    href: '/robotics/',
  },
  {
    num: 'viii.',
    title: 'Agent Security & Accountability',
    body: 'A lethal-trifecta linter that refuses a capability set holding private data, untrusted input, and an exfiltration vector at once; signed tool descriptors with rug-pull detection; a tamper-evident audit trail; and a budget credential that checks a payment against an AP2 mandate or x402 challenge.',
    spec: 'Shield & Accountability',
  },
  {
    num: 'ix.',
    title: 'Outcome Evidence',
    body: 'A verdict, prediction, or recommendation committed and signed before its outcome is known, then settled by a separate attestation that binds the real result back to it. A salted commitment keeps the call private until settlement, and verification rejects a backdated settlement, so an agent track record cannot be cherry-picked or rewritten after the fact.',
    spec: 'Outcome Evidence',
  },
];

const LANGUAGE_TILES = [
  {
    name: 'Python',
    install: 'pip install vouch-protocol',
    repoPath: 'vouch/',
    note: 'Reference SDK. Signer, verifier, async verifier, KMS, reputation, revocation, cache, rate-limit, metrics, CLI.',
  },
  {
    name: 'TypeScript / Browser',
    install: 'npm install @vouch-protocol-official/core-wasm',
    repoPath: 'core/wasm/',
    note: 'The Rust core compiled to WebAssembly. Runs in browsers and Node.js. The reference TypeScript SDK also ships for Node.',
  },
  {
    name: 'Go',
    install: 'go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar',
    repoPath: 'go-sidecar/',
    note: 'Long-running daemon for the Identity Sidecar pattern. HTTP /sign endpoint, ed25519 and hybrid signing.',
  },
  {
    name: 'Swift (iOS / macOS)',
    install: 'add VouchCore via Swift Package Manager',
    repoPath: 'sdks/swift/',
    note: 'Over the core via UniFFI, packaged as an XCFramework.',
  },
  {
    name: 'JVM (Java / Kotlin)',
    install: 'com.vouchprotocol:vouch-core',
    repoPath: 'sdks/jvm/',
    note: 'Gradle module. A plain Java class, plus the generated Kotlin binding.',
  },
  {
    name: '.NET',
    install: 'dotnet add package VouchProtocol.Core',
    repoPath: 'sdks/dotnet/',
    note: 'Over the C ABI via P/Invoke. NuGet package.',
  },
  {
    name: 'C / C++',
    install: 'header + prebuilt library',
    repoPath: 'sdks/cpp/',
    note: 'The C bindings shipped with the core, with a Makefile and CMake example.',
  },
];

const AI_ASSISTANTS = [
  {
    name: 'Claude Skill',
    note: 'A retrieval-grounded assistant that knows the specification, the SDKs, the conformance levels, and the compliance mappings. Runs on your own Claude subscription.',
  },
  {
    name: 'OpenAI Custom GPT',
    note: 'The same knowledge as a Custom GPT, for ChatGPT users.',
  },
  {
    name: 'Gemini Gem',
    note: 'The same knowledge as a Gemini Gem.',
  },
];

const STANDARDS = [
  { label: 'Verifiable Credentials 2.0', href: 'https://www.w3.org/TR/vc-data-model-2.0/' },
  { label: 'Data Integrity', href: 'https://www.w3.org/TR/vc-data-integrity/' },
  { label: 'DIDs', href: 'https://www.w3.org/TR/did-core/' },
  { label: 'Controlled Identifiers (Multikey)', href: 'https://www.w3.org/TR/controlled-identifiers/' },
  { label: 'BitstringStatusList', href: 'https://www.w3.org/TR/vc-bitstring-status-list/' },
  { label: 'RFC 8785 (JCS)', href: 'https://datatracker.ietf.org/doc/html/rfc8785' },
  { label: 'NIST FIPS 204 (ML-DSA)', href: 'https://csrc.nist.gov/pubs/fips/204/final' },
  { label: 'C2PA', href: 'https://c2pa.org' },
];

export default function HomePage() {
  return (
    <>
      {/* Hero */}
      <section className="border-b border-rule">
        <div className="container-wide py-20 md:py-28">
          <div className="eyebrow mb-6">SDKs on every platform &middot; standards-aligned</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.05] tracking-tight mb-6 max-w-[920px] text-[clamp(2.5rem,5.2vw,4rem)]">
            Cryptographic identity &amp; accountability for autonomous AI agents.
          </h1>
          <p className="drop-cap text-[1.2rem] leading-snug text-ink-soft max-w-prose mb-8">
            The Vouch Protocol is an open standard specification for establishing continuous state
            verifiability of autonomous AI agents, a layer that sits beneath, and complements, agent
            identity and delegation specifications. Built on Verifiable Credentials, Data Integrity
            proofs, and Decentralized Identifiers, with one byte-exact core and SDKs for every major
            platform: web, mobile, JVM, .NET, and native, plus the Python, TypeScript, and Go references.
          </p>
          <div className="flex flex-wrap gap-3 items-center">
            <Link href="/faq/" className="btn-primary">Read the FAQ</Link>
            <Link href="/help/" className="btn-secondary">Browse guides</Link>
            <a
              href="https://github.com/vouch-protocol/vouch"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary"
            >
              View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* What the protocol provides */}
      <section className="border-b border-rule">
        <div className="container-wide py-20">
          <div className="section-heading">
            <span className="num">§ I</span>
            <h2>What the protocol provides</h2>
          </div>
          <p className="text-ink-soft max-w-prose mb-12 leading-relaxed">
            Capabilities that traditional API keys, OAuth tokens, and bearer credentials cannot provide
            for autonomous AI agents operating in regulated environments, now reaching from software
            agents to robots.
          </p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-10">
            {FEATURES.map((feature) => (
              <div key={feature.title} className="feature-card">
                <div className="eyebrow-faint mb-2">{feature.num}</div>
                <h3 className="font-serif font-semibold text-[1.25rem] mb-3 tracking-tight">{feature.title}</h3>
                <p className="text-ink-soft text-[0.95rem] leading-relaxed mb-3">{feature.body}</p>
                {feature.href ? (
                  <Link href={feature.href} className="font-mono text-burgundy text-[0.7rem] tracking-wider no-underline hover:underline">
                    {feature.spec} &rarr;
                  </Link>
                ) : (
                  <span className="font-mono text-burgundy text-[0.7rem] tracking-wider">{feature.spec}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* One core, every platform */}
      <section className="border-b border-rule">
        <div className="container-wide py-20">
          <div className="section-heading">
            <span className="num">§ II</span>
            <h2>One core, every platform</h2>
          </div>
          <p className="text-ink-soft max-w-prose mb-12 leading-relaxed">
            One canonical Rust core does the cryptography once. Every SDK is a thin wrapper over it, so a
            credential signed on any platform verifies on every other, byte for byte (RFC 8785 JCS
            canonicalization). They all pass the same shared test vectors at <code>test-vectors/</code>.
          </p>
          <div className="grid md:grid-cols-3 gap-6">
            {LANGUAGE_TILES.map((lang) => (
              <div key={lang.name} className="border border-rule p-6">
                <h3 className="font-serif font-semibold text-[1.2rem] mb-3">{lang.name}</h3>
                <CodeBlock code={lang.install} className="text-[0.75rem] mb-3" />
                <p className="text-ink-soft text-[0.9rem] leading-relaxed mb-3">{lang.note}</p>
                <code className="font-mono text-burgundy text-[0.75rem] !bg-transparent !border-0 !p-0">{lang.repoPath}</code>
              </div>
            ))}
          </div>

          <div className="section-heading mt-20">
            <span className="num">§ II.b</span>
            <h2>An assistant that knows the protocol</h2>
          </div>
          <p className="text-ink-soft max-w-prose mb-12 leading-relaxed">
            The same specification, SDKs, and compliance mappings, packaged as a retrieval-grounded
            assistant for the tool you already use. It answers from the actual docs, not a guess.
          </p>
          <div className="grid md:grid-cols-3 gap-6">
            {AI_ASSISTANTS.map((a) => (
              <div key={a.name} className="border border-rule p-6">
                <h3 className="font-serif font-semibold text-[1.2rem] mb-3">{a.name}</h3>
                <p className="text-ink-soft text-[0.9rem] leading-relaxed">{a.note}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Standards */}
      <section className="border-b border-rule">
        <div className="container-wide py-20">
          <div className="section-heading">
            <span className="num">§ III</span>
            <h2>Built on open standards</h2>
          </div>
          <p className="text-ink-soft max-w-prose mb-10 leading-relaxed">
            Vouch builds on existing widely-adopted open standards. No new cryptographic primitives are
            introduced where existing standards suffice.
          </p>
          <div className="flex flex-wrap gap-2">
            {STANDARDS.map((standard) => (
              <a
                key={standard.label}
                href={standard.href}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-[0.7rem] tracking-wider px-3 py-1.5 border border-rule hover:border-burgundy hover:text-burgundy text-ink-soft no-underline transition-colors"
              >
                {standard.label}
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* Quick taste */}
      <section className="border-b border-rule">
        <div className="container-wide py-20">
          <div className="section-heading">
            <span className="num">§ IV</span>
            <h2>A quick taste</h2>
          </div>
          <p className="text-ink-soft max-w-prose mb-8 leading-relaxed">
            Sign a Vouch Credential and read back its proof. The same credential verifies
            byte-identically across every SDK, so pick your language.
          </p>
          <LangCodeBlock
            variants={[
              {
                label: 'Python',
                language: 'python',
                code: `from vouch import Signer, build_vouch_credential

signer = Signer.from_did("did:web:agent.example.com")

credential = build_vouch_credential(
  subject_did="did:web:agent.example.com",
  intent={
    "action": "submit_claim",
    "target": "claim:HC-001",
    "resource": "https://insurance.example.com/claims/HC-001",
  },
  reputation_score=92,
  valid_seconds=300,
)

signed = signer.sign_credential(credential)
print(signed["proof"]["proofValue"])  # z-base58-encoded Ed25519 signature
`,
              },
              {
                label: 'TypeScript',
                language: 'typescript',
                code: `import { Signer, generateIdentity, buildVouchCredential }
  from '@vouch-protocol-official/sdk';

const identity = await generateIdentity('agent.example.com');
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
console.log(signed.proof.proofValue); // z-base58-encoded Ed25519 signature
`,
              },
              {
                label: 'Go',
                language: 'go',
                code: `// The Go sidecar holds the key and signs over localhost HTTP,
// so the signing key never enters your agent's process.
// Start it with: vouch-sidecar --did did:web:agent.example.com --port 8877
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	body, _ := json.Marshal(map[string]any{
		"subjectDid": "did:web:agent.example.com",
		"intent": map[string]string{
			"action":   "submit_claim",
			"target":   "claim:HC-001",
			"resource": "https://insurance.example.com/claims/HC-001",
		},
		"validSeconds": 300,
	})

	resp, _ := http.Post("http://localhost:8877/sign",
		"application/json", bytes.NewReader(body))
	defer resp.Body.Close()

	var signed map[string]any
	json.NewDecoder(resp.Body).Decode(&signed)
	fmt.Println(signed["proof"].(map[string]any)["proofValue"])
}
`,
              },
              {
                label: 'Swift',
                language: 'swift',
                code: `import VouchCore

// VouchCore wraps the one Rust core via UniFFI, so a credential
// verified on iOS matches the exact bytes from every other SDK.
let keys = try Vouch.generateEd25519()
let signed = try Vouch.signCredential(credentialJson, keys: keys)

let result = try Vouch.verifyCredential(
  signed, publicKey: keys.publicKey, now: "2026-04-26T10:02:00Z")
print(result)
`,
              },
              {
                label: 'Java',
                language: 'java',
                code: `import com.vouchprotocol.core.Vouch;

String kp = Vouch.generateEd25519();   // {seed_b64, public_b64, multikey, did_key}
String signed = Vouch.signCredential(
    credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
boolean ok = Vouch.verifyProof(signed, publicB64);
`,
              },
              {
                label: 'C#',
                language: 'csharp',
                code: `using VouchProtocol.Core;

string kp = Vouch.GenerateEd25519();
string signed = Vouch.SignCredential(
    credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
bool ok = Vouch.VerifyProof(signed, publicB64);
`,
              },
              {
                label: 'C',
                language: 'c',
                code: `#include "vouch_core.h"

// Returned strings are heap-allocated; free with vouch_string_free.
char *err = NULL;
char *res = vouch_verify_proof(signed_credential_json, public_key_b64, &err); // "true"/"false"
if (res) vouch_string_free(res); else vouch_string_free(err);
`,
              },
              {
                label: 'WASM',
                language: 'javascript',
                code: `import init, * as core from '@vouch-protocol-official/core-wasm';
await init(); // fetches the .wasm next to the module

const kp = JSON.parse(core.generateEd25519());
const signed = core.signCredential(JSON.stringify(credential),
  kp.seed_b64, kp.did_key + '#key-1', '2026-04-26T10:00:00Z');
const ok = core.verifyProof(signed, kp.public_b64);   // true
`,
              },
            ]}
          />
          <div className="mt-7 flex flex-col sm:flex-row sm:items-baseline gap-x-6 gap-y-3">
            <span className="eyebrow text-burgundy shrink-0">Quickstarts</span>
            <div className="flex flex-wrap gap-x-5 gap-y-2">
              {[
                { href: '/help/#quickstart-python', label: 'Python' },
                { href: '/help/#quickstart-typescript', label: 'TypeScript' },
                { href: '/help/#quickstart-go', label: 'Go' },
                { href: '/help/#quickstart-swift', label: 'Swift' },
                { href: '/help/#quickstart-jvm', label: 'Java / Kotlin' },
                { href: '/help/#quickstart-dotnet', label: '.NET' },
                { href: '/help/#quickstart-c', label: 'C / C++' },
                { href: '/help/#quickstart-wasm', label: 'WebAssembly' },
              ].map((q) => (
                <Link
                  key={q.href}
                  href={q.href}
                  className="font-mono uppercase text-[0.7rem] tracking-[0.14em] no-underline border-b border-transparent pb-0.5 text-ink-soft hover:text-burgundy hover:border-burgundy transition-colors"
                >
                  {q.label}
                </Link>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section>
        <div className="container-wide py-20">
          <div className="border border-rule p-10 md:p-14 text-center">
            <h2 className="font-serif font-semibold text-[1.85rem] md:text-[2.25rem] mb-4 tracking-tight">
              Building an agent that must be accountable?
            </h2>
            <p className="text-ink-soft max-w-prose mx-auto mb-8 leading-relaxed">
              Start with the FAQ for concept clarity, jump into Help for hands-on quickstarts and
              deployment guides, or open an issue if you have a specific question.
            </p>
            <div className="flex flex-wrap gap-3 justify-center">
              <Link href="/faq/" className="btn-primary">Read the FAQ</Link>
              <Link href="/help/" className="btn-secondary">Browse guides</Link>
              <a
                href="https://discord.gg/mMqx5cG9Y"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-secondary"
              >
                Join Discord
              </a>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
