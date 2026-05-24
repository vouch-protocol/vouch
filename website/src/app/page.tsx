import Link from 'next/link';
import CodeBlock from '@/components/CodeBlock';

const FEATURES = [
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
];

const LANGUAGE_TILES = [
  {
    name: 'Python',
    install: 'pip install vouch-protocol',
    repoPath: 'vouch/',
    note: 'Reference SDK. Signer, verifier, async verifier, KMS, reputation, revocation, cache, rate-limit, metrics, CLI.',
  },
  {
    name: 'TypeScript',
    install: 'npm install vouch-protocol',
    repoPath: 'packages/sdk-ts/',
    note: 'Browser and Node. Signer, verifier, JCS, hybrid PQ, vouch-client for sidecar RPC.',
  },
  {
    name: 'Go',
    install: 'go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar',
    repoPath: 'go-sidecar/',
    note: 'Long-running daemon for the Identity Sidecar pattern. HTTP /sign endpoint, ed25519 and hybrid signing.',
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
          <div className="eyebrow mb-6">v1.6.0 shipped &middot; standards-aligned</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.05] tracking-tight mb-6 max-w-[920px] text-[clamp(2.5rem,5.2vw,4rem)]">
            Cryptographic identity &amp; accountability for autonomous AI agents.
          </h1>
          <p className="drop-cap text-[1.2rem] leading-snug text-ink-soft max-w-prose mb-8">
            The Vouch Protocol is an open standard specification for establishing continuous state
            verifiability of autonomous AI agents, a layer that sits beneath, and complements, agent
            identity and delegation specifications. Built on Verifiable Credentials, Data Integrity
            proofs, and Decentralized Identifiers, with reference implementations in Python, TypeScript,
            and Go.
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
            Six properties that traditional API keys, OAuth tokens, and bearer credentials cannot provide
            for autonomous AI agents operating in regulated environments.
          </p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-10">
            {FEATURES.map((feature) => (
              <div key={feature.title} className="feature-card">
                <div className="eyebrow-faint mb-2">{feature.num}</div>
                <h3 className="font-serif font-semibold text-[1.25rem] mb-3 tracking-tight">{feature.title}</h3>
                <p className="text-ink-soft text-[0.95rem] leading-relaxed mb-3">{feature.body}</p>
                <span className="font-mono text-burgundy text-[0.7rem] tracking-wider">{feature.spec}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Three language SDKs */}
      <section className="border-b border-rule">
        <div className="container-wide py-20">
          <div className="section-heading">
            <span className="num">§ II</span>
            <h2>Three language SDKs, one wire format</h2>
          </div>
          <p className="text-ink-soft max-w-prose mb-12 leading-relaxed">
            Every credential signed by any implementation is byte-identical (RFC 8785 JCS canonicalization)
            and cross-verifiable. Test vectors published at <code>test-vectors/hybrid-eddsa-mldsa44/</code>.
          </p>
          <div className="grid md:grid-cols-3 gap-6">
            {LANGUAGE_TILES.map((lang) => (
              <div key={lang.name} className="border border-rule p-6">
                <h3 className="font-serif font-semibold text-[1.2rem] mb-3">{lang.name}</h3>
                <CodeBlock code={lang.install} className="!p-3 text-[0.75rem] mb-3" />
                <p className="text-ink-soft text-[0.9rem] leading-relaxed mb-3">{lang.note}</p>
                <code className="font-mono text-burgundy text-[0.75rem] !bg-transparent !border-0 !p-0">{lang.repoPath}</code>
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
            Sign a Vouch Credential in Python. The same credential is verifiable in TypeScript and Go.
          </p>
          <CodeBlock
            language="python"
            code={`from vouch import Signer, build_vouch_credential

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
`}
          />
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/help/#quickstart-python" className="btn-primary">Full Python quickstart</Link>
            <Link href="/help/#quickstart-typescript" className="btn-secondary">TypeScript quickstart</Link>
            <Link href="/help/#quickstart-go" className="btn-secondary">Go sidecar quickstart</Link>
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
