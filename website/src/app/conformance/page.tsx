import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Conformance Levels — Vouch Protocol',
    description:
        'Three deployment tiers for Vouch Protocol: L1 (credential), L2 (sidecar + delegation + revocation), L3 (state verifiable + post-quantum).',
};

type Level = {
    id: 'L1' | 'L2' | 'L3';
    name: string;
    tagline: string;
    targetUser: string;
    must: string[];
    omits: string[];
    accent: string;
};

const LEVELS: Level[] = [
    {
        id: 'L1',
        name: 'Credential',
        tagline: 'Ad hoc agent-action attestation.',
        targetUser:
            'Single agents signing occasional actions. No long-running runtime. No structural capability bounds required.',
        must: [
            'Issue and verify Vouch Credentials',
            'Sign with the eddsa-jcs-2022 cryptosuite (Ed25519 over RFC 8785 JCS)',
            'Resolve issuer DIDs (did:web, did:key at minimum)',
            'Enforce credential validity windows',
            'Enforce nonce-based replay resistance',
        ],
        omits: ['Delegation chains', 'Sidecar pattern', 'Status-list revocation', 'State Verifiability'],
        accent: 'parchment-warm',
    },
    {
        id: 'L2',
        name: 'Structural-Security',
        tagline: 'Sidecar + delegation + revocation.',
        targetUser:
            'Production deployments with LLM-driven agents. Capability bounds and revocation are required.',
        must: [
            'Everything from L1',
            'Identity Sidecar pattern: signing key isolated from the LLM, intent allow-list enforced before signing',
            'Delegation chains with the resource-narrowing rule and the five-link depth bound',
            'BitstringStatusList revocation with configurable polling',
            'Structured rejection codes for sidecar refusals',
        ],
        omits: ['Dual-proof post-quantum profile', 'Heartbeat Protocol', 'Validator quorum'],
        accent: 'parchment-deep',
    },
    {
        id: 'L3',
        name: 'State Verifiable + PQ',
        tagline: 'The full protocol.',
        targetUser:
            'Long-running agents in regulated or adversarial environments. High-stakes actions (financial transfers, regulated submissions, clinical records, production deployments).',
        must: [
            'Everything from L2',
            'Dual-proof post-quantum cryptosuite (eddsa-jcs-2022 + mldsa44-jcs-2026)',
            'Heartbeat Protocol with configurable renewal interval',
            'Trust entropy decay against per-action thresholds',
            'Behavioural attestation digests + canary commit/reveal chains',
            'M-of-N validator quorum, with role-specialised validators (policy, behaviour, budget)',
        ],
        omits: [],
        accent: 'parchment',
    },
];

export default function ConformancePage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="max-w-prose-wide mx-auto px-6 py-16 md:py-24">
                <header className="mb-12">
                    <p className="eyebrow text-burgundy mb-3">Specification §17</p>
                    <h1 className="font-serif text-[2.2rem] md:text-[2.8rem] leading-tight tracking-tight mb-4">
                        Three deployment tiers,<br />one protocol
                    </h1>
                    <p className="font-serif italic text-ink-soft text-[1.1rem] max-w-prose leading-relaxed">
                        Vouch Protocol&trade; conforms at one of three levels. Higher levels are
                        strict supersets of lower levels. Deployments declare the level they target;
                        verifiers expect at least that level&apos;s guarantees.
                    </p>
                </header>

                <section className="space-y-12">
                    {LEVELS.map((lvl) => (
                        <article key={lvl.id} className={`bg-${lvl.accent} border border-rule p-8 md:p-10`}>
                            <header className="flex items-baseline gap-4 mb-3 border-b border-rule-light pb-4">
                                <span className="font-mono uppercase tracking-[0.18em] text-burgundy text-[0.75rem]">
                                    Level {lvl.id.slice(1)}
                                </span>
                                <h2 className="font-serif text-[1.5rem] md:text-[1.7rem] font-semibold tracking-tight">
                                    {lvl.name}
                                </h2>
                            </header>
                            <p className="font-serif italic text-ink-soft text-[1.05rem] mb-6">{lvl.tagline}</p>

                            <h3 className="eyebrow mb-2">Target deployment</h3>
                            <p className="mb-6 text-ink leading-relaxed">{lvl.targetUser}</p>

                            <h3 className="eyebrow mb-2">A conforming {lvl.id} implementation MUST</h3>
                            <ul className="list-disc list-outside pl-5 space-y-1.5 mb-6 marker:text-burgundy">
                                {lvl.must.map((m) => (
                                    <li key={m} className="text-ink leading-relaxed">{m}</li>
                                ))}
                            </ul>

                            {lvl.omits.length > 0 && (
                                <>
                                    <h3 className="eyebrow mb-2">MAY omit</h3>
                                    <ul className="list-disc list-outside pl-5 space-y-1 marker:text-ink-faint">
                                        {lvl.omits.map((o) => (
                                            <li key={o} className="text-ink-faint italic leading-relaxed">{o}</li>
                                        ))}
                                    </ul>
                                </>
                            )}
                        </article>
                    ))}
                </section>

                <section className="mt-16 border-t border-rule pt-12">
                    <h2 className="font-serif text-[1.5rem] font-semibold mb-4">Which tier is right for me?</h2>
                    <div className="space-y-4 text-ink leading-relaxed max-w-prose">
                        <p>
                            <strong className="font-semibold">Just signing a few actions, no LLM runtime?</strong> L1 is enough.
                            You get a verifiable credential per action.
                        </p>
                        <p>
                            <strong className="font-semibold">Running an LLM agent in production?</strong> L2. The Sidecar pattern
                            is the security primitive that bounds a prompt-injected LLM. Without it, a compromised LLM context
                            can sign arbitrary intents.
                        </p>
                        <p>
                            <strong className="font-semibold">Regulated industry, long-running agents, or post-quantum mandate?</strong> L3.
                            The Heartbeat layer makes silent compromise observable. The dual-proof PQ profile is the migration
                            path off Ed25519 without breaking existing verifiers.
                        </p>
                    </div>
                </section>

                <section className="mt-12">
                    <h2 className="font-serif text-[1.5rem] font-semibold mb-3">Conformance declaration</h2>
                    <p className="text-ink leading-relaxed mb-4">
                        Deployments SHOULD publish a machine-readable conformance declaration at a stable URL:
                    </p>
                    <pre className="font-mono text-[0.82rem] leading-relaxed">
{`{
  "@context": ["https://vouch-protocol.com/contexts/conformance/v1"],
  "type": "VouchConformanceDeclaration",
  "deployment": "did:web:example.com",
  "level": "L2",
  "implementations": ["vouch-python==1.0.0", "go-sidecar==1.0.0"],
  "validated": "2026-05-18T00:00:00Z",
  "testVectorsPassing": ["jcs", "eddsa-jcs-2022", "bitstring-status-list",
                         "delegation-chain", "sidecar-contract"]
}`}
                    </pre>
                </section>

                <footer className="mt-16 border-t border-rule pt-8 flex flex-col md:flex-row gap-4 md:justify-between text-[0.92rem]">
                    <Link
                        href="https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md#17-conformance-levels"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink border-b border-ink no-underline hover:bg-ink hover:text-parchment px-1 py-0.5 transition-colors w-fit"
                    >
                        Full specification (§17) →
                    </Link>
                    <Link
                        href="/compliance"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink-soft border-b border-rule no-underline hover:text-ink px-1 py-0.5 transition-colors w-fit"
                    >
                        Regulatory compliance mapping →
                    </Link>
                </footer>
            </div>
        </main>
    );
}
