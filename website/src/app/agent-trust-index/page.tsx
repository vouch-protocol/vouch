import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Agent Trust Index - Vouch Protocol',
    description:
        'An open benchmark of how many autonomous agents can prove who they are. The first sweep checked 11,168 public agents from the Model Context Protocol registry. 98.7% cannot present a verifiable identity.',
};

const HEADLINE = [
    {
        stat: '98.7%',
        label: 'of the 11,168 agents checked cannot present an identity anyone can verify.',
    },
    {
        stat: '1.34%',
        label: 'can prove who they are with a resolvable did:web identity. That is 150 agents.',
    },
    {
        stat: '0',
        label: 'agents are post-quantum ready. Not one carries an ML-DSA key.',
    },
];

const PROPERTIES = [
    { name: 'Can prove who they are (resolvable did:web identity)', count: '150', share: '1.34%' },
    { name: 'Agent card references a key or signature', count: '98', share: '0.88%' },
    { name: 'Publishes a service endpoint (revocation, MCP, A2A)', count: '72', share: '0.64%' },
    { name: 'Post-quantum ready (an ML-DSA key)', count: '0', share: '0.00%' },
];

export default function AgentTrustIndexPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="container-wide py-20 md:py-28">
                <p className="eyebrow text-burgundy mb-3">For the ecosystem</p>
                <h1 className="font-serif font-semibold text-[clamp(2.2rem,5vw,3.6rem)] leading-[1.05] tracking-tight mb-6 max-w-[900px]">
                    The Agent Trust Index
                </h1>
                <p className="drop-cap text-[1.2rem] leading-snug text-ink-soft max-w-prose mb-4">
                    An open benchmark of how trustworthy the agent world actually is. It checks one
                    simple thing for each public agent: can it cryptographically prove who it is, on
                    whose authority it acts, and that it has not been tampered with?
                </p>
                <p className="text-ink-soft max-w-prose mb-12">
                    The first sweep checked <strong>11,168 unique agents</strong> from the public Model
                    Context Protocol registry on <strong>7 June 2026</strong>. The answer is
                    uncomfortable.
                </p>

                <div className="grid sm:grid-cols-3 gap-8 max-w-3xl mb-16">
                    {HEADLINE.map((f) => (
                        <div key={f.label} className="border-l-2 border-burgundy pl-4">
                            <div className="font-serif font-semibold text-[2.2rem] tracking-tight mb-1">{f.stat}</div>
                            <p className="text-ink-soft text-[0.95rem] leading-relaxed">{f.label}</p>
                        </div>
                    ))}
                </div>

                <h2 className="font-serif font-semibold text-[1.5rem] tracking-tight mb-5">What the first sweep found</h2>
                <div className="border border-rule max-w-2xl mb-4 overflow-hidden">
                    <table className="w-full text-[0.95rem]">
                        <thead>
                            <tr className="border-b border-rule bg-parchment-warm">
                                <th className="text-left font-mono uppercase text-[0.65rem] tracking-[0.14em] text-ink-soft p-3">Trust property</th>
                                <th className="text-right font-mono uppercase text-[0.65rem] tracking-[0.14em] text-ink-soft p-3">Agents</th>
                                <th className="text-right font-mono uppercase text-[0.65rem] tracking-[0.14em] text-ink-soft p-3">Share</th>
                            </tr>
                        </thead>
                        <tbody>
                            {PROPERTIES.map((p) => (
                                <tr key={p.name} className="border-b border-rule last:border-0">
                                    <td className="p-3 text-ink leading-snug">{p.name}</td>
                                    <td className="p-3 text-right font-mono text-ink">{p.count}</td>
                                    <td className="p-3 text-right font-mono text-burgundy">{p.share}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                <p className="text-ink-soft text-[0.9rem] max-w-2xl mb-16">
                    Two properties a static scan cannot see are left out on purpose: delegation
                    provenance (who authorized the agent) and continuous trust (renewed, not trusted
                    once). Both are runtime properties.
                </p>

                <div className="border border-rule bg-parchment-warm p-8 max-w-prose">
                    <p className="eyebrow text-burgundy mb-2">How the score works</p>
                    <h2 className="font-serif font-semibold text-[1.4rem] tracking-tight mb-3">Open methodology</h2>
                    <p className="text-ink-soft leading-relaxed mb-4">
                        Each agent gets a Trust Score from 0 to 100 and a letter grade. For this first
                        version the source is the public Model Context Protocol registry, and the check
                        is a resolvable decentralized identity: a did:web document at the agent's own
                        domain (60 points) carrying a usable public key (40 points). A is 90 or above,
                        then B, C, D, and F below 40. The scoring is open so anyone can audit how a
                        number is reached. Nobody signs up; the Index finds agents on its own.
                    </p>
                    <div className="flex flex-wrap gap-3">
                        <a
                            href="https://github.com/vouch-protocol/vouch"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-primary"
                        >
                            Follow on GitHub
                        </a>
                        <Link href="/tools/" className="btn-secondary">See the tools</Link>
                    </div>
                </div>
            </div>
        </main>
    );
}
