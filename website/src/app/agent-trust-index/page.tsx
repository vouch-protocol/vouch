import Link from 'next/link';
import type { Metadata } from 'next';
import CodeBlock from '@/components/CodeBlock';
import { ATI_SUMMARY, ATI_AGENTS } from './ati-data';
import AtiLeaderboard from './AtiLeaderboard';
import GradeChecker from './GradeChecker';

const ACCOUNTABILITY = [
    { h: 'Who authorized it', p: 'A delegation chain shows who gave the agent its authority, on whose behalf, and within what limits, all verifiable.' },
    { h: 'Is it still trustworthy', p: 'Continuous trust means an agent has to keep proving itself, not get trusted once and forever.' },
    { h: 'Can it be stopped', p: 'Revocation lets you pull an agent\'s authority the moment it goes wrong, and anyone can check the status.' },
];

const TOTAL = ATI_SUMMARY.total.toLocaleString('en-US');

export const metadata: Metadata = {
    title: 'Agent Trust Index - Vouch Protocol',
    description: `An open benchmark of how many autonomous agents can prove who they are. The first sweep checked ${TOTAL} public agents from the Model Context Protocol registry. ${ATI_SUMMARY.pctCannot}% cannot present a verifiable identity.`,
    alternates: { canonical: 'https://index.vouch-protocol.com/' },
};

const HEADLINE = [
    {
        stat: `${ATI_SUMMARY.pctCannot}%`,
        label: `of the ${TOTAL} agents checked cannot present an identity anyone can verify.`,
    },
    {
        stat: `${ATI_SUMMARY.pctVerifiable}%`,
        label: `can prove who they are with a resolvable did:web identity. That is ${ATI_SUMMARY.verifiable} agents.`,
    },
    {
        stat: `${ATI_SUMMARY.pqCount}`,
        label: 'agents are post-quantum ready. Not one carries an ML-DSA key.',
    },
];

const PROPERTIES = [
    { name: 'Can prove who they are (resolvable did:web identity)', count: ATI_SUMMARY.verifiable, share: `${ATI_SUMMARY.pctVerifiable}%` },
    { name: 'Agent card references a key or signature', count: ATI_SUMMARY.cardCount, share: `${ATI_SUMMARY.pctCard}%` },
    { name: 'Publishes a service endpoint (revocation, MCP, A2A)', count: ATI_SUMMARY.revCount, share: `${ATI_SUMMARY.pctRev}%` },
    { name: 'Post-quantum ready (an ML-DSA key)', count: ATI_SUMMARY.pqCount, share: `${ATI_SUMMARY.pctPq}%` },
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
                    The first sweep checked <strong>{TOTAL} unique agents</strong> from the public Model
                    Context Protocol registry on <strong>{ATI_SUMMARY.generated}</strong>. The answer is
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

                <div className="border border-burgundy bg-parchment-warm p-8 md:p-10 max-w-3xl mb-16 text-center">
                    <h2 className="font-serif font-semibold text-[1.7rem] tracking-tight mb-3">Most agents are anonymous. Yours does not have to be.</h2>
                    <p className="text-ink-soft leading-relaxed max-w-prose mx-auto mb-5">
                        Give your agent a verifiable identity in one command. It is free and open source,
                        and you keep control of your own keys.
                    </p>
                    <div className="max-w-xs mx-auto mb-6 text-left">
                        <CodeBlock code="pip install vouch-protocol" className="text-[0.85rem]" />
                    </div>
                    <div className="flex flex-wrap gap-3 justify-center">
                        <Link href="/onboard/" className="btn-primary">Get started</Link>
                        <a href="https://github.com/vouch-protocol/vouch" target="_blank" rel="noopener noreferrer" className="btn-secondary">View on GitHub</a>
                    </div>
                </div>

                <div className="max-w-3xl mb-16">
                    <h2 className="font-serif font-semibold text-[1.5rem] tracking-tight mb-3">Identity is the floor. Accountability is the core.</h2>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
                        Knowing which agent acted is only the start. The harder questions are who
                        authorized it, whether it is still behaving, and whether it can be stopped. A bare
                        identity does not answer those. The Vouch Protocol does, and this Index will grow
                        to measure all of it.
                    </p>
                    <div className="grid sm:grid-cols-3 gap-6">
                        {ACCOUNTABILITY.map((c) => (
                            <div key={c.h} className="border-t-2 border-burgundy pt-3">
                                <h3 className="font-mono uppercase text-[0.65rem] tracking-[0.14em] text-burgundy mb-2">{c.h}</h3>
                                <p className="text-ink-soft text-[0.95rem] leading-relaxed">{c.p}</p>
                            </div>
                        ))}
                    </div>
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

                <h2 className="font-serif font-semibold text-[1.5rem] tracking-tight mb-2">The agents that can prove it</h2>
                <p className="text-ink-soft max-w-prose mb-6">
                    The {ATI_SUMMARY.verifiable} agents that publish a verifiable signal, scored from 0
                    to 100 and graded. The other {ATI_SUMMARY.cannot.toLocaleString('en-US')} scored
                    zero. Filter by grade.
                </p>
                <div className="mb-16">
                    <AtiLeaderboard agents={ATI_AGENTS} />
                </div>

                <div className="border border-burgundy bg-parchment-warm p-8 md:p-10 max-w-3xl mb-16">
                    <p className="eyebrow text-burgundy mb-2">Check your own agent</p>
                    <h2 className="font-serif font-semibold text-[1.5rem] tracking-tight mb-3">
                        Grade your agent before anyone else does
                    </h2>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-5">
                        Type your agent&apos;s domain to run the same check the Index runs. You get a letter
                        grade, the exact reasons, and numbered fixes to raise it.
                    </p>
                    <GradeChecker />
                    <p className="text-ink-soft text-[0.9rem] leading-relaxed max-w-prose mt-5 mb-2">
                        Prefer the command line, or want a badge for your README? Install once and run it
                        locally:
                    </p>
                    <div className="max-w-md mb-4">
                        <CodeBlock code={"pip install vouch-protocol\nvouch grade yourdomain.com --badge trust-badge.svg"} className="text-[0.85rem]" />
                    </div>
                    <p className="text-ink-soft text-[0.9rem] leading-relaxed max-w-prose">
                        Claiming and verified listings are coming. If you want your agent listed when
                        they open, say so in the discussion and we will follow up.
                    </p>
                    <div className="flex flex-wrap gap-3 mt-5">
                        <Link href="/onboard/" className="btn-primary">Raise your grade</Link>
                        <a
                            href="https://github.com/vouch-protocol/vouch/discussions"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-secondary"
                        >
                            Register interest
                        </a>
                    </div>
                </div>

                <div className="border border-rule bg-parchment-warm p-8 max-w-prose">
                    <p className="eyebrow text-burgundy mb-2">How the score works</p>
                    <h2 className="font-serif font-semibold text-[1.4rem] tracking-tight mb-3">Open methodology</h2>
                    <p className="text-ink-soft leading-relaxed mb-4">
                        Each agent gets a Trust Score from 0 to 100 and a letter grade. For this first
                        version the source is the public Model Context Protocol registry, and the check
                        is a resolvable decentralized identity: a did:web document at the agent&apos;s own
                        domain (60 points) carrying a usable public key (40 points). A is 90 or above,
                        then B, C, D, and F below 40. The scoring is open so anyone can audit how a
                        number is reached. Nobody signs up; the Index finds agents on its own.
                    </p>
                    <div className="flex flex-wrap gap-3">
                        <Link href="/agent-trust-index/methodology/" className="btn-primary">Read the full methodology</Link>
                        <a
                            href="https://github.com/vouch-protocol/vouch"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-secondary"
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
