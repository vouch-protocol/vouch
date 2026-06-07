import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Agent Trust Index - Vouch Protocol',
    description:
        'An open benchmark of how many autonomous agents in the wild can actually prove who they are. Today, fewer than one percent can.',
};

const FACTS = [
    {
        stat: '< 1%',
        label: 'of agents seen in the wild can present a verifiable identity today.',
    },
    {
        stat: 'Open',
        label: 'methodology and data. Anyone can audit how a score is reached.',
    },
    {
        stat: 'Live',
        label: 'continuous scanning, not a one-time snapshot. Trust is a moving target.',
    },
];

export default function IndexPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="container-wide py-20 md:py-28">
                <p className="eyebrow text-burgundy mb-3">For the ecosystem</p>
                <h1 className="font-serif font-semibold text-[clamp(2.2rem,5vw,3.6rem)] leading-[1.05] tracking-tight mb-6 max-w-[900px]">
                    The Agent Trust Index
                </h1>
                <p className="drop-cap text-[1.2rem] leading-snug text-ink-soft max-w-prose mb-10">
                    An open benchmark of how trustworthy the agent world actually is. It scans
                    autonomous agents in the wild and measures how many can cryptographically prove who
                    they are, on whose authority they act, and that they have not been tampered with.
                    The early answer is uncomfortable: almost none can.
                </p>

                <div className="grid sm:grid-cols-3 gap-8 max-w-3xl mb-14">
                    {FACTS.map((f) => (
                        <div key={f.label} className="border-l-2 border-burgundy pl-4">
                            <div className="font-serif font-semibold text-[2rem] tracking-tight mb-1">{f.stat}</div>
                            <p className="text-ink-soft text-[0.95rem] leading-relaxed">{f.label}</p>
                        </div>
                    ))}
                </div>

                <div className="border border-rule bg-parchment-warm p-8 max-w-prose">
                    <p className="eyebrow text-burgundy mb-2">Status</p>
                    <h2 className="font-serif font-semibold text-[1.4rem] tracking-tight mb-3">
                        The Index is being built in the open.
                    </h2>
                    <p className="text-ink-soft leading-relaxed mb-5">
                        The scanning methodology and the first dataset are in progress. If you run agents
                        and want them measured, or you want to be told when the first Index publishes,
                        the fastest way to follow along is the repository and the community.
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
