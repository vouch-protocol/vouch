import Link from 'next/link';
import type { Metadata } from 'next';
import { ATI_SUMMARY } from '../agent-trust-index/ati-data';
import ShareButtons from '../agent-trust-index/ShareButtons';

const TOTAL = ATI_SUMMARY.total.toLocaleString('en-US');
const VERIFIABLE = ATI_SUMMARY.verifiable.toLocaleString('en-US');
const PAGE_URL = 'https://vouch-protocol.com/the-trust-gap/';
const SHARE_TEXT = `"Trust me, I'm an AI agent." ${ATI_SUMMARY.pctCannot}% of public AI agents can't back that up: they can't prove who they are or who authorized them. As agents start touching money and real data, this is the AI trust gap to watch:`;

export const metadata: Metadata = {
    title: 'The AI trust gap - Vouch Protocol',
    description: `"Trust me, I'm an AI agent." ${ATI_SUMMARY.pctCannot}% can't back that up. They act for us, yet cannot prove who they are or who put them in charge. The AI trust gap, in plain English.`,
    alternates: { canonical: PAGE_URL },
    openGraph: {
        title: `"Trust me, I'm an AI agent." ${ATI_SUMMARY.pctCannot}% can't prove it.`,
        description:
            'AI agents now act for us. Almost none can prove who they are or who authorized them. The AI trust gap, in plain English.',
        url: PAGE_URL,
        type: 'article',
        images: [{ url: '/assets/ati-card.png', width: 1200, height: 630 }],
    },
    twitter: {
        card: 'summary_large_image',
        site: '@Vouch_Protocol',
        images: ['/assets/ati-card.png'],
    },
};

export default function TrustGapPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            {/* HERO */}
            <section className="container-wide pt-20 md:pt-28 pb-14">
                <p className="eyebrow text-burgundy mb-5">The Agent Trust Index</p>
                <h1 className="font-serif font-semibold text-[clamp(2.6rem,7vw,5rem)] leading-[1.02] tracking-tight mb-6">
                    &ldquo;Trust me,
                    <br />
                    I&rsquo;m an AI agent.&rdquo;
                </h1>
                <p className="text-[clamp(1.3rem,3vw,1.9rem)] text-ink-soft mb-9">
                    <strong className="text-burgundy font-semibold">{ATI_SUMMARY.pctCannot}%</strong> can&rsquo;t
                    back that up.
                </p>
                <div className="flex flex-wrap gap-3">
                    <Link href="/agent-trust-index/" className="btn-primary">
                        See the proof
                    </Link>
                    <Link href="/" className="btn-secondary">
                        Meet the standard
                    </Link>
                </div>
            </section>

            {/* THE PROBLEM: the trust handoff */}
            <section className="border-t border-rule bg-parchment-warm/40">
                <div className="container-wide py-12 md:py-16">
                    <p className="eyebrow text-burgundy mb-6">The handoff</p>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src="/assets/trust-handoff.svg"
                        alt="A human delegates to an AI agent that carries a verifiable identity, and the agent acts on an MCP server. Each handoff is signed."
                        className="w-full h-auto max-w-[940px] mx-auto"
                    />
                </div>
            </section>

            {/* THE SOLUTION: how Vouch works */}
            <section className="border-t border-rule">
                <div className="container-wide py-12 md:py-16">
                    <p className="eyebrow text-burgundy mb-6">The fix, in four steps</p>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src="/assets/how-vouch-works.svg"
                        alt="How Vouch works: give the agent a verifiable ID, the human sets the rules, every action is signed, and anyone can check it. Tampering and fakes are rejected."
                        className="w-full h-auto max-w-[940px] mx-auto"
                    />
                </div>
            </section>

            {/* THE NUMBER */}
            <section className="container-wide py-16 md:py-24">
                <div className="flex flex-col md:flex-row md:items-baseline gap-5 md:gap-12">
                    <div className="font-serif font-semibold text-[clamp(4.5rem,13vw,9rem)] leading-none tracking-tight">
                        {ATI_SUMMARY.pctCannot}%
                    </div>
                    <p className="text-[1.3rem] leading-snug text-ink-soft max-w-[22ch]">
                        of AI agents <strong className="text-ink font-semibold">cannot prove who they are.</strong>{' '}
                        Only {VERIFIABLE} of {TOTAL} can.
                    </p>
                </div>
            </section>

            {/* ONE-LINER */}
            <section className="border-t border-rule">
                <div className="container-wide py-14 md:py-16">
                    <p className="font-serif italic text-[clamp(1.5rem,4vw,2.5rem)] tracking-tight">
                        The web got a padlock. Agents get Vouch.
                    </p>
                </div>
            </section>

            {/* CTA BAND */}
            <section className="bg-ink text-parchment">
                <div className="container-wide py-14 md:py-16 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
                    <p className="font-serif font-semibold text-[clamp(1.6rem,4vw,2.4rem)] tracking-tight">
                        Can your agent prove it?
                    </p>
                    <Link
                        href="/agent-trust-index/"
                        className="inline-flex items-center gap-2 font-mono uppercase text-[0.75rem] tracking-[0.16em] px-6 py-[0.85rem] bg-burgundy text-parchment border border-burgundy no-underline transition-colors hover:bg-[#5f222c] hover:border-[#5f222c]"
                    >
                        Grade it in 10 seconds
                    </Link>
                </div>
            </section>

            {/* SHARE */}
            <section className="container-wide py-12">
                <ShareButtons text={SHARE_TEXT} url={PAGE_URL} image="/assets/ati-card.png" />
            </section>
        </main>
    );
}
