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
            <section className="container-wide pt-20 md:pt-28 pb-16 md:pb-20">
                <p className="eyebrow text-burgundy mb-5">The Agent Trust Index</p>
                <h1 className="font-serif font-semibold text-[clamp(2.6rem,7vw,5rem)] leading-[1.02] tracking-tight mb-6">
                    &ldquo;Trust me,
                    <br />
                    I&rsquo;m an AI agent.&rdquo;
                </h1>
                <p className="text-[clamp(1.25rem,3vw,1.75rem)] leading-snug text-ink-soft mb-9 max-w-[24ch]">
                    <strong className="text-burgundy font-semibold">{ATI_SUMMARY.pctCannot}%</strong> can&rsquo;t
                    back that up. Only {VERIFIABLE} of {TOTAL} public agents can prove who they are.
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

            {/* THE PROBLEM */}
            <section className="border-t border-rule">
                <div className="container-wide py-16 md:py-20">
                    <p className="eyebrow text-burgundy mb-4">The gap</p>
                    <h2 className="font-serif font-semibold text-[clamp(1.7rem,4vw,2.6rem)] leading-tight tracking-tight mb-4 max-w-[16ch]">
                        Your AI already acts on real systems.
                    </h2>
                    <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-[52ch] mb-10">
                        It books, buys, emails, and ships code for you. The open question is whether it can prove
                        who it is, and who allowed it.
                    </p>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src="/assets/trust-handoff.svg"
                        alt="A human delegates to an AI agent that carries a verifiable identity, and the agent acts on an MCP server. Each handoff is signed."
                        className="hidden md:block w-full h-auto max-w-[880px]"
                    />
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src="/assets/trust-handoff-mobile.svg"
                        alt="A human delegates to an AI agent that carries a verifiable identity, and the agent acts on an MCP server. Each handoff is signed."
                        className="block md:hidden w-full h-auto max-w-[320px]"
                    />
                </div>
            </section>

            {/* THE SOLUTION */}
            <section className="border-t border-rule">
                <div className="container-wide py-16 md:py-20">
                    <p className="eyebrow text-burgundy mb-4">The fix</p>
                    <h2 className="font-serif font-semibold text-[clamp(1.7rem,4vw,2.6rem)] leading-tight tracking-tight mb-4 max-w-[16ch]">
                        Give every agent a way to prove it.
                    </h2>
                    <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-[52ch] mb-10">
                        A verifiable identity, a signed permission slip, and a signature on every action that
                        anyone can check.
                    </p>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src="/assets/how-vouch-works.svg"
                        alt="How Vouch works: give the agent a verifiable ID, the human sets the rules, every action is signed, and anyone can check it. Tampering and fakes are rejected."
                        className="hidden md:block w-full h-auto max-w-[880px]"
                    />
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src="/assets/how-vouch-works-mobile.svg"
                        alt="How Vouch works: give the agent a verifiable ID, the human sets the rules, every action is signed, and anyone can check it. Tampering and fakes are rejected."
                        className="block md:hidden w-full h-auto max-w-[340px]"
                    />
                </div>
            </section>

            {/* CLOSING LINE + CTA */}
            <section className="bg-ink text-parchment border-t border-rule">
                <div className="container-wide py-16 md:py-20">
                    <p className="font-serif italic text-[clamp(1.6rem,4vw,2.6rem)] leading-tight tracking-tight mb-8 max-w-[20ch]">
                        The web got a padlock. Agents get Vouch.
                    </p>
                    <div className="flex flex-col sm:flex-row sm:items-center gap-5">
                        <span className="font-serif font-semibold text-[1.4rem] tracking-tight">
                            Can your agent prove it?
                        </span>
                        <Link
                            href="/agent-trust-index/"
                            className="inline-flex items-center gap-2 font-mono uppercase text-[0.75rem] tracking-[0.16em] px-6 py-[0.85rem] bg-burgundy text-parchment border border-burgundy no-underline transition-colors hover:bg-[#5f222c] hover:border-[#5f222c] self-start"
                        >
                            Grade it in 10 seconds
                        </Link>
                    </div>
                </div>
            </section>

            {/* SHARE */}
            <section className="container-wide py-12">
                <ShareButtons text={SHARE_TEXT} url={PAGE_URL} image="/assets/ati-card.png" />
            </section>
        </main>
    );
}
