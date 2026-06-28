import Link from 'next/link';
import Image from 'next/image';
import type { Metadata } from 'next';
import { ATI_SUMMARY } from '../agent-trust-index/ati-data';
import ShareButtons from '../agent-trust-index/ShareButtons';

const TOTAL = ATI_SUMMARY.total.toLocaleString('en-US');
const PAGE_URL = 'https://vouch-protocol.com/the-trust-gap/';
const SHARE_TEXT = `AI agents now act on our behalf, yet ${ATI_SUMMARY.pctCannot}% of them cannot prove who they are or who authorized them. As they start touching money and real data, this is the AI trust gap to watch:`;

export const metadata: Metadata = {
    title: 'The AI trust gap - Vouch Protocol',
    description: `AI agents are starting to act for us, book, buy, email, write code. ${ATI_SUMMARY.pctCannot}% of them cannot prove who they are or who put them in charge. Here is why that matters, in plain English.`,
    alternates: { canonical: PAGE_URL },
    openGraph: {
        title: `${ATI_SUMMARY.pctCannot}% of AI agents cannot prove who they are`,
        description:
            'AI agents are starting to act for us. Almost none can prove who they are or who authorized them. Here is why that matters, in plain English.',
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

const POINTS = [
    {
        h: 'What is changing',
        p: 'AI agents have started to do things, not only chat. They book travel, move money, send email, file tickets, and change code, acting for a person or a company.',
    },
    {
        h: 'The problem',
        p: 'When an agent acts, can you prove which agent it was, who allowed it, and that the instruction was not tampered with on the way? Today, almost never. So when one makes a costly mistake or gets hijacked, no one can say who was responsible.',
    },
    {
        h: 'What Vouch does',
        p: 'Vouch gives every AI agent a verifiable identity and a signed permission slip, like a passport and an authorization anyone can check. The web got the padlock so you can trust a website. Agents need the same, and Vouch is the open standard for it.',
    },
];

export default function TrustGapPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="container-wide py-20 md:py-28">
                <p className="eyebrow text-burgundy mb-3">The AI trust gap</p>
                <h1 className="font-serif font-semibold text-[clamp(2.2rem,5vw,3.6rem)] leading-[1.05] tracking-tight mb-6 max-w-[900px]">
                    Your AI is starting to act for you. Can it prove it is allowed to?
                </h1>
                <p className="drop-cap text-[1.2rem] leading-snug text-ink-soft max-w-prose mb-10">
                    We checked every public AI agent we could find. <strong>{ATI_SUMMARY.pctCannot}%</strong> of
                    them cannot prove who they are or who put them in charge. Only {ATI_SUMMARY.verifiable} of{' '}
                    {TOTAL} can.
                </p>

                <div className="max-w-3xl mb-12 border border-rule">
                    <Image
                        src="/assets/ati-card.png"
                        alt={`${ATI_SUMMARY.pctCannot}% of AI agents cannot prove who they are`}
                        width={1200}
                        height={630}
                        className="w-full h-auto"
                        priority
                    />
                </div>

                <div className="grid md:grid-cols-3 gap-8 max-w-4xl mb-16">
                    {POINTS.map((c) => (
                        <div key={c.h} className="border-t-2 border-burgundy pt-3">
                            <h2 className="font-serif font-semibold text-[1.2rem] tracking-tight mb-2">{c.h}</h2>
                            <p className="text-ink-soft text-[0.98rem] leading-relaxed">{c.p}</p>
                        </div>
                    ))}
                </div>

                <div className="border border-burgundy bg-parchment-warm p-8 md:p-10 max-w-3xl mb-12">
                    <h2 className="font-serif font-semibold text-[1.6rem] tracking-tight mb-3">
                        Want to see for yourself?
                    </h2>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
                        The Agent Trust Index is the live scoreboard: how many agents can prove who they are,
                        updated every week. You can also grade any agent, or your own, in about ten seconds.
                    </p>
                    <div className="flex flex-wrap gap-3">
                        <Link href="/agent-trust-index/" className="btn-primary">See the live numbers</Link>
                        <Link href="/" className="btn-secondary">How Vouch works</Link>
                    </div>
                </div>

                <div className="max-w-3xl">
                    <ShareButtons text={SHARE_TEXT} url={PAGE_URL} image="/assets/ati-card.png" />
                </div>
            </div>
        </main>
    );
}
