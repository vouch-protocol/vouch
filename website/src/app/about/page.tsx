import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
    title: 'About - Vouch Protocol',
    description:
        'The story behind Vouch Protocol: an open, independent standard for the cryptographic identity and accountability of autonomous AI agents.',
};

const FOUNDER_LINKS = [
    { label: 'LinkedIn', href: 'https://www.linkedin.com/in/rampy' },
    { label: 'X', href: 'https://x.com/rampyg' },
    { label: 'GitHub', href: 'https://github.com/rampyg' },
    { label: 'Email', href: 'mailto:ram@vouch-protocol.com' },
];

export default function AboutPage() {
    return (
        <>
            {/* Hero */}
            <section className="border-b border-rule">
                <div className="container-wide py-16 md:py-24">
                    <div className="eyebrow mb-5">About</div>
                    <h1 className="font-serif font-semibold text-ink leading-[1.08] tracking-tight mb-6 max-w-[880px] text-[clamp(2.2rem,4.8vw,3.4rem)]">
                        An open accountability layer for a world of autonomous agents.
                    </h1>
                    <p className="drop-cap text-ink-soft text-[1.2rem] leading-snug max-w-prose mb-4">
                        Software is starting to act on its own. AI agents book, buy, file, deploy, and
                        decide, often on your behalf and increasingly with no human in the loop. When one of
                        them acts, there is usually no way to prove which agent it was, who authorized it, or
                        whether it stayed within bounds.
                    </p>
                    <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
                        Vouch Protocol exists to close that gap, to give autonomous agents a cryptographic
                        identity and a verifiable record of accountability, as an open standard that no single
                        company owns.
                    </p>
                </div>
            </section>

            {/* The problem */}
            <section className="border-b border-rule">
                <div className="container-wide py-16">
                    <div className="section-heading mb-6">
                        <span className="num">§ I</span>
                        <h2>Accountability is the missing layer</h2>
                    </div>
                    <div className="max-w-prose space-y-4 text-ink-soft leading-relaxed">
                        <p>
                            API keys, OAuth tokens, and bearer secrets were built for apps and people, not for
                            autonomous agents that reason, delegate, and act continuously. They prove
                            possession of a secret. They do not prove who acted, on whose authority, or whether
                            the action stayed within policy.
                        </p>
                        <p>
                            As agents take on real consequences, financial, clinical, operational, that missing
                            accountability becomes the thing that blocks trust. Vouch treats it as a protocol
                            problem rather than a product, and builds on proven open standards (Verifiable
                            Credentials, Data Integrity proofs, Decentralized Identifiers) instead of inventing
                            new cryptography where good standards already exist.
                        </p>
                    </div>
                </div>
            </section>

            {/* Open and independent */}
            <section className="border-b border-rule">
                <div className="container-wide py-16">
                    <div className="section-heading mb-6">
                        <span className="num">§ II</span>
                        <h2>Open, and built to stay open</h2>
                    </div>
                    <div className="max-w-prose space-y-4 text-ink-soft leading-relaxed">
                        <p>
                            Vouch is free and open source. The cryptographic methods are published as open
                            defensive disclosures so they stay free for anyone to implement, and the protocol
                            is vendor-neutral by design, so no single company controls the trust layer for AI
                            agents.
                        </p>
                        <p>
                            It is bootstrapped and independent, with no investors steering it. The goal is
                            infrastructure: the kind of thing that works best when it belongs to everyone.
                        </p>
                    </div>
                </div>
            </section>

            {/* Founder */}
            <section className="border-b border-rule">
                <div className="container-wide py-16">
                    <div className="section-heading mb-6">
                        <span className="num">§ III</span>
                        <h2>Who is behind it</h2>
                    </div>
                    <div className="max-w-prose space-y-4 text-ink-soft leading-relaxed">
                        <p>
                            Vouch Protocol is built by{' '}
                            <strong className="text-ink font-semibold">Ramprasad Gaddam</strong>, an
                            independent engineer, in a personal capacity. It began from a simple conviction:
                            the agent era needs an accountability layer as foundational as TLS was for the web,
                            and it should be open from the first day rather than owned by whoever reaches it
                            first.
                        </p>
                        <p>
                            The work is done in the open. The specification, the reference implementations, and
                            the cryptographic disclosures are all public, so the protocol can be inspected,
                            challenged, and improved by anyone who relies on it.
                        </p>
                    </div>
                    <div className="flex flex-wrap gap-3 mt-7">
                        {FOUNDER_LINKS.map((l) => (
                            <a
                                key={l.label}
                                href={l.href}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="btn-secondary"
                            >
                                {l.label}
                            </a>
                        ))}
                    </div>
                </div>
            </section>

            {/* CTA */}
            <section>
                <div className="container-wide py-16">
                    <div className="section-heading mb-6">
                        <span className="num">§ IV</span>
                        <h2>Build it with us</h2>
                    </div>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-7">
                        Vouch is open and welcoming. Read the specification, pick up a good first issue, or
                        reach out if you are building or securing AI agents and want a trust layer underneath
                        them.
                    </p>
                    <div className="flex flex-wrap gap-3">
                        <Link href="/onboard/" className="btn-primary">
                            Get started
                        </Link>
                        <a
                            href="https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-secondary"
                        >
                            Good first issues
                        </a>
                        <a href="mailto:vouch.protocol.official@gmail.com" className="btn-secondary">
                            Contact
                        </a>
                    </div>
                </div>
            </section>
        </>
    );
}
