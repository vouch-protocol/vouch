import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Adopters - Vouch Protocol',
    description:
        'Independent systems that build on or integrate Vouch Protocol, starting with invinoveritas, the first reference integration of Outcome Evidence and the AccountabilityRecord.',
};

type LinkItem = { label: string; href: string };

type Adopter = {
    name: string;
    by: string;
    focus: string;
    badge: string;
    summary: string;
    links: LinkItem[];
};

const ADOPTERS: Adopter[] = [
    {
        name: 'invinoveritas',
        by: 'babyblueviper1',
        focus: 'Outcome Evidence and the AccountabilityRecord',
        badge: 'First reference integration',
        summary:
            'A live outcome-verified reputation service. invinoveritas emits a Vouch AccountabilityRecord on its handshake surface, conforming to the shipped field set (verifierKey, recordPointer, verifyEndpoint, reputationModel: recomputable, publishesLosses). Its review of the commit-before-outcome primitive also produced the third-party timestamp anchor and the existence-versus-ordering precedence affordance now in the protocol.',
        links: [
            {
                label: 'Live handshake',
                href: 'https://api.babyblueviper.com/.well-known/agent-handshake',
            },
            {
                label: 'Discussion #53',
                href: 'https://github.com/vouch-protocol/vouch/discussions/53',
            },
            { label: 'Certificate', href: '/i/invinoveritas/' },
        ],
    },
];

export default function AdoptersPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="container-wide py-16 md:py-24">
                <header className="mb-12">
                    <p className="eyebrow text-burgundy mb-3">Built on Vouch</p>
                    <h1 className="font-serif text-[2.2rem] md:text-[2.8rem] leading-tight tracking-tight mb-4">
                        Adopters
                    </h1>
                    <p className="font-serif italic text-ink-soft text-[1.1rem] max-w-prose leading-relaxed">
                        Independent systems that build on or integrate Vouch Protocol. A reference
                        integration produces or consumes Vouch credentials against the published
                        schema, so anyone can verify it. This is a living list.
                    </p>
                </header>

                <section className="space-y-12">
                    {ADOPTERS.map((a) => (
                        <article key={a.name} className="bg-parchment-warm border border-rule p-8 md:p-10">
                            <header className="flex flex-wrap items-baseline gap-x-4 gap-y-2 mb-3 border-b border-rule-light pb-4">
                                <h2 className="font-serif text-[1.6rem] md:text-[1.8rem] font-semibold tracking-tight">
                                    {a.name}
                                </h2>
                                <span className="font-mono uppercase tracking-[0.16em] text-burgundy text-[0.72rem]">
                                    {a.badge}
                                </span>
                                <span className="font-serif italic text-ink-faint text-[0.95rem]">
                                    by {a.by}
                                </span>
                            </header>

                            <h3 className="eyebrow mb-2">Integrates</h3>
                            <p className="mb-6 text-ink leading-relaxed">{a.focus}</p>

                            <p className="text-ink leading-relaxed mb-6 max-w-prose">{a.summary}</p>

                            <div className="flex flex-wrap gap-x-6 gap-y-2">
                                {a.links.map((l) => (
                                    <a
                                        key={l.label}
                                        href={l.href}
                                        target={l.href.startsWith('http') ? '_blank' : undefined}
                                        rel={l.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                                        className="font-mono uppercase tracking-[0.14em] text-[0.72rem] text-burgundy border-b border-burgundy pb-0.5 no-underline hover:text-burgundy-dark hover:border-burgundy-dark"
                                    >
                                        {l.label}
                                    </a>
                                ))}
                            </div>
                        </article>
                    ))}
                </section>

                <section className="mt-16 border-t border-rule-light pt-10">
                    <h2 className="font-serif text-[1.4rem] font-semibold mb-3">Build a reference integration</h2>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-4">
                        If your system produces or consumes Vouch credentials, identity, delegation,
                        outcome evidence, or an AccountabilityRecord, against the published schema, we
                        are glad to list it here. Open a discussion and show the live surface a
                        verifier can check.
                    </p>
                    <a
                        href="https://github.com/vouch-protocol/vouch/discussions"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono uppercase tracking-[0.14em] text-[0.72rem] text-burgundy border-b border-burgundy pb-0.5 no-underline hover:text-burgundy-dark hover:border-burgundy-dark"
                    >
                        Start a discussion
                    </a>
                </section>
            </div>
        </main>
    );
}
