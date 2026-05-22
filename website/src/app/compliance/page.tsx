import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Regulatory Compliance — Vouch Protocol',
    description:
        'Vouch Protocol mappings against GDPR, EU AI Act, NIST SP 800-63, and HIPAA. How the protocol maps to specific regulatory requirements.',
};

type Framework = {
    slug: string;
    name: string;
    jurisdiction: string;
    status: 'Draft' | 'Planned';
    minLevel: 'L1' | 'L2' | 'L3';
    summary: string;
    helps: string[];
    notAddressed: string[];
    docHref: string;
};

const FRAMEWORKS: Framework[] = [
    {
        slug: 'gdpr',
        name: 'GDPR',
        jurisdiction: 'EU',
        status: 'Draft',
        minLevel: 'L2',
        summary: 'EU General Data Protection Regulation (Regulation 2016/679). Vouch directly supports integrity, accountability, and data-protection-by-design requirements.',
        helps: [
            'Art. 5(1)(f) Integrity and confidentiality',
            'Art. 5(2) Accountability',
            'Art. 25 Data protection by design and default',
            'Art. 32 Security of processing',
            'Art. 33 Breach notification (earlier signals via canary chain)',
        ],
        notAddressed: [
            'Data subject rights (Art. 12-22)',
            'Lawful basis of processing (Art. 6)',
            'Cross-border transfer mechanisms',
        ],
        docHref: 'https://github.com/vouch-protocol/vouch/blob/main/docs/compliance/gdpr.md',
    },
    {
        slug: 'eu-ai-act',
        name: 'EU AI Act',
        jurisdiction: 'EU',
        status: 'Draft',
        minLevel: 'L3',
        summary: 'Regulation (EU) 2024/1689. Vouch supports record-keeping, transparency, human-oversight, and cybersecurity requirements for high-risk AI systems.',
        helps: [
            'Art. 12 Automatic logging for high-risk AI systems',
            'Art. 13 Transparency to deployers',
            'Art. 14 Human oversight (trusted-principal anchoring)',
            'Art. 15 Accuracy, robustness, cybersecurity',
            'Art. 50 Transparency about AI-generated actions',
        ],
        notAddressed: [
            'Risk classification (Annex III)',
            'Bias and fairness assessment',
            'Conformity assessment (Art. 43)',
        ],
        docHref: 'https://github.com/vouch-protocol/vouch/blob/main/docs/compliance/eu-ai-act.md',
    },
    {
        slug: 'nist-800-63',
        name: 'NIST SP 800-63',
        jurisdiction: 'US (federal)',
        status: 'Draft',
        minLevel: 'L2',
        summary: 'Digital Identity Guidelines. Vouch addresses AAL (Authentication Assurance) and FAL (Federation Assurance) for autonomous agents; IAL (Identity Assurance) is upstream.',
        helps: [
            'AAL2 multi-factor authentication',
            'AAL3 hardware-isolated authenticators (Sidecar + HSM)',
            'FAL2 / FAL3 assertion protection',
            'Phishing-resistant authentication (with hardware keys)',
            'Reauthentication via Heartbeat + Trust Entropy',
        ],
        notAddressed: [
            'IAL (identity proofing) at any level - upstream of the protocol',
        ],
        docHref: 'https://github.com/vouch-protocol/vouch/blob/main/docs/compliance/nist-800-63.md',
    },
    {
        slug: 'hipaa',
        name: 'HIPAA',
        jurisdiction: 'US (healthcare)',
        status: 'Draft',
        minLevel: 'L3',
        summary: 'US Health Insurance Portability and Accountability Act. Vouch supports the Security Rule\'s access-control, audit, and integrity requirements for AI agents touching PHI.',
        helps: [
            '§164.312(a) Unique user identification (DIDs)',
            '§164.312(b) Audit controls (per-action signed credentials)',
            '§164.312(c) Integrity controls (Data Integrity proofs)',
            '§164.308(a)(4) Access establishment and modification (Sidecar allow-list)',
            '§164.502(b) Minimum-necessary rule (delegation narrowing)',
        ],
        notAddressed: [
            'Privacy Rule substantive provisions',
            'Breach notification workflow itself',
            'PHI encryption at rest (Vouch is identity, not encryption)',
        ],
        docHref: 'https://github.com/vouch-protocol/vouch/blob/main/docs/compliance/hipaa.md',
    },
    {
        slug: 'soc-2',
        name: 'SOC 2',
        jurisdiction: 'US (audit standard)',
        status: 'Planned',
        minLevel: 'L2',
        summary: 'AICPA SOC 2 Trust Services Criteria. Mapping in preparation.',
        helps: [],
        notAddressed: [],
        docHref: '',
    },
    {
        slug: 'iso-27001',
        name: 'ISO/IEC 27001',
        jurisdiction: 'International',
        status: 'Planned',
        minLevel: 'L2',
        summary: 'Information Security Management System standard. Mapping in preparation.',
        helps: [],
        notAddressed: [],
        docHref: '',
    },
    {
        slug: 'dpdpa',
        name: 'DPDPA',
        jurisdiction: 'India',
        status: 'Planned',
        minLevel: 'L2',
        summary: 'Digital Personal Data Protection Act 2023. Mapping in preparation.',
        helps: [],
        notAddressed: [],
        docHref: '',
    },
];

function LevelChip({ level }: { level: 'L1' | 'L2' | 'L3' }) {
    return (
        <span className="inline-block font-mono uppercase text-[0.62rem] tracking-[0.18em] border border-burgundy text-burgundy px-2 py-0.5">
            {level}
        </span>
    );
}

export default function CompliancePage() {
    const draft = FRAMEWORKS.filter((f) => f.status === 'Draft');
    const planned = FRAMEWORKS.filter((f) => f.status === 'Planned');

    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="max-w-prose-wide mx-auto px-6 py-16 md:py-24">
                <header className="mb-12">
                    <p className="eyebrow text-burgundy mb-3">Regulatory mapping</p>
                    <h1 className="font-serif text-[2.2rem] md:text-[2.8rem] leading-tight tracking-tight mb-4">
                        Vouch Protocol&trade; against the frameworks<br />
                        your compliance team asks about
                    </h1>
                    <p className="font-serif italic text-ink-soft text-[1.1rem] max-w-prose leading-relaxed">
                        For each major regulation, we publish a clause-by-clause mapping showing which
                        requirements Vouch&apos;s mechanisms satisfy and which it explicitly does not address.
                        These are informative, not normative; legal compliance depends on the full deployment.
                    </p>
                </header>

                <section className="space-y-10">
                    {draft.map((f) => (
                        <article key={f.slug} className="bg-parchment-warm border border-rule p-8">
                            <header className="flex items-start justify-between gap-4 mb-3 pb-3 border-b border-rule-light">
                                <div>
                                    <h2 className="font-serif text-[1.5rem] font-semibold tracking-tight">{f.name}</h2>
                                    <p className="font-mono uppercase text-[0.65rem] tracking-[0.16em] text-ink-faint mt-1">
                                        {f.jurisdiction} &middot; minimum recommended: <LevelChip level={f.minLevel} />
                                    </p>
                                </div>
                                <Link
                                    href={f.docHref}
                                    className="font-mono uppercase text-[0.65rem] tracking-[0.14em] text-ink border border-ink px-2.5 py-1 no-underline hover:bg-ink hover:text-parchment whitespace-nowrap transition-colors"
                                >
                                    Full mapping →
                                </Link>
                            </header>

                            <p className="text-ink leading-relaxed mb-5">{f.summary}</p>

                            <div className="grid md:grid-cols-2 gap-6 mb-4">
                                <div>
                                    <h3 className="eyebrow text-burgundy mb-2">Vouch helps</h3>
                                    <ul className="list-disc list-outside pl-5 space-y-1 marker:text-burgundy text-[0.95rem]">
                                        {f.helps.map((h) => (
                                            <li key={h} className="text-ink leading-relaxed">{h}</li>
                                        ))}
                                    </ul>
                                </div>
                                <div>
                                    <h3 className="eyebrow text-ink-faint mb-2">Out of scope</h3>
                                    <ul className="list-disc list-outside pl-5 space-y-1 marker:text-ink-faint text-[0.95rem]">
                                        {f.notAddressed.map((n) => (
                                            <li key={n} className="text-ink-soft italic leading-relaxed">{n}</li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                        </article>
                    ))}
                </section>

                {planned.length > 0 && (
                    <section className="mt-16 border-t border-rule pt-10">
                        <h2 className="font-serif text-[1.4rem] font-semibold mb-2">Mappings in preparation</h2>
                        <p className="text-ink-soft italic mb-6 leading-relaxed">
                            We are extending the mapping to these frameworks. If you need one prioritised,
                            email <a className="text-burgundy border-b border-burgundy" href="mailto:ask@vouch-protocol.com">ask@vouch-protocol.com</a>.
                        </p>
                        <ul className="grid md:grid-cols-3 gap-3 list-none p-0">
                            {planned.map((f) => (
                                <li key={f.slug} className="border border-rule-light p-4">
                                    <p className="font-serif font-semibold">{f.name}</p>
                                    <p className="font-mono uppercase text-[0.62rem] tracking-[0.16em] text-ink-faint mt-1">
                                        {f.jurisdiction}
                                    </p>
                                </li>
                            ))}
                        </ul>
                    </section>
                )}

                <footer className="mt-16 border-t border-rule pt-8 flex flex-col md:flex-row gap-4 md:justify-between text-[0.92rem]">
                    <Link
                        href="/conformance"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink border-b border-ink no-underline hover:bg-ink hover:text-parchment px-1 py-0.5 transition-colors w-fit"
                    >
                        ← Protocol conformance levels (L1/L2/L3)
                    </Link>
                    <Link
                        href="https://github.com/vouch-protocol/vouch/tree/main/docs/compliance"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink-soft border-b border-rule no-underline hover:text-ink px-1 py-0.5 transition-colors w-fit"
                    >
                        Source on GitHub →
                    </Link>
                </footer>
            </div>
        </main>
    );
}
