import Link from 'next/link';
import type { Metadata } from 'next';
import contributors from '@/data/contributors.json';

export const metadata: Metadata = {
    title: 'Verified Contributors - Vouch Protocol',
    description:
        'People who have contributed to Vouch Protocol, each issued a signed Vouch Verified Contributor credential.',
};

type Contributor = {
    login: string;
    pr: number;
    title?: string;
};

// The list is populated automatically when a contributor's first PR merges
// (see .github/workflows/verified-contributor.yml). Each entry links to that
// contributor's certificate page at /c/<login>.
const CONTRIBUTORS: Contributor[] = contributors as Contributor[];

const BADGE_URL =
    'https://img.shields.io/badge/Vouch-Verified_Contributor-7C2D3A?style=for-the-badge&labelColor=2d2d2d';

const BADGE_SNIPPET = `[![Vouch Verified Contributor](${BADGE_URL})](https://vouch-protocol.com/contributors)`;

export default function ContributorsPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="max-w-prose-wide mx-auto px-6 py-16 md:py-24">
                <header className="mb-12">
                    <p className="eyebrow text-burgundy mb-3">Recognition</p>
                    <h1 className="font-serif text-[2.2rem] md:text-[2.8rem] leading-tight tracking-tight mb-4">
                        Vouch Verified Contributors
                    </h1>
                    <p className="font-serif italic text-ink-soft text-[1.1rem] max-w-prose leading-relaxed">
                        Everyone who contributes to Vouch Protocol&trade; earns a signed Verified
                        Contributor credential, issued with our own protocol and chained back to the
                        project root authority. The badge is a real Verifiable Credential, not a
                        decorative image: anyone can verify it.
                    </p>
                </header>

                <section className="mb-16 bg-parchment-warm border border-rule p-8 md:p-10">
                    <h2 className="font-serif text-[1.5rem] font-semibold mb-4">The badge</h2>
                    <p className="mb-6 text-ink leading-relaxed">
                        Add it to your profile or site if you would like. It is offered, never forced.
                    </p>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={BADGE_URL} alt="Vouch Verified Contributor" className="mb-6" />
                    <pre className="bg-ink text-parchment text-[0.85rem] p-4 overflow-x-auto">
                        <code>{BADGE_SNIPPET}</code>
                    </pre>
                </section>

                <section className="mb-16">
                    <h2 className="font-serif text-[1.5rem] font-semibold mb-4">How it works</h2>
                    <ul className="list-disc list-outside pl-5 space-y-2 marker:text-burgundy text-ink leading-relaxed">
                        <li>Land your first merged pull request.</li>
                        <li>A signed credential is minted automatically and posted on your PR.</li>
                        <li>
                            It is issued by <code>did:web:vouch-protocol.com:contributors</code> and
                            chained to the root identity <code>did:web:vouch-protocol.com</code>.
                        </li>
                        <li>Verify it any time with the Vouch verifier or the SDK.</li>
                    </ul>
                </section>

                <section>
                    <h2 className="font-serif text-[1.5rem] font-semibold mb-6">Contributors</h2>
                    {CONTRIBUTORS.length === 0 ? (
                        <p className="font-serif italic text-ink-soft leading-relaxed">
                            The first verified contributors will appear here. Want to be one?{' '}
                            <Link
                                href="https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22"
                                className="text-burgundy underline"
                            >
                                Pick up a good first issue
                            </Link>
                            .
                        </p>
                    ) : (
                        <ul className="grid grid-cols-2 md:grid-cols-3 gap-4">
                            {CONTRIBUTORS.map((c) => (
                                <li key={`${c.login}-${c.pr}`} className="bg-parchment-warm border border-rule p-4">
                                    <Link
                                        href={`/c/${c.login}/${c.pr}/`}
                                        className="font-mono text-burgundy no-underline"
                                    >
                                        @{c.login}
                                    </Link>
                                    <p className="text-ink-faint text-[0.85rem] mt-1 leading-snug">
                                        {c.title ? c.title : `PR #${c.pr}`}
                                    </p>
                                </li>
                            ))}
                        </ul>
                    )}
                </section>
            </div>
        </main>
    );
}
