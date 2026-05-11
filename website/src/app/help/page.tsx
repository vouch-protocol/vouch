import type { Metadata } from 'next';
import { HELP_SECTIONS } from './help-data';
import HelpClient from './HelpClient';

export const metadata: Metadata = {
    title: 'Help & Guides',
    description:
        'Long-form guides for Vouch Protocol: quickstarts in Python, TypeScript, and Go; key management; hybrid post-quantum signing; delegation chains; sidecar deployment; KMS integration; reputation and revocation; framework integrations; CLI reference.',
};

export default function HelpPage() {
    const totalArticles = HELP_SECTIONS.reduce((sum, s) => sum + s.articles.length, 0);

    return (
        <>
            {/* Hero */}
            <section className="border-b border-rule">
                <div className="container-wide py-16 md:py-20">
                    <div className="eyebrow mb-5">Help &amp; Guides</div>
                    <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
                        Long-form guides for getting Vouch into production.
                    </h1>
                    <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
                        {HELP_SECTIONS.length} parts covering {totalArticles} guides: quickstarts in three languages,
                        identity and key management, the hybrid post-quantum profile, delegation chains, sidecar
                        deployment, KMS integration, reputation and revocation engines, framework integrations, and the
                        complete CLI reference. Use the marginalia at left to navigate, or search across every guide.
                    </p>
                </div>
            </section>

            {/* Help content */}
            <section>
                <div className="container-wide py-12 md:py-16">
                    <HelpClient sections={HELP_SECTIONS} />
                </div>
            </section>
        </>
    );
}
