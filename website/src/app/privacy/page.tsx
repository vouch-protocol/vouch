import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Privacy — Vouch Protocol',
    description:
        'What Vouch Protocol logs, what it does not, and what you can do about it. Plain English. No dark patterns.',
};

export default function PrivacyPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="max-w-prose mx-auto px-6 py-16 md:py-24 leading-relaxed">
                <p className="eyebrow text-burgundy mb-3">Plain English</p>
                <h1 className="font-serif text-[2.2rem] md:text-[2.6rem] leading-tight tracking-tight mb-4">
                    Privacy
                </h1>
                <p className="font-serif italic text-ink-soft text-[1.05rem] mb-10">
                    What we collect, why, for how long, and what you can do about it. If anything below is unclear,
                    email{' '}
                    <a className="text-burgundy" href="mailto:privacy@vouch-protocol.com">privacy@vouch-protocol.com</a>.
                </p>

                <Section title="What we run">
                    <p>
                        Vouch Protocol&trade; is an open-source specification and reference implementation. The
                        software is Apache 2.0; the protocol is W3C-track. When you visit vouch-protocol.com, you&apos;re
                        looking at our marketing and documentation surface plus an AI assistant. Three surfaces
                        collect data:
                    </p>
                    <ul>
                        <li><strong>The website itself</strong> (static pages): no analytics, no cookies, no tracking pixels.</li>
                        <li><strong>The Vouch Assistant chat</strong> (the panel at <code>/ask</code> and the floating widget): logs as described below.</li>
                        <li><strong>The email assistant</strong> (replies to <code>ask@vouch-protocol.com</code>): processes your message via Gemini and replies via Resend.</li>
                    </ul>
                </Section>

                <Section title="What the chat assistant logs">
                    <p>
                        Every conversation with the chat assistant is logged. Each row contains:
                    </p>
                    <ul>
                        <li>Your question text and the assistant&apos;s reply text</li>
                        <li>A timestamp (UTC, second precision)</li>
                        <li>The retrieval sources we used to answer</li>
                        <li>Your IP address, <strong>truncated to /24 (IPv4) or /48 (IPv6)</strong>, so we keep coarse geography but lose the last octet that identifies an individual subscriber</li>
                        <li>A two-letter country code (we get this from our upstream proxy)</li>
                        <li>Your browser&apos;s User-Agent string, truncated to 240 characters</li>
                        <li>Your feedback rating (▲ / ▼) and optional comment, if you provide one</li>
                    </ul>
                    <p>
                        We do not log: cookies, session tokens, authentication bearers, account identifiers, full IP
                        addresses, fingerprints derived from beyond the listed fields, or anything we don&apos;t list above.
                    </p>
                </Section>

                <Section title="Why we log it">
                    <p>
                        The single purpose is <strong>quality improvement</strong> — finding questions we answer
                        poorly, mis-cited sources, prompts that confuse the assistant. The IP-truncation + country
                        code lets us tell <em>roughly</em> where confusion originates (a regulated industry in
                        country X, a developer community in country Y) without identifying individuals. We do not
                        sell this data, share it with third parties, or use it for advertising. We do not have ads.
                    </p>
                </Section>

                <Section title="What the email assistant logs">
                    <p>
                        Email replies to <code>ask@vouch-protocol.com</code> go through Cloudflare Email Routing &rarr;
                        a Cloudflare Worker &rarr; Gemini &rarr; Resend. The Worker keeps minimal logs: the inbound
                        address, the response code from Gemini and Resend, the timestamp. The full email body is
                        not persisted by us; it&apos;s passed in-memory to Gemini for response generation and to
                        Resend for delivery, both of which apply their own retention policies.
                    </p>
                    <p>
                        A copy of every inbound email is forwarded to <code>ram@vouch-protocol.com</code> for the
                        maintainer&apos;s visibility — this is so we can spot misclassified questions and improve.
                    </p>
                </Section>

                <Section title="Third parties that touch your data">
                    <ul>
                        <li><strong>Google (Gemini API)</strong> — processes your question to generate a reply. Subject to <a className="text-burgundy" href="https://ai.google.dev/gemini-api/terms">Gemini API terms</a>. We use the free tier; queries may be used by Google to improve their models per Google&apos;s policy.</li>
                        <li><strong>Cloudflare</strong> — routes traffic, runs the email worker, terminates TLS. Standard Cloudflare data-handling.</li>
                        <li><strong>Fly.io</strong> — hosts the chat assistant backend in Mumbai. Standard Fly data-handling.</li>
                        <li><strong>Resend</strong> — sends email replies. Subject to <a className="text-burgundy" href="https://resend.com/legal/privacy-policy">Resend privacy policy</a>.</li>
                        <li><strong>GitHub Pages</strong> — serves the static parts of this website.</li>
                    </ul>
                </Section>

                <Section title="How long we keep things">
                    <ul>
                        <li>Chat interaction logs: indefinitely while we are actively maintaining the assistant; we will purge logs older than 24 months on a rolling basis once the protocol stabilises</li>
                        <li>Email worker logs: 30 days, then Cloudflare expires them</li>
                        <li>Vouch credentials we publish at <code>vch.sh/&lt;id&gt;</code>: as long as you (the creator) request, up to the free-tier expiry (1 year) or indefinitely for Pro-tier credentials</li>
                    </ul>
                </Section>

                <Section title="Your rights">
                    <p>
                        You can:
                    </p>
                    <ul>
                        <li><strong>Request your data</strong>: email <a className="text-burgundy" href="mailto:privacy@vouch-protocol.com">privacy@vouch-protocol.com</a>. We can&apos;t look up a specific person without an identifier you provide, but if you tell us a session ID, IP prefix, or approximate timestamp, we can return what&apos;s in our logs.</li>
                        <li><strong>Request deletion</strong>: same address. We delete on next request and confirm.</li>
                        <li><strong>Skip the chat</strong>: every page on this site reads fine without it. The chat is optional.</li>
                        <li><strong>Verify our claims</strong>: the source code is at <a className="text-burgundy" href="https://github.com/vouch-protocol/vouch">github.com/vouch-protocol/vouch</a>. The logging logic is in <code>website-agent/backend/vouch_agent/interactions.py</code> and is open for inspection.</li>
                    </ul>
                </Section>

                <Section title="Children">
                    <p>
                        Vouch Protocol is a technical specification for developers and AI agent operators. We do not
                        target the service at children under 16 and do not knowingly collect data from them. If you
                        believe a child has used the service, email <a className="text-burgundy" href="mailto:privacy@vouch-protocol.com">privacy@vouch-protocol.com</a>{' '}
                        and we will delete their logs.
                    </p>
                </Section>

                <Section title="Jurisdiction">
                    <p>
                        The maintainer is based in India. Data is processed in:
                        Mumbai (Fly.io), Cloudflare&apos;s global network (Workers, KV), the EU/US (Resend), and Google&apos;s
                        US infrastructure (Gemini). If you&apos;re in the EU, the GDPR rights summarised above apply; see also{' '}
                        <Link className="text-burgundy" href="/compliance/gdpr">our GDPR mapping</Link> for how the protocol
                        layer addresses specific articles.
                    </p>
                </Section>

                <Section title="Changes">
                    <p>
                        We&apos;ll update this page when our practices change. For material changes, we&apos;ll also
                        publish a note in the blog and (if you&apos;ve given us your email) drop you a line. Last
                        substantive update: 2026-05-22.
                    </p>
                </Section>

                <footer className="mt-12 pt-6 border-t border-rule text-[0.85rem] text-ink-faint">
                    Questions? <a className="text-burgundy" href="mailto:privacy@vouch-protocol.com">privacy@vouch-protocol.com</a>{' '}
                    or open an issue at{' '}
                    <a className="text-burgundy" href="https://github.com/vouch-protocol/vouch/issues">github.com/vouch-protocol/vouch/issues</a>.
                </footer>
            </div>
        </main>
    );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <section className="my-8 space-y-3">
            <h2 className="font-serif text-[1.4rem] font-semibold tracking-tight mb-2">{title}</h2>
            <div className="prose prose-stone text-ink leading-relaxed [&_a]:no-underline [&_a]:border-b [&_a]:border-current [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1 [&_code]:font-mono [&_code]:text-[0.88em] [&_code]:bg-parchment-warm [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm">
                {children}
            </div>
        </section>
    );
}
