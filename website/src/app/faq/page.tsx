import type { Metadata } from 'next';
import { FAQ_SECTIONS } from './faq-data';
import FAQClient from './FAQClient';

export const metadata: Metadata = {
  title: 'FAQ',
  description:
    'Frequently asked questions about Vouch Protocol: what it is, how it differs from API keys and OAuth, three-language SDK usage, KMS and storage backends, hybrid post-quantum signatures, compliance positioning, and how Vouch composes with the underlying open specifications.',
};

export default function FAQPage() {
  const totalQuestions = FAQ_SECTIONS.reduce((sum, s) => sum + s.items.length, 0);

  return (
    <>
      {/* Hero */}
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Frequently Asked Questions</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Everything that is in the Vouch Protocol repo, in plain English.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            Organized by audience, grouped into {FAQ_SECTIONS.length} sections covering {totalQuestions} questions. Use the
            marginalia at left to jump between sections, or search across the whole page. Every answer that
            cites a feature also points at the specification section, the PAD disclosure, or the shipped
            version where it lives.
          </p>
        </div>
      </section>

      {/* FAQ content */}
      <section>
        <div className="container-wide py-12 md:py-16">
          <FAQClient sections={FAQ_SECTIONS} />
        </div>
      </section>
    </>
  );
}
