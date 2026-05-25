import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'Support',
  description:
    'How to get help with Vouch Protocol: the Vouch Assistant chat for fast answers, the public-credentials mailing list for specification questions, GitHub Issues for bugs, Discord for community discussion, and a private channel for security disclosure.',
};

const CHANNELS = [
  {
    eyebrow: 'For quick answers',
    title: 'Vouch Assistant',
    body: 'A retrieval-grounded assistant that knows the specification, the SDKs, the conformance levels, and the compliance mappings. Every reply is itself signed by a real Vouch credential. Use the web chat for the fastest path, send an email if you prefer text in your inbox, or run one of the AI-tool packages on your own subscription (Claude Skill, OpenAI Custom GPT, Gemini Gem).',
    cta: { label: 'Open the chat', href: '/ask/' },
    secondary: { label: 'ask@vouch-protocol.com', href: 'mailto:ask@vouch-protocol.com' },
  },
  {
    eyebrow: 'For specification questions',
    title: 'open standards body',
    body: 'The mailing list is the right venue for normative questions about the specification, transition pathways to the VC Working Group, and proposed clarifications.',
    cta: { label: 'public-credentials@w3.org', href: 'mailto:public-credentials@w3.org' },
    secondary: { label: 'Archives', href: '' },
  },
  {
    eyebrow: 'For implementation bugs',
    title: 'GitHub Issues',
    body: 'Bugs in the Python, TypeScript, or Go reference implementations belong on the issue tracker. Include the SDK version, a minimal reproducer, and the cross-language scenario if applicable.',
    cta: { label: 'Open an issue', href: 'https://github.com/vouch-protocol/vouch/issues/new' },
    secondary: { label: 'Browse open issues', href: 'https://github.com/vouch-protocol/vouch/issues' },
  },
  {
    eyebrow: 'For community discussion',
    title: 'Discord',
    body: 'Real-time discussion, quick questions, and integration help. Channels for general discussion, ideas and feedback, dev-discussion, support, and github-activity.',
    cta: { label: 'Join the Discord', href: 'https://discord.gg/mMqx5cG9Y' },
  },
  {
    eyebrow: 'For security disclosures',
    title: 'Private security channel',
    body: 'Do not file public GitHub issues for vulnerabilities. The disclosure process and PGP key are documented in SECURITY.md. The editor will acknowledge within 48 hours and coordinate a disclosure timeline.',
    cta: { label: 'Read SECURITY.md', href: 'https://github.com/vouch-protocol/vouch/blob/main/SECURITY.md' },
  },
];

const QUICK_LINKS = [
  { label: 'Vouch Assistant', href: '/ask/', body: 'Retrieval-grounded chat over the entire knowledge base. Signs every reply.' },
  { label: 'FAQ', href: '/faq/', body: 'Plain-English answers to common questions across every audience.' },
  { label: 'Help & Guides', href: '/help/', body: 'Long-form guides for quickstarts, deployment, and integrations.' },
  { label: 'Specification', href: 'https://github.com/vouch-protocol/vouch/blob/main/docs/specs/specification-executive-summary.md', external: true, body: 'Executive summary of the specification.' },
  { label: 'CHANGELOG', href: 'https://github.com/vouch-protocol/vouch/blob/main/CHANGELOG.md', external: true, body: 'Every version, every shipped feature.' },
];

export default function SupportPage() {
  return (
    <>
      {/* Hero */}
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            How to get help.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            Five channels, each with a clear scope. The Vouch Assistant answers most "how does X work"
            and "give me a sample of Y" questions in seconds; the other four are for normative
            specification questions, implementation bugs, community-level discussion, and security
            disclosures.
          </p>
        </div>
      </section>

      {/* Channels */}
      <section className="border-b border-rule">
        <div className="container-wide py-16">
          <div className="grid md:grid-cols-2 gap-10">
            {CHANNELS.map((channel) => (
              <div key={channel.title} className="border-t-2 border-ink pt-5">
                <div className="eyebrow mb-2">{channel.eyebrow}</div>
                <h2 className="font-serif font-semibold text-[1.4rem] tracking-tight mb-3">
                  {channel.title}
                </h2>
                <p className="text-ink-soft leading-relaxed mb-5">
                  {channel.body}
                </p>
                <div className="flex flex-wrap gap-3">
                  <a
                    href={channel.cta.href}
                    target={channel.cta.href.startsWith('http') ? '_blank' : undefined}
                    rel={channel.cta.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                    className="btn-primary"
                  >
                    {channel.cta.label}
                  </a>
                  {channel.secondary && (
                    <a
                      href={channel.secondary.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-secondary"
                    >
                      {channel.secondary.label}
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* AI-tool packages: same answers on the visitor's own AI subscription */}
      <section className="border-b border-rule">
        <div className="container-wide py-16">
          <div className="section-heading mb-6">
            <span className="num">§ II</span>
            <h2>Run the assistant on your own AI subscription</h2>
          </div>
          <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
            The same canonical Vouch knowledge that powers{' '}
            <Link href="/ask/" className="underline decoration-1 underline-offset-2 hover:text-burgundy">
              the web chat
            </Link>{' '}
            is also packaged for three other AI tools, so you can ask Vouch questions inside the
            interface you already use. These run on{' '}<em>your</em>{' '}plan, not ours.
          </p>
          <div className="grid md:grid-cols-3 gap-6 max-w-prose-wide">
            <a
              href="https://github.com/vouch-protocol/vouch/tree/main/claude-skill"
              target="_blank"
              rel="noopener noreferrer"
              className="block border border-rule p-5 hover:border-burgundy transition-colors no-underline"
            >
              <h3 className="font-serif font-semibold text-[1.1rem] mb-2">Claude Skill</h3>
              <p className="text-ink-soft text-[0.9rem] leading-relaxed">
                Drop the <code className="font-mono text-[0.85em]">claude-skill/</code> folder into{' '}
                <code className="font-mono text-[0.85em]">~/.claude/skills/</code>. Claude Code picks it up automatically.
              </p>
            </a>
            <a
              href="https://github.com/vouch-protocol/vouch/tree/main/openai-gpt"
              target="_blank"
              rel="noopener noreferrer"
              className="block border border-rule p-5 hover:border-burgundy transition-colors no-underline"
            >
              <h3 className="font-serif font-semibold text-[1.1rem] mb-2">OpenAI Custom GPT</h3>
              <p className="text-ink-soft text-[0.9rem] leading-relaxed">
                Paste the configuration from{' '}
                <code className="font-mono text-[0.85em]">openai-gpt/</code> into ChatGPT&apos;s GPT builder.
              </p>
            </a>
            <a
              href="https://github.com/vouch-protocol/vouch/tree/main/gemini-gem"
              target="_blank"
              rel="noopener noreferrer"
              className="block border border-rule p-5 hover:border-burgundy transition-colors no-underline"
            >
              <h3 className="font-serif font-semibold text-[1.1rem] mb-2">Gemini Gem</h3>
              <p className="text-ink-soft text-[0.9rem] leading-relaxed">
                Paste the configuration from{' '}
                <code className="font-mono text-[0.85em]">gemini-gem/</code> into Gemini&apos;s Gem creator.
              </p>
            </a>
          </div>
        </div>
      </section>

      {/* Before opening an issue */}
      <section className="border-b border-rule">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ III</span>
            <h2>Before opening an issue</h2>
          </div>
          <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
            A quick checklist that resolves most of the questions we see:
          </p>
          <ol className="list-decimal list-outside ml-6 space-y-3 text-ink-soft max-w-prose-wide">
            <li>
              <strong>Check the CHANGELOG.</strong> The feature may already have shipped (or been deprecated) in a version
              you do not have. Current release is v1.6.0.
            </li>
            <li>
              <strong>Search the FAQ.</strong> Most cross-language verification mismatches, install failures, and verifier
              rejections have a known cause.
            </li>
            <li>
              <strong>Search closed GitHub issues.</strong> If somebody hit it before, the resolution is usually in the
              issue thread or referenced commit.
            </li>
            <li>
              <strong>Reproduce against the published test vectors.</strong> If a Python-generated test vector verifies in
              your TypeScript or Go code, the bug is probably in your integration; if not, it is probably in the SDK.
            </li>
            <li>
              <strong>Include the version, OS, and the minimal reproducer.</strong> "It fails for me" is not actionable; a
              10-line script that fails is.
            </li>
          </ol>
        </div>
      </section>

      {/* Quick links */}
      <section>
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ IV</span>
            <h2>Quick links</h2>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {QUICK_LINKS.map((link) =>
              link.external ? (
                <a
                  key={link.label}
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block border border-rule p-5 hover:border-burgundy transition-colors no-underline"
                >
                  <h3 className="font-serif font-semibold text-[1.1rem] mb-2">{link.label}</h3>
                  <p className="text-ink-soft text-[0.9rem] leading-relaxed">{link.body}</p>
                </a>
              ) : (
                <Link
                  key={link.label}
                  href={link.href}
                  className="block border border-rule p-5 hover:border-burgundy transition-colors no-underline"
                >
                  <h3 className="font-serif font-semibold text-[1.1rem] mb-2">{link.label}</h3>
                  <p className="text-ink-soft text-[0.9rem] leading-relaxed">{link.body}</p>
                </Link>
              )
            )}
          </div>
        </div>
      </section>
    </>
  );
}
