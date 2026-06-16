import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'Support',
  description:
    'How to get help with Vouch Protocol: the Vouch Assistant chat, the FAQ and guides for self-serve answers, GitHub Issues for bugs, Discord for community discussion, and the public-credentials mailing list for specification questions.',
};

type Channel = {
  eyebrow: string;
  title: string;
  body: string;
  cta: { label: string; href: string };
  secondary?: { label: string; href: string };
};

// Start here: the three self-serve surfaces, Assistant first.
const PRIMARY: Channel[] = [
  {
    eyebrow: 'For quick answers',
    title: 'Vouch Assistant',
    body: 'A retrieval-grounded assistant that knows the specification, the SDKs, the conformance levels, and the compliance mappings. Every reply is itself signed by a real Vouch credential. Use the web chat for the fastest path, or send an email if you prefer text in your inbox.',
    cta: { label: 'Open the chat', href: '/ask/' },
    secondary: { label: 'ask@vouch-protocol.com', href: 'mailto:ask@vouch-protocol.com' },
  },
  {
    eyebrow: 'For common questions',
    title: 'FAQ',
    body: 'Plain-English answers to the questions we hear most, grouped by audience: developers, robots and embodied agents, businesses, and the simply curious.',
    cta: { label: 'Read the FAQ', href: '/faq/' },
  },
  {
    eyebrow: 'For step-by-step help',
    title: 'Help & Guides',
    body: 'Long-form guides for quickstarts, deployment, cross-language verification, robotics, and integrations, each with runnable code.',
    cta: { label: 'Open the guides', href: '/help/' },
  },
];

// The other channels, in order. The standards mailing list comes last.
const CHANNELS: Channel[] = [
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
    eyebrow: 'For specification questions',
    title: 'Standards mailing list',
    body: 'The public-credentials list is the venue for normative questions about the specification, transition pathways to the VC Working Group, and proposed clarifications.',
    cta: { label: 'public-credentials@w3.org', href: 'mailto:public-credentials@w3.org' },
  },
];

const QUICK_LINKS = [
  { label: 'Specification', href: 'https://github.com/vouch-protocol/vouch/blob/main/docs/specs/specification-executive-summary.md', external: true, body: 'Executive summary of the specification.' },
  { label: 'CHANGELOG', href: 'https://github.com/vouch-protocol/vouch/blob/main/CHANGELOG.md', external: true, body: 'Every version, every shipped feature.' },
  { label: 'Test vectors', href: 'https://github.com/vouch-protocol/vouch/tree/main/test-vectors', external: true, body: 'Cross-language vectors to check your implementation against.' },
  { label: 'GitHub repository', href: 'https://github.com/vouch-protocol/vouch', external: true, body: 'Source, SDKs, and reference implementations.' },
];

function ChannelCard({ channel }: { channel: Channel }) {
  return (
    <div className="border-t-2 border-ink pt-5">
      <div className="eyebrow mb-2">{channel.eyebrow}</div>
      <h2 className="font-serif font-semibold text-[1.4rem] tracking-tight mb-3">{channel.title}</h2>
      <p className="text-ink-soft leading-relaxed mb-5">{channel.body}</p>
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
  );
}

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
            Start with the Assistant, the FAQ, or the guides. They answer most questions in seconds.
            For everything else there is the issue tracker, Discord, and the specification mailing list.
          </p>
        </div>
      </section>

      {/* Start here */}
      <section className="border-b border-rule">
        <div className="container-wide py-16">
          <div className="section-heading mb-8">
            <span className="num">§ I</span>
            <h2>Start here</h2>
          </div>
          <div className="grid md:grid-cols-3 gap-10">
            {PRIMARY.map((channel) => (
              <ChannelCard key={channel.title} channel={channel} />
            ))}
          </div>
        </div>
      </section>

      {/* Other channels */}
      <section className="border-b border-rule">
        <div className="container-wide py-16">
          <div className="section-heading mb-8">
            <span className="num">§ II</span>
            <h2>Other channels</h2>
          </div>
          <div className="grid md:grid-cols-3 gap-10">
            {CHANNELS.map((channel) => (
              <ChannelCard key={channel.title} channel={channel} />
            ))}
          </div>
          {/* Security disclosure: a slim callout, not a channel of its own. */}
          <div className="mt-10 border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">Security disclosure.</strong> Please do not file a public GitHub
              issue for a vulnerability. Follow the coordinated process and PGP key in{' '}
              <a
                href="https://github.com/vouch-protocol/vouch/blob/main/SECURITY.md"
                target="_blank"
                rel="noopener noreferrer"
                className="underline decoration-1 underline-offset-2 hover:text-burgundy"
              >
                SECURITY.md
              </a>
              . The editor acknowledges within 48 hours and coordinates a disclosure timeline.
            </p>
          </div>
        </div>
      </section>

      {/* AI-tool packages: same answers inside the visitor's own assistant */}
      <section className="border-b border-rule">
        <div className="container-wide py-16">
          <div className="section-heading mb-6">
            <span className="num">§ III</span>
            <h2>Run it within your own favourite vibe-coding assistant</h2>
          </div>
          <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
            The same canonical Vouch knowledge that powers{' '}
            <Link href="/ask/" className="underline decoration-1 underline-offset-2 hover:text-burgundy">
              the web chat
            </Link>{' '}
            is also packaged for three other AI tools, so you can ask Vouch questions inside the
            vibe-coding assistant you already use. These run on{' '}<em>your</em>{' '}plan, not ours.
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
            <span className="num">§ IV</span>
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
            <span className="num">§ V</span>
            <h2>Quick links</h2>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {QUICK_LINKS.map((link) => (
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
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
