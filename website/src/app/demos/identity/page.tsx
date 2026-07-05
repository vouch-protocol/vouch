import type { Metadata } from 'next';

import IdentityDemos from './IdentityDemos';

export const metadata: Metadata = {
  title: 'Identity interactive demos',
  description:
    'See Vouch Protocol cross-device identity controls run in the browser: a device that acts on a delegated grant and gets revoked when lost, a root identity rebuilt from a threshold of Shamir shares, and a signature produced by any threshold of custodians without the full key ever existing whole.',
};

export default function IdentityDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Identity demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Watch a key stay out of reach.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            A private key is the one thing that should never move. Vouch keeps it in place three ways: each device signs
            with a key it minted itself, a lost root rebuilds from shares that reveal nothing below their threshold, and a
            group of custodians can sign together without any one of them ever holding the whole key. All three run below,
            on the real credential shapes.
          </p>
          <p className="footnote mt-5">
            Every verdict here mirrors the shipped SDK modules
            {' '}<code className="font-mono text-[0.85em]">vouch.fleet</code>,
            {' '}<code className="font-mono text-[0.85em]">vouch.recovery</code>, and
            {' '}<code className="font-mono text-[0.85em]">vouch.threshold</code>. Available in every SDK: Python,
            TypeScript, Go, JVM, .NET, C, and Swift.
          </p>
        </div>
      </section>

      <IdentityDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">Run it yourself.</strong> Each demo maps to a runnable path in the reference
              docs:
              {' '}<code className="font-mono text-[0.85em]">docs/cross-device-identity.md</code> and
              {' '}<code className="font-mono text-[0.85em]">docs/threshold-signing.md</code>. See the{' '}
              <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
