import type { Metadata } from 'next';
import DemosClient from './DemosClient';

export const metadata: Metadata = {
  title: 'Interactive demos',
  description:
    'See Vouch Protocol’s accountable-autonomy controls run in the browser: an agent that must state why before it acts, an irreversible action you can veto during a live challenge window, and a delegation chain whose caveats block an out-of-envelope action two hops down.',
};

export default function DemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Interactive demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Watch an agent get stopped.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            You can&apos;t read an AI agent&apos;s mind, and you can&apos;t pre-approve every action it invents. So Vouch does
            what every institution has always done with authorized actors: it makes each action state its reason, slows
            down the irreversible ones, and keeps a veto. All three run below, on real credential shapes.
          </p>
          <p className="footnote mt-5">
            Every verdict here mirrors the shipped SDK modules
            {' '}<code className="font-mono text-[0.85em]">vouch.reasoning</code>,
            {' '}<code className="font-mono text-[0.85em]">vouch.deliberation</code>, and
            {' '}<code className="font-mono text-[0.85em]">vouch.caveats</code>, and
            {' '}<code className="font-mono text-[0.85em]">vouch.provenance</code>. Disclosed as PAD-043, PAD-045, PAD-085, and PAD-086.
          </p>
        </div>
      </section>

      <DemosClient />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">Run it yourself.</strong> Each demo maps to a runnable example in the repo:
              {' '}<code className="font-mono text-[0.85em]">examples/reasoned_action_demo.py</code>,
              {' '}<code className="font-mono text-[0.85em]">examples/deliberation_demo.py</code>, and
              {' '}<code className="font-mono text-[0.85em]">examples/caveats_demo.py</code>. See the{' '}
              <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
