import type { Metadata } from 'next';

import RoboticsDemos from './RoboticsDemos';

export const metadata: Metadata = {
  title: 'Robotics interactive demos',
  description:
    'See Vouch Protocol robotics controls run in the browser: a robot that opens a door with a grant the door authorizes offline, a fused world model bound to the exact sensor frames that made it, a worn robot that narrows its own force and speed envelope as it degrades, and bystander consent bound to a single capture so it cannot be replayed.',
};

export default function RoboticsDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Robotics demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Watch a robot stay in bounds.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            A robot acts in the physical world, so the questions get sharper: what is it allowed to touch, is the world it
            sees real, and is it still fit to do the job. Vouch answers each with a credential the robot or the resource
            can check on the spot. Four of them run below, on the real credential shapes.
          </p>
          <p className="footnote mt-5">
            Every verdict here mirrors the shipped SDK modules
            {' '}<code className="font-mono text-[0.85em]">vouch.robotics.access</code>,
            {' '}<code className="font-mono text-[0.85em]">vouch.robotics.fusion</code>,
            {' '}<code className="font-mono text-[0.85em]">vouch.robotics.wear</code>, and
            {' '}<code className="font-mono text-[0.85em]">vouch.robotics.consent</code>. Disclosed as PAD-087 through PAD-094.
          </p>
        </div>
      </section>

      <RoboticsDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">Build it yourself.</strong> Each demo maps to the same functions the SDK ships
              in Python, TypeScript, Go, and the Rust core:
              {' '}<code className="font-mono text-[0.85em]">authorize_access</code>,
              {' '}<code className="font-mono text-[0.85em]">verify_fused_attestation</code>,
              {' '}<code className="font-mono text-[0.85em]">attenuate_for_wear</code>, and
              {' '}<code className="font-mono text-[0.85em]">verify_consent_evidence</code>. See the{' '}
              <a href="/robotics/" className="prose-link">robotics overview</a> and the{' '}
              <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
