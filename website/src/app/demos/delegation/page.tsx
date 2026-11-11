import type { Metadata } from 'next';

import DelegationDemos from './DelegationDemos';

export const metadata: Metadata = {
  title: 'Delegation chain interactive demo',
  description:
    'Watch a delegation chain verify in the browser: Alice grants an assistant read and update with a spend cap, the assistant passes a narrower grant to a sub-agent, and every attempt to go beyond a grant is refused with a reason. Every signature is a real eddsa-jcs-2022 proof checked by the Vouch Protocol core.',
};

export default function DelegationDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Delegation demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            A grant can only get smaller.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            When an agent hands work to another agent, the second one should never end up with more authority than the one
            that handed it work. Each grant here is signed and travels inside the credential, so the verifier can check every step of
            the chain without calling anyone. A step that adds an action, raises a cap, or stretches the time window is
            refused, and so is a grant that was edited or signed by the wrong key. Pick a case below and watch the
            verdict come back.
          </p>
          <p className="footnote mt-5">
            The credentials are ordinary <code className="font-mono text-[0.85em]">eddsa-jcs-2022</code> Verifiable
            Credentials, checked by the same core that powers every SDK: Python, TypeScript, Go, JVM, .NET, C, and
            Swift. The same story runs from the command line in
            {' '}<code className="font-mono text-[0.85em]">examples/ccg_demo/01_delegation.py</code>.
          </p>
        </div>
      </section>

      <DelegationDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">What you just proved.</strong> You checked, with real signatures and no
              network call, that the sub-agent&apos;s allowed actions trace back to Alice, that nothing above its grant
              went through, and that an edited or forged parent grant fails on the cryptography alone. See the{' '}
              <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
