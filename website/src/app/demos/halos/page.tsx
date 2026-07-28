import type { Metadata } from 'next';

import HalosDemos from './HalosDemos';

export const metadata: Metadata = {
  title: 'Halos safety-evidence interactive demo',
  description:
    'Watch a robot record its Halos safety-event stream into a tamper-evident black-box and sign a HalosSafetyEvidenceCredential, then verify it, tamper with an event, and watch the verifier reject the change. Every value is produced by the Vouch Protocol core in your browser.',
};

export default function HalosDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Halos safety-evidence demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Record what a robot did, and prove it later.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            A safety certification such as NVIDIA Halos shows a robot&apos;s stack is safe by design. It does not record
            what a specific robot actually did. This is the evidence layer that sits underneath it. The robot writes its
            safety-event stream into a tamper-evident encrypted black-box, then signs a credential that seals the black-box
            head and entry count and binds them to its identity and the certified stack it ran on. A verifier confirms the
            record is unaltered, complete, attributable to that robot, and tied to the certified configuration, all without
            the black-box key. The demo below runs that flow live, and every value is produced by the Vouch Protocol core
            in your browser.
          </p>
          <p className="footnote mt-5">
            The credential here is an ordinary
            {' '}<code className="font-mono text-[0.85em]">eddsa-jcs-2022</code> Verifiable Credential, signed and verified
            by the same core that powers every SDK: Python, TypeScript, Go, JVM, .NET, C, and Swift. The keys are throwaway,
            generated in the browser, and never leave it.
          </p>
        </div>
      </section>

      <HalosDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">What you just proved.</strong> A robot on a certified safety stack sealed a
              tamper-evident record of what it did, bound to its identity and the certified configuration. Editing or
              truncating the record makes the verifier reject it, on the cryptography alone, with no network call and no
              access to the encrypted contents. See the{' '}
              <a href="/help/#robotics-halos" className="prose-link">guide</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
