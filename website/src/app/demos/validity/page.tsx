import type { Metadata } from 'next';

import ValidityDemos from './ValidityDemos';

export const metadata: Metadata = {
  title: 'Credential validity interactive demo',
  description:
    'Choose how long a signed credential lasts and watch it stop working when its time is up. An agent asks its sidecar for a duration, the sidecar applies a default and a ceiling, and a verifier checks the result at a time you pick. Every credential is signed and checked in your browser by the Vouch Protocol core.',
};

export default function ValidityDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Validity demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            A signature that runs out on time.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            A credential says what an agent is about to do, and for how long that statement holds. The agent picks the
            length each time it asks for a signature. Whoever runs the sidecar sets a default for requests that name no
            length, and a ceiling no request can go past. Once the time is up, every verifier refuses the credential,
            and nobody can stretch it without the key. Pick a request below, change the settings, move the
            verifier&apos;s clock, and watch the verdict come back.
          </p>
          <p className="footnote mt-5">
            The credentials are ordinary <code className="font-mono text-[0.85em]">eddsa-jcs-2022</code> Verifiable
            Credentials, checked by the same core that powers every SDK. The same limits run on your own machine with{' '}
            <code className="font-mono text-[0.85em]">vouch sidecar --default-validity 5m --max-validity 1h</code>, and a
            caller picks the length by sending <code className="font-mono text-[0.85em]">validSeconds</code>. When you
            sign directly, without a sidecar, <code className="font-mono text-[0.85em]">vouch sign --valid-for</code>{' '}
            sets the length.
          </p>
        </div>
      </section>

      <ValidityDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">What you just proved.</strong> You signed credentials with a key made in
              your browser, saw the sidecar hold each one to its default and its ceiling, and checked with a real
              verifier that a credential stops being accepted when its time is up and that editing its end time breaks
              the signature. See the <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
