import type { Metadata } from 'next';

import RootOfTrustDemos from './RootOfTrustDemos';

export const metadata: Metadata = {
  title: 'Root of Trust interactive demo',
  description:
    'Watch a machine-identity chain of trust verify in the browser: a root identity recognizes an issuer, the issuer binds an agent to its attributes, and a verifier that pins only the root DID accepts the honest chain and rejects a forged one. Every signature is a real eddsa-jcs-2022 proof produced by the Vouch Protocol core.',
};

export default function RootOfTrustDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Root of Trust demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Trust one key, verify the rest.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            Machine identity works when you have to trust exactly one thing. A single root is anchored once, it recognizes
            an issuer for a specific action, and that issuer binds an agent to its owner, model, and capabilities. A
            verifier that pins only the root DID can then check the whole chain offline, accept a genuine agent, and reject
            an impostor whose recognition comes from a root it never trusted. The demo below runs that chain live, and
            every signature is produced by the Vouch Protocol core in your browser.
          </p>
          <p className="footnote mt-5">
            The credentials here are ordinary
            {' '}<code className="font-mono text-[0.85em]">eddsa-jcs-2022</code> Verifiable Credentials, signed and verified
            by the same core that powers every SDK: Python, TypeScript, Go, JVM, .NET, C, and Swift. The keys are throwaway,
            generated in the browser, and never leave it.
          </p>
        </div>
      </section>

      <RootOfTrustDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">What you just proved.</strong> Pinning one root key, you verified that a real
              agent identity chains back to it through a recognized issuer, and that a forged recognition signed by a
              different root is rejected on the cryptography alone, with no network call and no policy server. See the{' '}
              <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
