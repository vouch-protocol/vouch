import type { Metadata } from 'next';

import TransparencyDemos from './TransparencyDemos';

export const metadata: Metadata = {
  title: 'AI transparency marking interactive demo',
  description:
    'Mark an AI agent output with a machine-readable, cryptographically signed disclosure of its AI origin, verify it live in the browser with the Vouch Protocol WebAssembly core, and watch verification fail when a single character of the text changes.',
};

export default function TransparencyDemosPage() {
  return (
    <>
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Support · Transparency demos</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Watch an output declare its origin.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
            Readers, platforms, and regulators all ask the same question about a piece of text: did an AI produce this?
            Vouch Protocol answers with a signed disclosure that travels with the content. The agent states, in a
            machine-readable credential, that the output is AI generated, who signed that statement, and when. Anyone
            can verify it offline, and the moment the text changes, verification fails. The demo below runs the real
            cryptography in your browser: the agent key is a throwaway generated on this page, and every signature and
            verdict comes from a live call into the Vouch Protocol core compiled to WebAssembly.
          </p>
          <p className="footnote mt-5">
            EU AI Act transparency obligations apply from August 2, 2026, and machine-readable marking of AI-generated
            content applies from December 2, 2026. What you see here is that kind of marking: a machine-readable
            disclosure, signed with the{' '}
            <code className="font-mono text-[0.85em]">eddsa-jcs-2022</code> Data Integrity cryptosuite over a{' '}
            <code className="font-mono text-[0.85em]">did:key</code> identity.
          </p>
        </div>
      </section>

      <TransparencyDemos />

      <section>
        <div className="container-wide py-16">
          <div className="border-l-2 border-burgundy bg-burgundy/[0.03] px-5 py-4 max-w-prose-wide">
            <p className="text-ink-soft text-[0.95rem] leading-relaxed">
              <strong className="text-ink">Run it yourself.</strong> This page calls the published WebAssembly package
              {' '}<code className="font-mono text-[0.85em]">@vouch-protocol-official/core-wasm</code> directly:
              {' '}<code className="font-mono text-[0.85em]">generateEd25519</code>,
              {' '}<code className="font-mono text-[0.85em]">sign</code>, and
              {' '}<code className="font-mono text-[0.85em]">verifyProof</code>. The same functions ship in every Vouch
              Protocol SDK. See the <a href="/help/" className="prose-link">guides</a> for the full walkthrough.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
