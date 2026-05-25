import type { Metadata } from 'next';
import CodeBlock from '@/components/CodeBlock';
import OnboardClient from './OnboardClient';

export const metadata: Metadata = {
  title: 'Onboard',
  description:
    'Six-step adoption path for Vouch Protocol: issuer DID, sidecar tier, allow-list, tool-call wiring, verifier middleware, and heartbeat quorum. Driven by the vouch onboard CLI wizard. Every step can be tried locally first, then graduated to a hosted deployment. Roughly thirty interactive minutes for the credential layer.',
};

export default function OnboardPage() {
  return (
    <>
      {/* Hero */}
      <section className="border-b border-rule">
        <div className="container-wide py-16 md:py-20">
          <div className="eyebrow mb-5">Onboarding</div>
          <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
            Adopt Vouch in six guided steps.
          </h1>
          <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose mb-4">
            The Vouch Protocol paper describes a six-step adoption path. The{' '}
            <code className="font-mono text-[0.95em]">vouch onboard</code> CLI wizard
            walks you through each step, generates the artifacts, and persists your
            progress so an interrupted session resumes where you left off. This page
            mirrors the wizard step-by-step; use it to look before you leap, then run
            the command on your own machine.
          </p>
          <p className="text-ink-soft text-[0.98rem] leading-relaxed max-w-prose mb-8 italic">
            Every step below has a{' '}
            <span className="font-mono uppercase not-italic text-[0.7rem] tracking-[0.14em] text-burgundy">
              Try it locally first
            </span>{' '}
            note so you can prove the loop end-to-end in your dev env, no domain or
            hosting required, before you publish anything. The production command for
            each step is unchanged.
          </p>
          <div className="max-w-prose">
            <CodeBlock code="pip install vouch-protocol && vouch onboard" language="bash" />
          </div>
        </div>
      </section>

      {/* Stepper */}
      <section>
        <div className="container-wide py-12 md:py-16">
          <OnboardClient />
        </div>
      </section>

      {/* What you get */}
      <section className="border-t border-rule">
        <div className="container-wide py-16">
          <div className="section-heading mb-6">
            <span className="num">§ II</span>
            <h2>What the wizard writes</h2>
          </div>
          <p className="text-ink-soft leading-relaxed max-w-prose mb-8">
            Every step emits a real artifact, not a placeholder. The full set is
            ready to drop into your deployment.
          </p>
          <div className="grid md:grid-cols-2 gap-x-12 gap-y-6 max-w-prose-wide">
            <Artifact
              name="did.json"
              body="Standards-aligned did:web document with an Ed25519 verification method. Commit to your domain at /.well-known/did.json."
            />
            <Artifact
              name="~/.vouch/onboarding.json"
              body="Persisted wizard state so you can resume across sessions and machines. Encrypted private key sits next to it in ~/.vouch/keys/."
            />
            <Artifact
              name="vouch-allowlist.json"
              body="The action vocabulary the verifier enforces. Three starter presets cover read-only, scoped read-write, and regulated workloads."
            />
            <Artifact
              name="vouch-toolwire.{py,ts,go}"
              body="Tool-call wrapper for your agent runtime. Intercepts every call, mints a credential against the Sidecar /sign endpoint, attaches it as Vouch-Token."
            />
            <Artifact
              name="vouch-verifier.{py,ts,go}"
              body="Drop-in middleware for FastAPI, Express, or Gin. Verifies the Vouch-Token header and rejects calls whose action is not allow-listed."
            />
            <Artifact
              name="vouch-heartbeat.yaml"
              body="Kubernetes deployment for the heartbeat validator. One replica for standard tier; three for regulated, set automatically."
            />
          </div>
        </div>
      </section>

      {/* Time budget */}
      <section className="border-t border-rule">
        <div className="container-wide py-16">
          <div className="section-heading mb-6">
            <span className="num">§ III</span>
            <h2>Time budget</h2>
          </div>
          <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
            The Vouch Protocol paper estimates one to two engineering days for the
            credential layer and two to four days for state verifiability and
            quorum. The wizard collapses the credential layer into roughly thirty
            interactive minutes by generating every artifact for you; the remaining
            time goes to deploying and integration testing in your own infrastructure.
          </p>
          <dl className="grid sm:grid-cols-3 gap-6 max-w-prose-wide">
            <Stat label="Credential layer" wizard="~30 minutes" hand="1 to 2 days" />
            <Stat label="State verifiability" wizard="~10 minutes" hand="2 to 4 days" />
            <Stat label="Time to first verified request" wizard="under 1 hour" hand="multiple days" />
          </dl>
        </div>
      </section>
    </>
  );
}

function Artifact({ name, body }: { name: string; body: string }) {
  return (
    <div className="border-t border-rule pt-4">
      <code className="font-mono text-[0.95rem] text-burgundy">{name}</code>
      <p className="text-ink-soft leading-relaxed mt-2">{body}</p>
    </div>
  );
}

function Stat({ label, wizard, hand }: { label: string; wizard: string; hand: string }) {
  return (
    <div className="border-t-2 border-ink pt-3">
      <dt className="eyebrow mb-2">{label}</dt>
      <dd className="space-y-1">
        <div>
          <span className="font-mono text-[0.7rem] uppercase tracking-[0.14em] text-ink-soft mr-2">
            Wizard
          </span>
          <span className="font-serif font-semibold text-ink">{wizard}</span>
        </div>
        <div>
          <span className="font-mono text-[0.7rem] uppercase tracking-[0.14em] text-ink-soft mr-2">
            By hand
          </span>
          <span className="text-ink-soft">{hand}</span>
        </div>
      </dd>
    </div>
  );
}
