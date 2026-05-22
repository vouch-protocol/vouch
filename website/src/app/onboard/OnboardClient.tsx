'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import CodeBlock from '@/components/CodeBlock';
import { ONBOARD_STEPS } from './onboard-data';

const STORAGE_KEY = 'vouch-onboard-cursor';

/**
 * Six-step adoption path stepper. State (current step + completed set) is
 * held locally in useState and mirrored to localStorage so a returning
 * visitor lands on the step they were last reading. Nothing is sent to
 * the server; the page is purely educational.
 */
export default function OnboardClient() {
  const [cursor, setCursor] = useState(0);
  const [completed, setCompleted] = useState<Set<number>>(new Set());

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (typeof parsed.cursor === 'number' && Array.isArray(parsed.completed)) {
          setCursor(Math.min(parsed.cursor, ONBOARD_STEPS.length - 1));
          setCompleted(new Set(parsed.completed));
        }
      }
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ cursor, completed: Array.from(completed) }),
      );
    } catch {
      /* ignore */
    }
  }, [cursor, completed]);

  const step = ONBOARD_STEPS[cursor];
  const isLast = cursor === ONBOARD_STEPS.length - 1;
  const isFirst = cursor === 0;
  const allDone = completed.size === ONBOARD_STEPS.length;

  function markDoneAndAdvance() {
    setCompleted((prev) => new Set(prev).add(step.num));
    if (!isLast) setCursor(cursor + 1);
  }

  function reset() {
    setCursor(0);
    setCompleted(new Set());
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="grid lg:grid-cols-[220px_1fr] gap-10 lg:gap-16">
      {/* Stepper rail */}
      <nav aria-label="Onboarding steps" className="lg:sticky lg:top-24 lg:self-start">
        <ol className="space-y-1">
          {ONBOARD_STEPS.map((s, i) => {
            const done = completed.has(s.num);
            const current = i === cursor;
            return (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => setCursor(i)}
                  className={`w-full text-left flex items-baseline gap-3 py-2 px-3 border-l-2 transition-colors ${
                    current
                      ? 'border-burgundy text-ink bg-parchment-warm'
                      : done
                      ? 'border-burgundy-light text-ink hover:text-burgundy'
                      : 'border-rule text-ink-soft hover:text-ink hover:border-ink-soft'
                  }`}
                >
                  <span className="font-mono text-[0.7rem] tabular-nums w-5">
                    {done ? '✓' : s.num}
                  </span>
                  <span className="font-mono uppercase text-[0.7rem] tracking-[0.12em]">
                    {s.short}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
        <div className="mt-6 px-3">
          <div className="font-mono uppercase text-[0.62rem] tracking-[0.16em] text-ink-soft mb-1">
            Progress
          </div>
          <div className="h-1.5 bg-rule overflow-hidden">
            <div
              className="h-full bg-burgundy transition-all"
              style={{ width: `${(completed.size / ONBOARD_STEPS.length) * 100}%` }}
            />
          </div>
          <div className="mt-1 font-mono text-[0.7rem] tabular-nums text-ink-soft">
            {completed.size} of {ONBOARD_STEPS.length} complete
          </div>
        </div>
      </nav>

      {/* Step body */}
      <article>
        <div className="eyebrow mb-3">
          Step {step.num} of {ONBOARD_STEPS.length} . {step.eta}
        </div>
        <h2 className="font-serif font-semibold text-ink leading-tight tracking-tight mb-5 text-[clamp(1.6rem,3.2vw,2.2rem)]">
          {step.title}
        </h2>
        <p className="text-ink-soft text-[1.02rem] leading-relaxed max-w-prose mb-8">
          {step.blurb}
        </p>

        <div className="mb-8">
          <div className="font-mono uppercase text-[0.62rem] tracking-[0.16em] text-ink-soft mb-2">
            Run
          </div>
          <CodeBlock code={step.command} language="bash" />
        </div>

        <div className="mb-10">
          <div className="font-mono uppercase text-[0.62rem] tracking-[0.16em] text-ink-soft mb-2">
            Artifact: <span className="text-ink normal-case font-medium">{step.artifact}</span>
          </div>
          <CodeBlock code={step.preview} language={step.previewLanguage} />
        </div>

        {/* Step navigation */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-t border-rule pt-6">
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => !isFirst && setCursor(cursor - 1)}
              disabled={isFirst}
              className="btn-secondary disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={markDoneAndAdvance}
              className="btn-primary"
            >
              {isLast ? 'Mark done' : 'Mark done and continue'}
            </button>
          </div>
          {completed.size > 0 && (
            <button
              type="button"
              onClick={reset}
              className="font-mono uppercase text-[0.7rem] tracking-[0.14em] text-ink-soft hover:text-burgundy"
            >
              Reset progress
            </button>
          )}
        </div>

        {/* All-done banner */}
        {allDone && (
          <div className="mt-10 border-t-2 border-burgundy pt-5">
            <div className="eyebrow text-burgundy mb-2">All six steps complete</div>
            <h3 className="font-serif font-semibold text-ink text-[1.4rem] tracking-tight mb-3">
              You have a deployable adoption set.
            </h3>
            <p className="text-ink-soft leading-relaxed mb-5 max-w-prose">
              Commit <code className="font-mono text-[0.95em]">did.json</code> to your domain at{' '}
              <code className="font-mono text-[0.95em]">/.well-known/did.json</code>, drop the
              tool-call wrapper into your agent runtime, mount the verifier middleware at
              your API boundary, and bring up the heartbeat validator. The corresponding CLI
              command on your machine writes every file you just previewed.
            </p>
            <div className="flex flex-wrap gap-3">
              <a
                href="https://github.com/vouch-protocol/vouch/blob/main/docs/onboarding-wizard-spec.md"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-primary"
              >
                Read the wizard spec
              </a>
              <Link href="/help/" className="btn-secondary">
                Long-form guides
              </Link>
              <Link href="/support/" className="btn-secondary">
                Get help
              </Link>
            </div>
          </div>
        )}
      </article>
    </div>
  );
}
