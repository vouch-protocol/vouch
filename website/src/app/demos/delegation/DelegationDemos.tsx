'use client';

import React, { useEffect, useMemo, useState } from 'react';

import styles from './DelegationDemos.module.css';
import { tamperRootGrant, verifyAction, type Core, type Verdict } from './chain';
import fixtures from './fixtures.json';

/**
 * Interactive demo for delegation chains and the non-expansion rule. The
 * credentials come from fixtures.json (written by generate_fixtures.py with
 * fresh throwaway keys). Every verdict on the page is computed live in the
 * browser by the Vouch Protocol core compiled to WebAssembly: grant signatures,
 * did:key resolution, the non-expansion rule, and the holder's own proof.
 * Burgundy doubles as refuse, a parchment-harmonized green marks allow, and
 * both read on either theme.
 */

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

/* ------------------------------------------------------------------ */
/* WASM core loader, same approach as the other live-crypto demos.       */
/* ------------------------------------------------------------------ */

let corePromise: Promise<Core> | null = null;

function loadCore(): Promise<Core> {
  if (!corePromise) {
    corePromise = (async () => {
      const dynamicImport = new Function('u', 'return import(u)') as (u: string) => Promise<Record<string, unknown>>;
      const mod = await dynamicImport('/wasm/vouch_core_wasm.js');
      await (mod.default as () => Promise<unknown>)();
      return mod as unknown as Core;
    })();
  }
  return corePromise;
}

/* ------------------------------------------------------------------ */

type Fixture = (typeof fixtures)['cases'][number];

const NAMES: Record<string, string> = {
  [fixtures.parties.alice]: 'Alice',
  [fixtures.parties.assistant]: 'assistant',
  [fixtures.parties.subAgent]: 'sub-agent',
  [fixtures.parties.grandchild]: 'grandchild',
  [fixtures.parties.mallory]: 'Mallory',
};

const who = (did: string) => NAMES[did] ?? `${did.slice(0, 16)}…`;
const short = (did: string) => `${did.slice(0, 16)}…${did.slice(-6)}`;

const GROUPS: Array<{ title: string; ids: string[] }> = [
  { title: 'The sub-agent acts', ids: ['a', 'b', 'c', 'd'] },
  { title: 'The sub-agent re-delegates', ids: ['e1', 'e2'] },
  { title: 'Someone attacks the chain', ids: ['f', 'g'] },
];

const REASONS: Record<string, string> = {
  'scope_exceeds_parent:action': 'scope_exceeds_parent:action, the action is broader than the grant above it',
  'scope_exceeds_parent:policy': 'scope_exceeds_parent:policy, the spend is above the cap in the grant above it',
  delegation_signature_invalid: 'delegation_signature_invalid, a parent grant was not signed by the key it names',
};

type Step = { label: string; state: 'ok' | 'fail' | 'skipped' };

function stepsFor(v: Verdict): Step[] {
  const r = v.chainReason;
  let failAt = -1;
  if (r) {
    if (r.startsWith('scope_exceeds_parent')) failAt = 3;
    else if (r === 'untrusted_principal') failAt = 2;
    else if (r.includes('subject') || r.includes('issuer_mismatch')) failAt = 1;
    else failAt = 0;
  } else if (!v.holderValid || !v.coreAccepts) {
    failAt = 4;
  }
  const labels = [
    'every grant is signed by the key it names',
    'each grant names the next holder, and the chain ends at the sender',
    'the chain starts at Alice, the only root this verifier trusts',
    'no step is broader than the grant above it (non-expansion)',
    'the sender’s own signature and time window verify',
  ];
  return labels.map((label, i) => ({
    label,
    state: failAt === -1 || i < failAt ? 'ok' : i === failAt ? 'fail' : 'skipped',
  }));
}

function describeIntent(intent: Record<string, unknown>): string {
  const action = Array.isArray(intent.action) ? intent.action.join(' + ') : String(intent.action);
  const policy = intent.policy as { maxSpend?: number } | undefined;
  const parts = [action];
  if (policy?.maxSpend !== undefined) parts.push(`maxSpend $${policy.maxSpend}`);
  if (typeof intent.amount === 'number') parts.push(`spends $${intent.amount}`);
  return parts.join(' · ');
}

function Delegation() {
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [errorMsg, setErrorMsg] = useState('');
  const [core, setCore] = useState<Core | null>(null);
  const [caseId, setCaseId] = useState('a');

  useEffect(() => {
    let active = true;
    loadCore()
      .then((c) => {
        if (!active) return;
        setCore(c);
        setStatus('ready');
      })
      .catch((e) => {
        if (!active) return;
        setErrorMsg(e instanceof Error ? e.message : String(e));
        setStatus('error');
      });
    return () => {
      active = false;
    };
  }, []);

  const current = fixtures.cases.find((c) => c.id === caseId) as Fixture;

  const outcome = useMemo(() => {
    if (!core) return null;
    // Case f edits Alice's grant here, live, after it was signed.
    const credential = current.tamper
      ? tamperRootGrant(current.credential, current.tamper.action)
      : current.credential;
    const verdict = verifyAction(core, credential, [fixtures.root], fixtures.now);
    return { credential, verdict, steps: stepsFor(verdict) };
  }, [core, current]);

  const subject = current.credential.credentialSubject as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const links = (subject.delegationChain ?? []) as Array<Record<string, any>>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const shownGrants = links.map((l) => ({
    from: who(l.issuer),
    to: who(l.subject),
    intent: l.parentCredential?.credentialSubject?.intent ?? {},
  }));
  const verdict = outcome?.verdict;
  const reasonText = verdict
    ? verdict.allowed
      ? 'the whole chain verifies back to Alice'
      : verdict.chainReason
        ? (REASONS[verdict.chainReason] ?? verdict.chainReason)
        : 'the sender’s own signature or window failed'
    : '';

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          Alice gives her assistant read and update on her calendar with a $50 spend cap. The assistant passes read only,
          with a $20 cap, to a sub-agent. A grant can only narrow as it moves down, and the verifier decides every case
          from the credential alone. The signatures below are real <code className="font-mono text-[0.85em]">eddsa-jcs-2022</code>{' '}
          proofs, and the Vouch Protocol core compiled to WebAssembly checks each one in your browser. The keys were
          generated fresh by a script, are throwaway, and the private halves were never saved.
        </p>

        {GROUPS.map((g) => (
          <div key={g.title} className="mb-4">
            <div className="eyebrow-faint mb-2">{g.title}</div>
            <div className={styles.controls}>
              {g.ids.map((id) => {
                const c = fixtures.cases.find((x) => x.id === id) as Fixture;
                return (
                  <button
                    key={id}
                    className={`${styles.radio}${caseId === id ? ' ' + styles.on : ''}`}
                    onClick={() => setCaseId(id)}
                    disabled={status !== 'ready'}
                  >
                    {c.label}
                  </button>
                );
              })}
            </div>
          </div>
        ))}

        <p className={styles.note}>
          Where a case is refused, the honest signer declines to issue it. The cases here are built by hand to get around
          the signer, and the verifier refuses them anyway.
        </p>
      </div>

      <div className={styles.stage}>
        {status === 'loading' && <div className={styles.loading}>Loading the WebAssembly core…</div>}
        {status === 'error' && (
          <div className={styles.error}>
            The in-browser core could not load, so nothing was verified. Nothing here is faked.
            <br />
            <span className={styles.mono}>{errorMsg}</span>
          </div>
        )}

        {status === 'ready' && outcome && verdict && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel}>Grants in the chain (signed)</div>
              <div className={styles.mono}>
                {shownGrants.length === 0 && 'none'}
                {shownGrants.map((g, i) => (
                  <div key={i}>
                    {g.from} to {g.to}: {describeIntent(g.intent)}
                  </div>
                ))}
              </div>
            </div>

            {current.tamper && (
              <div className={styles.card}>
                <div className={styles.cardLabel}>Edited just now in your browser</div>
                <div className={styles.mono}>
                  Alice&apos;s grant now reads: {current.tamper.action.join(' + ')}
                  <br />
                  Her signature was made over: read + update
                </div>
              </div>
            )}

            {current.id === 'g' && (
              <div className={styles.card}>
                <div className={styles.cardLabel}>The forged grant</div>
                <div className={styles.mono}>
                  issuer claims to be: Alice ({short(fixtures.root)})
                  <br />
                  signed with: Mallory&apos;s key
                </div>
              </div>
            )}

            <div className={styles.card}>
              <div className={styles.cardLabel}>Action sent by {who(current.holder)}</div>
              <div className={styles.mono}>{describeIntent(subject.intent)}</div>
            </div>

            {current.refusal && (
              <div className={styles.card}>
                <div className={styles.cardLabel}>Honest signer, recorded when the fixture was made</div>
                <div className={styles.mono}>refused: {current.refusal}</div>
              </div>
            )}

            <div className={styles.checks}>
              {outcome.steps.map((s) => (
                <div key={s.label} className={styles.checkRow}>
                  <span
                    className={styles.checkMark}
                    style={{ color: s.state === 'ok' ? ALLOW : s.state === 'fail' ? DENY : undefined }}
                  >
                    {s.state === 'ok' ? '✓' : s.state === 'fail' ? '✕' : '·'}
                  </span>
                  <span>{s.label}</span>
                </div>
              ))}
            </div>

            <div className={styles.verdict}>
              <span
                className={styles.badge}
                style={{ color: verdict.allowed ? ALLOW : DENY, borderColor: verdict.allowed ? ALLOW : DENY }}
              >
                {verdict.allowed ? '✓ ALLOWED' : '✕ DENIED'}
              </span>
              <span className={styles.reason}>{reasonText}</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function DelegationDemos() {
  return (
    <section id="delegation-chain" className="scroll-mt-24">
      <div className="container-wide py-16">
        <div className="section-heading">
          <span className="num">§ I</span>
          <h2>Delegation that can only narrow</h2>
        </div>
        <p className="eyebrow mb-6">
          Signed grants travel inside the credential, and the verifier checks each step against the one above it ·
          vouch.delegation
        </p>
        <Delegation />
      </div>
    </section>
  );
}
