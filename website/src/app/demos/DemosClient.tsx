'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Interactive demos for the three accountable-autonomy runtime primitives that
 * ship in the SDK: Reasoned Action Proofs (PAD-085 companion, vouch.reasoning),
 * Proof of Deliberation (PAD-085, vouch.deliberation), and Executable Caveats
 * (PAD-086, vouch.caveats). Styled with the site's parchment/burgundy/serif
 * system so it reads as part of the document, light and dark.
 *
 * Semantic colours are demo-local: burgundy (the brand) doubles as deny/veto,
 * a parchment-harmonised green marks allow. Both read on either theme.
 */

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const m = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(m.matches);
    const h = () => setReduced(m.matches);
    m.addEventListener('change', h);
    return () => m.removeEventListener('change', h);
  }, []);
  return reduced;
}

/* ------------------------------------------------------------------ */
/* Section II — The Deliberation (vouch.deliberation)                  */
/* ------------------------------------------------------------------ */

type DelibState = 'idle' | 'running' | 'executed' | 'blocked';

function Deliberation() {
  const reduced = useReducedMotion();
  const WINDOW_MS = 7000;
  const [state, setState] = useState<DelibState>('idle');
  const [progress, setProgress] = useState(0); // 0..1
  const [log, setLog] = useState<React.ReactNode[]>([]);
  const [toast, setToast] = useState<string | null>(null);
  const raf = useRef<number | null>(null);
  const start = useRef<number>(0);
  const toastTimer = useRef<number | null>(null);

  const push = useCallback((node: React.ReactNode) => setLog((l) => [...l, node]), []);
  const flash = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 1900);
  }, []);

  const stop = () => { if (raf.current) cancelAnimationFrame(raf.current); raf.current = null; };
  useEffect(() => stop, []);

  const minsLeft = (p: number) => {
    const s = Math.ceil((1 - p) * 15 * 60);
    return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  };

  const tick = useCallback((now: number) => {
    const p = Math.min(1, (now - start.current) / WINDOW_MS);
    setProgress(p);
    if (p >= 1) {
      setState('executed');
      push(<span><span className="k">t+15:00</span>  window closed · <b style={{ color: ALLOW }}>no veto</b></span>);
      push(<span style={{ color: ALLOW }}>✓ EXECUTE accepted</span>);
      return;
    }
    raf.current = requestAnimationFrame(tick);
  }, [push]);

  const commit = () => {
    setLog([]); setProgress(0); setState('running');
    push(<span><b style={{ color: DENY }}>INTENT</b> transfer_funds · usd:5000 → acct:vendor-1</span>);
    push(<span className="k">class irreversible-financial · window 900s · veto→ did:web:controller</span>);
    if (reduced) { setProgress(0.45); return; }
    start.current = performance.now();
    raf.current = requestAnimationFrame(tick);
  };
  const force = () => {
    push(<span><span className="k">t+00:31</span>  agent tries to execute early</span>);
    push(<span style={{ color: DENY }}>✕ rejected · challenge_window_not_elapsed</span>);
    flash('rejected · challenge_window_not_elapsed');
  };
  const veto = () => {
    stop(); setState('blocked');
    push(<span><b style={{ color: DENY }}>VETO</b> signed by did:web:controller · over unattended threshold</span>);
    push(<span style={{ color: DENY }}>✕ EXECUTE rejected · vetoed</span>);
  };
  const reset = () => { stop(); setState('idle'); setProgress(0); setLog([]); };

  const pct = (progress * 100).toFixed(1);
  return (
    <div className="grid md:grid-cols-2 gap-8 items-start">
      <div>
        <div className="flex items-center justify-between mb-4">
          <span className="font-serif text-[1.05rem]">Agent wants to <span className="text-burgundy font-semibold">wire $5,000</span></span>
          <button className="demo-chip" onClick={() => flash('reversible · executed instantly')}>read cache · reversible</button>
        </div>
        <div className="border border-dashed border-rule px-6 py-8 flex flex-col items-center gap-4 text-center min-h-[240px] justify-center">
          {state === 'executed' ? (
            <div className="demo-stamp" style={{ color: ALLOW, borderColor: ALLOW }}>✓ EXECUTED</div>
          ) : state === 'blocked' ? (
            <div className="demo-stamp" style={{ color: DENY, borderColor: DENY }}>⦸ BLOCKED</div>
          ) : (
            <div className="demo-ring" style={{ ['--p' as string]: pct, ['--arc' as string]: DENY }}>
              <div className="demo-ring-face">
                <span className="font-mono text-[1.5rem] tabular-nums">{state === 'running' ? minsLeft(progress) : '15:00'}</span>
                <small className="eyebrow-faint block mt-1">window</small>
              </div>
            </div>
          )}
          <p className="text-ink-soft text-[0.9rem] max-w-[42ch] leading-relaxed">
            {state === 'idle' && <>Commit the intent to broadcast what the agent wants and start a 15-minute window (compressed to a few seconds). You are the controller.</>}
            {state === 'running' && <>Intent is broadcast and the clock is running. Wait it out, or veto.</>}
            {state === 'executed' && <>Window elapsed with no veto. The verifier accepts the execute credential.</>}
            {state === 'blocked' && <>The controller signed a veto bound to this intent. Every verifier now rejects the execute.</>}
          </p>
        </div>
        <div className="flex flex-wrap gap-3 mt-5">
          <button className="btn-primary" onClick={commit} disabled={state === 'running'}>Commit intent</button>
          <button className="demo-btn" onClick={force} disabled={state !== 'running'}>Force execute now</button>
          <button className="demo-btn demo-veto" onClick={veto} disabled={state !== 'running'}>Veto</button>
          <button className="demo-btn ml-auto" onClick={reset}>Reset</button>
        </div>
      </div>
      <div>
        <div className="eyebrow-faint mb-2">Signed action ledger</div>
        <div className="demo-ledger">
          {log.length === 0 ? <div className="k">— idle —</div> : log.map((l, i) => <div key={i} className="demo-line">{l}</div>)}
        </div>
      </div>
      {toast && <div className="demo-toast">{toast}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Section III — The Envelope (vouch.caveats)                          */
/* ------------------------------------------------------------------ */

function Envelope() {
  const [amount, setAmount] = useState(120);
  const [hour, setHour] = useState(11);
  const [shipped, setShipped] = useState(true);
  const [drop, setDrop] = useState(false);

  let deny: string | null = null;
  let reason = '';
  if (drop) { deny = 'root'; reason = 'unrooted_capability'; }
  else if (!shipped) { deny = 'shipped'; reason = 'caveat_denied:shipped-only'; }
  else if (amount > 200) { deny = 'ceiling'; reason = 'caveat_denied:amount≤200'; }
  else if (!(hour >= 9 && hour < 17)) { deny = 'hours'; reason = 'caveat_denied:business-hours'; }
  const allow = deny === null;

  const chip = (key: string, label: string) => {
    const blocked = deny === key;
    const dropped = drop && key === 'shipped';
    return (
      <span className={`demo-cav${blocked ? ' blocked' : ''}${dropped ? ' dropped' : ''}`}>{label}</span>
    );
  };

  return (
    <div>
      <div className="flex flex-wrap items-stretch gap-0">
        <div className="demo-hop">
          <div className="eyebrow-faint">Root · grantor</div>
          <div className="font-serif font-semibold text-[1.05rem] mt-1">CEO</div>
          <div className="mt-2">{chip('shipped', 'shipped-only')}</div>
        </div>
        <div className="self-center font-mono text-ink-faint px-2">→</div>
        <div className="demo-hop">
          <div className="eyebrow-faint">delegate</div>
          <div className="font-serif font-semibold text-[1.05rem] mt-1">Manager</div>
          <div className="mt-2">{chip('ceiling', 'amount ≤ $200')}{chip('hours', 'business-hours')}</div>
        </div>
        <div className="self-center font-mono text-ink-faint px-2">→</div>
        <div className="demo-hop">
          <div className="eyebrow-faint">holder · acts</div>
          <div className="font-serif font-semibold text-[1.05rem] mt-1">Refund Agent</div>
          <div className="eyebrow-faint mt-3">issues a refund</div>
        </div>
      </div>

      <div className="grid gap-4 mt-7 max-w-prose-wide">
        <label className="demo-ctl">
          <span>refund amount</span>
          <input type="range" min={0} max={600} step={10} value={amount} onChange={(e) => setAmount(+e.target.value)} />
          <output>${amount}</output>
        </label>
        <label className="demo-ctl">
          <span>time of day</span>
          <input type="range" min={0} max={23} step={1} value={hour} onChange={(e) => setHour(+e.target.value)} />
          <output>{String(hour).padStart(2, '0')}:00</output>
        </label>
        <div className="flex flex-wrap gap-x-8 gap-y-2">
          <label className="demo-switch"><input type="checkbox" checked={shipped} onChange={(e) => setShipped(e.target.checked)} /> order has shipped</label>
          <label className="demo-switch"><input type="checkbox" checked={drop} onChange={(e) => setDrop(e.target.checked)} /> agent hides the CEO&apos;s rule</label>
        </div>
      </div>

      <div className="demo-verdict mt-6" style={{ borderColor: allow ? ALLOW : DENY }}>
        <span className="demo-badge" style={{ color: allow ? ALLOW : DENY, borderColor: allow ? ALLOW : DENY }}>
          {allow ? 'ALLOW' : 'DENY'}
        </span>
        <span className="font-mono text-[0.85rem] text-ink-soft">
          {allow ? 'All three accumulated caveats pass. Verified offline, no policy server.'
            : deny === 'root' ? <>Chain no longer roots at the CEO → <b className="text-ink">{reason}</b>. You can&apos;t shed an ancestor&apos;s caveat by hiding a hop.</>
            : <>Blocked by a caveat from {deny === 'shipped' ? 'the CEO, two hops up' : 'the Manager'} → <b className="text-ink">{reason}</b></>}
        </span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Section I — Reasoned Action (vouch.reasoning)                       */
/* ------------------------------------------------------------------ */

function ReasonedAction() {
  const [mode, setMode] = useState<'honest' | 'fabricate' | 'rewrite'>('honest');
  const verdicts = {
    honest: { ok: true, reason: 'every reason resolves and hashes match', label: 'ACCEPTED' },
    fabricate: { ok: false, reason: 'evidence_unresolved · "the CFO approved by phone" resolves to nothing', label: 'REJECTED' },
    rewrite: { ok: false, reason: 'justification_digest_mismatch · rewritten after the escrow commit', label: 'REJECTED' },
  } as const;
  const v = verdicts[mode];
  return (
    <div className="grid md:grid-cols-2 gap-8 items-start">
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          Before acting, the agent states <em>why</em>, ties each reason to a real artifact by its hash, and escrows the
          justification <b className="text-ink">before</b> it executes. An auditor can then prove the reasoning was neither
          fabricated nor rewritten after the fact.
        </p>
        <div className="eyebrow-faint mb-2">Try it as the agent</div>
        <div className="flex flex-col gap-2">
          <button className={`demo-radio${mode === 'honest' ? ' on' : ''}`} onClick={() => setMode('honest')}>Cite the real user request + delegation</button>
          <button className={`demo-radio${mode === 'fabricate' ? ' on' : ''}`} onClick={() => setMode('fabricate')}>Fabricate a reason (&ldquo;the CFO approved by phone&rdquo;)</button>
          <button className={`demo-radio${mode === 'rewrite' ? ' on' : ''}`} onClick={() => setMode('rewrite')}>Rewrite the justification after acting</button>
        </div>
      </div>
      <div>
        <div className="demo-ledger" style={{ minHeight: '150px' }}>
          <div className="demo-line"><span className="k">intent</span> delete · /tmp/cache/*</div>
          <div className="demo-line"><span className="k">reason</span> {mode === 'fabricate' ? 'CFO approved by phone → call:none' : mode === 'rewrite' ? 'user asked → (digest changed)' : 'user asked to clean /tmp → msg:c-42'}</div>
          <div className="demo-line"><span className="k">escrowed</span> before execution ✓</div>
        </div>
        <div className="demo-verdict mt-4" style={{ borderColor: v.ok ? ALLOW : DENY }}>
          <span className="demo-badge" style={{ color: v.ok ? ALLOW : DENY, borderColor: v.ok ? ALLOW : DENY }}>{v.label}</span>
          <span className="font-mono text-[0.85rem] text-ink-soft">{v.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function DemosClient() {
  return (
    <>
      <section id="reasoned-action" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ I</span>
            <h2>Reasoned action</h2>
          </div>
          <p className="eyebrow mb-6">Every action states why — and can&apos;t lie about it · vouch.reasoning</p>
          <ReasonedAction />
        </div>
      </section>

      <section id="deliberation" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ II</span>
            <h2>The deliberation</h2>
          </div>
          <p className="eyebrow mb-6">Irreversible actions wait, and you can veto · vouch.deliberation</p>
          <Deliberation />
        </div>
      </section>

      <section id="caveats" className="scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ III</span>
            <h2>The envelope</h2>
          </div>
          <p className="eyebrow mb-6">A rule the CEO sets binds an agent two hops down · vouch.caveats</p>
          <Envelope />
        </div>
      </section>
    </>
  );
}
