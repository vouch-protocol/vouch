'use client';

import React, { useEffect, useLayoutEffect, useMemo, useState } from 'react';

import styles from './ValidityDemos.module.css';

/**
 * Interactive demo of credential validity. The page plays the part of the
 * signing sidecar: the agent asks for a duration, the sidecar applies its
 * default and its ceiling, and the credential is signed for that long. A
 * verifier then checks it at a time the visitor chooses.
 *
 * The signing and the checking are real. The Vouch Protocol core, compiled to
 * WebAssembly, makes a throwaway key in the browser, signs each credential with
 * an eddsa-jcs-2022 proof, and verifies it against the chosen time.
 */

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

/* ------------------------------------------------------------------ */
/* WASM core loader, same approach as the other live-crypto demos.       */
/* ------------------------------------------------------------------ */

type Core = {
  generateEd25519: () => string;
  sign: (credentialJson: string, seedB64: string, verificationMethod: string, created: string) => string;
  verify: (credentialJson: string, publicB64: string, nowIso: string, skewSeconds: number) => string;
};

type Identity = { seed_b64: string; public_b64: string; multikey: string; did_key: string };

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

// Verifiers allow this much for clocks that disagree.
const SKEW_SECONDS = 30;

const DEFAULTS = [
  { seconds: 60, label: '1 minute' },
  { seconds: 300, label: '5 minutes' },
  { seconds: 600, label: '10 minutes' },
];

const CEILINGS = [
  { seconds: 900, label: '15 minutes' },
  { seconds: 3600, label: '1 hour' },
  { seconds: 7200, label: '2 hours' },
];

const ASKS: Array<{ seconds: number | null; label: string }> = [
  { seconds: null, label: 'Nothing: let the sidecar decide' },
  { seconds: 30, label: '30 seconds' },
  { seconds: 1800, label: '30 minutes' },
  { seconds: 7200, label: '2 hours' },
];

const CLOCKS = [
  { ahead: 0, label: 'Right away' },
  { ahead: 120, label: '2 minutes later' },
  { ahead: 1200, label: '20 minutes later' },
  { ahead: 10800, label: '3 hours later' },
];

const iso = (date: Date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');
const clockTime = (isoTime: string) => isoTime.slice(11, 19) + ' UTC';

/** A time, with its date added when it falls on a different UTC day from `start`. */
function stamp(isoTime: string, start: string): string {
  if (isoTime.slice(0, 10) === start.slice(0, 10)) return clockTime(isoTime);
  return `${isoTime.slice(0, 10)} ${clockTime(isoTime)}`;
}

/** A random credential id. Falls back for browsers without crypto.randomUUID. */
function uuid(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const short = (did: string) => `${did.slice(0, 16)}…${did.slice(-6)}`;

function span(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return seconds === 60 ? '1 minute' : `${seconds / 60} minutes`;
  return seconds === 3600 ? '1 hour' : `${seconds / 3600} hours`;
}

type Signed = {
  kind: 'signed';
  credential: Record<string, unknown>;
  seconds: number;
  because: string;
  signedAt: number;
};
type Refused = { kind: 'refused'; message: string };

/** What the sidecar does with one request: sign it, or refuse it. */
function decide(
  core: Core,
  identity: Identity,
  asked: number | null,
  defaultSeconds: number,
  ceilingSeconds: number,
): Signed | Refused {
  if (asked !== null && asked > ceilingSeconds) {
    return {
      kind: 'refused',
      message: `validity must be between 1 and ${ceilingSeconds} seconds; leave it out for the default of ${defaultSeconds}`,
    };
  }
  const seconds = asked ?? defaultSeconds;
  const now = new Date();
  now.setMilliseconds(0);
  const did = identity.did_key;
  const unsigned = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://vouch-protocol.com/contexts/v1'],
    id: `urn:uuid:${uuid()}`,
    type: ['VerifiableCredential', 'VouchCredential'],
    issuer: did,
    validFrom: iso(now),
    validUntil: iso(new Date(now.getTime() + seconds * 1000)),
    credentialSubject: {
      id: did,
      vouchVersion: '1.0',
      intent: { action: 'read', target: 'reports', resource: 'https://api.example.com/reports/1' },
    },
  };
  const signed = core.sign(JSON.stringify(unsigned), identity.seed_b64, `${did}#${identity.multikey}`, iso(now));
  return {
    kind: 'signed',
    credential: JSON.parse(signed) as Record<string, unknown>,
    seconds,
    because: asked === null ? 'the agent asked for nothing, so the default applies' : 'this is what the agent asked for',
    signedAt: now.getTime(),
  };
}

function Validity() {
  const [status, setStatus] = useState<'loading' | 'ready' | 'error' | 'sign-error'>('loading');
  const [errorMsg, setErrorMsg] = useState('');
  const [core, setCore] = useState<Core | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);

  const [defaultSeconds, setDefaultSeconds] = useState(300);
  const [ceilingSeconds, setCeilingSeconds] = useState(3600);
  const [asked, setAsked] = useState<number | null>(null);
  const [ahead, setAhead] = useState(0);
  const [edited, setEdited] = useState(false);
  const [result, setResult] = useState<Signed | Refused | null>(null);

  useEffect(() => {
    let active = true;
    loadCore()
      .then((c) => {
        if (!active) return;
        // A fresh key for this visit. It never leaves the page.
        setIdentity(JSON.parse(c.generateEd25519()) as Identity);
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

  // Every change to the request or to the sidecar's settings is a new request,
  // signed again from scratch. A layout effect, so the new request and its
  // verdict appear together in the same frame.
  useLayoutEffect(() => {
    if (!core || !identity) return;
    try {
      setResult(decide(core, identity, asked, defaultSeconds, ceilingSeconds));
      setEdited(false);
      setStatus('ready');
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setStatus('sign-error');
    }
  }, [core, identity, asked, defaultSeconds, ceilingSeconds]);

  const check = useMemo(() => {
    if (!core || !identity || !result || result.kind !== 'signed') return null;
    const presented = edited
      ? { ...result.credential, validUntil: iso(new Date(Date.parse(String(result.credential.validUntil)) + 86400 * 1000)) }
      : result.credential;
    const at = iso(new Date(result.signedAt + ahead * 1000));
    try {
      const verdict = JSON.parse(core.verify(JSON.stringify(presented), identity.public_b64, at, SKEW_SECONDS)) as {
        proofValid: boolean;
        timeValid: boolean;
        valid: boolean;
      };
      return { presented, at, ...verdict };
    } catch {
      return { presented, at, proofValid: false, timeValid: false, valid: false };
    }
  }, [core, identity, result, ahead, edited]);

  const reason = !check
    ? ''
    : check.valid
      ? 'the signature matches and the time is inside the window'
      : !check.proofValid
        ? 'the credential was changed after it was signed'
        : 'its time is up';

  const ready = status === 'ready';
  const usable = !!core && !!identity && status !== 'error';

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          An agent asks its sidecar to sign what it is about to do, and says how long the signature should last. The
          sidecar signs for that long. Whoever runs the sidecar sets two limits around that choice: a default, for when
          the agent asks for nothing, and a ceiling the agent cannot go past. This page plays the sidecar&apos;s part, with
          the same rule and the same refusal message as the real one. Every credential below is signed in your
          browser with a real <code className="font-mono text-[0.85em]">eddsa-jcs-2022</code> proof, and the Vouch
          Protocol core compiled to WebAssembly checks it. The key is made fresh for this visit and is thrown away when
          you leave.
        </p>

        <div className={styles.group}>
          <div className="eyebrow-faint mb-2">The agent asks for</div>
          <div className={styles.controls} role="group" aria-label="The agent asks for">
            {ASKS.map((a) => (
              <button
                key={a.label}
                className={`${styles.radio}${asked === a.seconds ? ' ' + styles.on : ''}`}
                aria-pressed={asked === a.seconds}
                onClick={() => setAsked(a.seconds)}
                disabled={!usable}
              >
                {a.label}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.group}>
          <div className="eyebrow-faint mb-2">The sidecar&apos;s default</div>
          <div className={styles.inline} role="group" aria-label="The sidecar’s default">
            {DEFAULTS.map((d) => (
              <button
                key={d.seconds}
                className={`${styles.radio}${defaultSeconds === d.seconds ? ' ' + styles.on : ''}`}
                aria-pressed={defaultSeconds === d.seconds}
                onClick={() => setDefaultSeconds(d.seconds)}
                disabled={!usable}
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.group}>
          <div className="eyebrow-faint mb-2">The sidecar&apos;s ceiling</div>
          <div className={styles.inline} role="group" aria-label="The sidecar’s ceiling">
            {CEILINGS.map((c) => (
              <button
                key={c.seconds}
                className={`${styles.radio}${ceilingSeconds === c.seconds ? ' ' + styles.on : ''}`}
                aria-pressed={ceilingSeconds === c.seconds}
                onClick={() => setCeilingSeconds(c.seconds)}
                disabled={!usable}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.group}>
          <div className="eyebrow-faint mb-2">A verifier checks it</div>
          <div className={styles.inline} role="group" aria-label="A verifier checks it">
            {CLOCKS.map((c) => (
              <button
                key={c.ahead}
                className={`${styles.radio}${ahead === c.ahead ? ' ' + styles.on : ''}`}
                aria-pressed={ahead === c.ahead}
                onClick={() => setAhead(c.ahead)}
                disabled={!ready || result?.kind !== 'signed'}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.group}>
          <div className="eyebrow-faint mb-2">Or someone edits it first</div>
          <div className={styles.inline} role="group" aria-label="Or someone edits it first">
            <button
              className={`${styles.radio}${edited ? ' ' + styles.on : ''}`}
              aria-pressed={edited}
              onClick={() => setEdited((v) => !v)}
              disabled={!ready || result?.kind !== 'signed'}
            >
              Push the end time out by a day, without the key
            </button>
          </div>
        </div>

        <p className={styles.note}>
          The same two settings on a real sidecar are{' '}
          <code className="font-mono text-[0.85em]">--default-validity</code> and{' '}
          <code className="font-mono text-[0.85em]">--max-validity</code>. Verifiers allow {SKEW_SECONDS} seconds for
          clocks that disagree.
        </p>
      </div>

      <div className={styles.stage}>
        {status === 'loading' && <div className={styles.loading}>Loading the WebAssembly core…</div>}
        {status === 'error' && (
          <div className={styles.error}>
            The in-browser core could not load, so nothing was signed or verified. Nothing here is faked.
            <br />
            <span className={styles.mono}>{errorMsg}</span>
          </div>
        )}
        {status === 'sign-error' && (
          <div className={styles.error}>
            The core loaded, but signing this request failed in your browser, so nothing was signed or verified. Pick
            another option to try again.
            <br />
            <span className={styles.mono}>{errorMsg}</span>
          </div>
        )}

        {ready && identity && result && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel}>The request</div>
              <div className={styles.mono}>
                agent: {short(identity.did_key)}
                <br />
                action: read · resource: https://api.example.com/reports/1
                <br />
                validSeconds: {asked === null ? 'not sent' : asked}
              </div>
            </div>

            <div className={styles.card}>
              <div className={styles.cardLabel}>The sidecar decides</div>
              <div className={styles.mono}>
                default {span(defaultSeconds)} · ceiling {span(ceilingSeconds)}
                <br />
                {result.kind === 'signed' ? (
                  <>
                    signs for {span(result.seconds)}: {result.because}
                  </>
                ) : (
                  <>refuses: {result.message}</>
                )}
              </div>
            </div>

            {result.kind === 'signed' && check && (
              <>
                <div className={styles.card}>
                  <div className={styles.cardLabel}>
                    {edited ? 'The credential, edited in your browser' : 'The credential, signed in your browser'}
                  </div>
                  <div className={styles.mono}>
                    valid from {clockTime(String(check.presented.validFrom))}
                    <br />
                    valid until {stamp(String(check.presented.validUntil), String(check.presented.validFrom))}
                    {edited ? ' (moved out by a day)' : ''}
                    <br />
                    proof: {String((check.presented.proof as { proofValue?: string })?.proofValue ?? '').slice(0, 28)}…
                  </div>
                </div>

                <div className={styles.card}>
                  <div className={styles.cardLabel}>The verifier&apos;s clock</div>
                  <div className={styles.mono}>{stamp(check.at, String(check.presented.validFrom))}</div>
                </div>

                <div className={styles.checks}>
                  <div className={styles.checkRow}>
                    <span className={styles.checkMark} style={{ color: check.proofValid ? ALLOW : DENY }}>
                      {check.proofValid ? '✓' : '✕'}
                    </span>
                    <span>the signature matches the agent&apos;s key</span>
                  </div>
                  <div className={styles.checkRow}>
                    <span className={styles.checkMark} style={{ color: check.timeValid ? ALLOW : DENY }}>
                      {check.timeValid ? '✓' : '✕'}
                    </span>
                    <span>the verifier&apos;s clock is inside the window</span>
                  </div>
                </div>
              </>
            )}

            <div className={styles.verdict} role="status" aria-live="polite">
              {result.kind === 'refused' ? (
                <>
                  <span className={styles.badge} style={{ color: DENY, borderColor: DENY }}>
                    ✕ NOT SIGNED
                  </span>
                  <span className={styles.reason}>the agent asked for more than the ceiling allows</span>
                </>
              ) : (
                check && (
                  <>
                    <span
                      className={styles.badge}
                      style={{ color: check.valid ? ALLOW : DENY, borderColor: check.valid ? ALLOW : DENY }}
                    >
                      {check.valid ? '✓ VERIFIED' : '✕ REJECTED'}
                    </span>
                    <span className={styles.reason}>{reason}</span>
                  </>
                )
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function ValidityDemos() {
  return (
    <section id="credential-validity" className="scroll-mt-24">
      <div className="container-wide py-16">
        <div className="section-heading">
          <span className="num">§ I</span>
          <h2>The agent chooses, inside limits the operator sets</h2>
        </div>
        <p className="eyebrow mb-6">
          Each credential carries its own start and end time, and a verifier refuses it once that time is up ·
          vouch.sidecar
        </p>
        <Validity />
      </div>
    </section>
  );
}
