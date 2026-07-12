'use client';

import React, { useCallback, useEffect, useState } from 'react';

import styles from './TransparencyDemos.module.css';

/**
 * Interactive demo for machine-readable AI transparency marking. The visitor
 * picks or types an agent output, a throwaway did:key identity is generated in
 * the browser, and the Vouch Protocol core (compiled to WebAssembly) signs a
 * disclosure credential over the text: AI generated, by this agent DID, at
 * this time. The verify panel checks the content digest and the eddsa-jcs-2022
 * proof live, so tampering with one character of the text makes verification
 * fail. Every DID, digest, and signature on screen comes from a real WASM
 * call; nothing is precomputed. Burgundy doubles as the fail color, a
 * parchment-harmonized green marks a verified disclosure, and both read on
 * either theme.
 */

type CoreModule = typeof import('@vouch-protocol-official/core-wasm');

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

const SAMPLES: Array<{ label: string; text: string }> = [
  {
    label: 'Support reply',
    text: 'Your refund of $42.18 was approved this morning and should reach your account within three business days.',
  },
  {
    label: 'Meeting update',
    text: 'The design review moved to Thursday at 10:00. I notified the other attendees and updated the calendar.',
  },
  {
    label: 'Report summary',
    text: 'Quarterly summary: revenue grew 8 percent, driven mostly by the new onboarding flow launched in April.',
  },
];

interface Disclosure {
  credential: Record<string, unknown>;
  did: string;
  created: string;
  digest: string;
  proofValue: string;
}

interface Verdict {
  sigValid: boolean;
  digestMatch: boolean;
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Shorten a long identifier for display, keeping both ends. */
function shorten(s: string, head = 20, tail = 6): string {
  return s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

function Marking() {
  const [core, setCore] = useState<CoreModule | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [text, setText] = useState(SAMPLES[0].text);
  const [disclosure, setDisclosure] = useState<Disclosure | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [signedText, setSignedText] = useState<string | null>(null);

  // Load and initialize the WASM core once, in the browser only.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mod = await import('@vouch-protocol-official/core-wasm');
        await mod.default();
        if (!cancelled) setCore(mod);
      } catch {
        if (!cancelled) setLoadFailed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const mark = useCallback(async () => {
    if (!core) return;
    // Throwaway agent identity, minted in this browser tab. The seed is used
    // once to sign and never leaves this function.
    const kp = JSON.parse(core.generateEd25519()) as {
      seed_b64: string;
      public_b64: string;
      multikey: string;
      did_key: string;
    };
    const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const digest = `sha256:${await sha256Hex(text)}`;
    const unsigned = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'AIDisclosureCredential'],
      issuer: kp.did_key,
      validFrom: created,
      credentialSubject: {
        disclosure: 'ai-generated',
        contentType: 'text/plain',
        contentDigest: digest,
        generator: kp.did_key,
        generatedAt: created,
      },
    };
    const vm = `${kp.did_key}#${kp.multikey}`;
    const signed = JSON.parse(core.sign(JSON.stringify(unsigned), kp.seed_b64, vm, created)) as Record<string, unknown>;
    const proof = signed.proof as { proofValue?: string } | undefined;
    setDisclosure({
      credential: signed,
      did: kp.did_key,
      created,
      digest,
      proofValue: proof?.proofValue ?? '',
    });
    setSignedText(text);
  }, [core, text]);

  const tamper = useCallback(() => {
    setText((t) => {
      if (t.length === 0) return t;
      const i = Math.floor(t.length / 2);
      const c = t[i];
      const swapped = c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase();
      const replacement = swapped === c ? (c === '0' ? '1' : '0') : swapped;
      return t.slice(0, i) + replacement + t.slice(i + 1);
    });
  }, []);

  const restore = useCallback(() => {
    if (signedText !== null) setText(signedText);
  }, [signedText]);

  // Re-verify whenever the text or the credential changes: recompute the
  // content digest, then check the Data Integrity proof through WASM using
  // only the public key recovered from the issuer DID.
  useEffect(() => {
    if (!core || !disclosure) {
      setVerdict(null);
      return;
    }
    let cancelled = false;
    (async () => {
      const digestNow = `sha256:${await sha256Hex(text)}`;
      const publicB64 = core.ed25519FromDidKey(disclosure.did);
      const sigValid = core.verifyProof(JSON.stringify(disclosure.credential), publicB64);
      if (!cancelled) setVerdict({ sigValid, digestMatch: digestNow === disclosure.digest });
    })();
    return () => {
      cancelled = true;
    };
  }, [core, disclosure, text]);

  const verified = verdict !== null && verdict.sigValid && verdict.digestMatch;

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          An AI agent produced some text. Before handing it over, the agent signs a small credential stating that the
          text is AI generated, which DID signed that statement, and when. The disclosure binds to the exact bytes of
          the text through a digest, so a verifier needs no server and no account: the credential alone proves what was
          disclosed and that nothing changed since.
        </p>
        <div className="eyebrow-faint mb-2">The agent output</div>
        <div className={styles.sampleRow}>
          {SAMPLES.map((s) => (
            <button key={s.label} className={styles.sample} onClick={() => setText(s.text)}>
              {s.label}
            </button>
          ))}
        </div>
        <textarea
          className={styles.textarea}
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={4}
          aria-label="Agent output text"
        />
        <div className={styles.actions}>
          <button className={styles.primary} onClick={mark} disabled={!core || text.length === 0}>
            {core ? 'Mark as AI-generated' : loadFailed ? 'Crypto core unavailable' : 'Loading crypto core…'}
          </button>
          <button className={styles.action} onClick={tamper} disabled={!disclosure}>
            Tamper one character
          </button>
          <button className={styles.action} onClick={restore} disabled={!disclosure || signedText === text}>
            Restore signed text
          </button>
        </div>
        <p className="footnote mt-4">
          The key pair is a throwaway minted in your browser for this page. The seed signs once and is discarded;
          verification uses only the public key inside the DID.
        </p>
      </div>
      <div className={styles.stage}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Throwaway agent identity</div>
          <div className={styles.mono}>{disclosure ? disclosure.did : '· mark the output to mint one ·'}</div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Signed disclosure credential</div>
          <div className={styles.mono}>
            {disclosure ? (
              <>
                disclosure: ai-generated
                <br />
                issuer: {shorten(disclosure.did)}
                <br />
                created: {disclosure.created}
                <br />
                contentDigest: {shorten(disclosure.digest, 18, 8)}
                <br />
                proofValue: {shorten(disclosure.proofValue, 18, 8)}
              </>
            ) : (
              '· no disclosure yet ·'
            )}
          </div>
        </div>
        <div className={styles.verdict}>
          <span
            className={styles.badge}
            style={
              disclosure
                ? { color: verified ? ALLOW : DENY, borderColor: verified ? ALLOW : DENY }
                : undefined
            }
          >
            {!disclosure ? '· IDLE ·' : verdict === null ? '· CHECKING ·' : verified ? '✓ DISCLOSURE VERIFIED' : '✕ VERIFICATION FAILED'}
          </span>
          <span className={styles.reason}>
            {!disclosure
              ? 'mark the output to create its disclosure'
              : verdict === null
                ? 'recomputing digest and checking the proof'
                : verified
                  ? `AI-generated · signed by ${shorten(disclosure.did, 14, 4)} · at ${disclosure.created} · signature valid`
                  : verdict.digestMatch
                    ? 'the proof on the credential does not verify'
                    : 'the text no longer matches the digest the agent signed'}
          </span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function TransparencyDemos() {
  return (
    <section id="marking" className="scroll-mt-24">
      <div className="container-wide py-16">
        <div className="section-heading">
          <span className="num">§ I</span>
          <h2>Machine-readable AI marking</h2>
        </div>
        <p className="eyebrow mb-6">Sign a disclosure over the output, verify it, then tamper with it · eddsa-jcs-2022</p>
        <Marking />
      </div>
    </section>
  );
}
