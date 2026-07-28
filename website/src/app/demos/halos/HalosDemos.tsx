'use client';

import React, { useCallback, useEffect, useState } from 'react';

import styles from './HalosDemos.module.css';

/**
 * Interactive demo for the Halos safety-evidence recorder. Every value here is
 * produced by the Vouch Protocol WASM core in the visitor's own browser: a
 * throwaway robot identity is generated, a stream of Halos safety events is
 * recorded into the tamper-evident encrypted black-box, the robot signs a
 * HalosSafetyEvidenceCredential sealing the black-box head and entry count, and a
 * verifier confirms it. The tamper and truncate paths perturb the record and let
 * the verifier reject it on the cryptography alone.
 */

type Core = {
  generateEd25519: () => string;
  roboticsGenesisPrevHash: () => string;
  roboticsBlackboxAppend: (
    keyB64: string,
    seq: bigint,
    event: string,
    payloadJson: string,
    timestamp: string,
    prevHash: string,
  ) => string;
  roboticsBuildSafetyEvidence: (signerSeedB64: string, paramsJson: string) => string;
  roboticsVerifySafetyEvidence: (credentialJson: string, robotPublicB64: string, entriesJson: string) => string;
};

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

const HALOS_STACK = {
  igxSom: 'IGX-Thor-SoM',
  halosCore: 'Halos Core Linux 1.0',
  blueprint: ['SAIM', 'SEI', 'SDM'],
};
const WINDOW = { from: '2026-07-12T09:00:00Z', to: '2026-07-12T09:05:00Z' };

const EVENTS: { source: string; event: string; detail: Record<string, unknown>; ts: string }[] = [
  { source: 'SIPP', event: 'frame_ingested', detail: { camera: 3 }, ts: '2026-07-12T09:00:10Z' },
  { source: 'SAIM', event: 'camera_blockage_cleared', detail: { camera: 2 }, ts: '2026-07-12T09:01:00Z' },
  { source: 'SEI', event: 'multi_camera_fused', detail: { objects: 3 }, ts: '2026-07-12T09:02:30Z' },
  { source: 'SDM', event: 'slow_stop', detail: { reason: 'out_of_distribution' }, ts: '2026-07-12T09:03:15Z' },
  { source: 'estop', event: 'emergency_stop', detail: { by: 'operator-7' }, ts: '2026-07-12T09:04:40Z' },
];

function randomKeyB64(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

type Built = {
  entries: Record<string, unknown>[];
  credential: Record<string, unknown>;
  subject: Record<string, unknown>;
  robotPublicB64: string;
};

type Check = { label: string; ok: boolean; detail: string } | null;

export default function HalosDemos() {
  const [core, setCore] = useState<Core | null>(null);
  const [built, setBuilt] = useState<Built | null>(null);
  const [check, setCheck] = useState<Check>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadCore().then(setCore).catch((e) => setError(String(e)));
  }, []);

  const record = useCallback(() => {
    if (!core) return;
    setError(null);
    setCheck(null);
    try {
      const kp = JSON.parse(core.generateEd25519()) as { seed_b64: string; public_b64: string };
      const key = randomKeyB64();
      let prev = core.roboticsGenesisPrevHash();
      const entries: Record<string, unknown>[] = [];
      EVENTS.forEach((ev, i) => {
        const payload = JSON.stringify({ source: ev.source, detail: ev.detail });
        const entry = JSON.parse(core.roboticsBlackboxAppend(key, BigInt(i), ev.event, payload, ev.ts, prev));
        entries.push(entry);
        prev = entry.entryHash as string;
      });
      const params = JSON.stringify({
        halosStack: HALOS_STACK,
        window: WINDOW,
        blackboxHead: prev,
        entryCount: entries.length,
        robotIdentity: 'urn:uuid:demo-robot',
      });
      const credential = JSON.parse(core.roboticsBuildSafetyEvidence(kp.seed_b64, params));
      const verified = JSON.parse(
        core.roboticsVerifySafetyEvidence(JSON.stringify(credential), kp.public_b64, JSON.stringify(entries)),
      );
      setBuilt({ entries, credential, subject: verified.subject, robotPublicB64: kp.public_b64 });
      setCheck({
        label: 'Verified',
        ok: verified.ok === true,
        detail: 'The record is unaltered, its length and head match the seal, and the robot signed it.',
      });
    } catch (e) {
      setError(String(e));
    }
  }, [core]);

  const reverify = useCallback(
    (entries: Record<string, unknown>[], label: string, detail: string) => {
      if (!core || !built) return;
      try {
        const res = JSON.parse(
          core.roboticsVerifySafetyEvidence(
            JSON.stringify(built.credential),
            built.robotPublicB64,
            JSON.stringify(entries),
          ),
        );
        setCheck({ label, ok: res.ok === true, detail });
      } catch (e) {
        setError(String(e));
      }
    },
    [core, built],
  );

  const tamper = useCallback(() => {
    if (!built) return;
    const entries = built.entries.map((e) => ({ ...e }));
    entries[2] = { ...entries[2], event: 'nothing_happened' };
    reverify(entries, 'Tampered record rejected', 'One event was edited, so its hash no longer matches the chain.');
  }, [built, reverify]);

  const truncate = useCallback(() => {
    if (!built) return;
    const entries = built.entries.slice(0, -1);
    reverify(entries, 'Truncated record rejected', 'The last event was dropped, so the length and head no longer match the seal.');
  }, [built, reverify]);

  const short = (s: unknown) => (typeof s === 'string' && s.length > 24 ? `${s.slice(0, 14)}...${s.slice(-6)}` : String(s));

  return (
    <section>
      <div className="container-wide py-12">
        {error && (
          <div className={`${styles.badge} ${styles.badgeBad}`} role="alert">
            Could not load the core in this browser: {error}
          </div>
        )}

        <div className={styles.panel}>
          <p className="text-ink-soft text-[0.95rem] leading-relaxed mb-2">
            The robot records its Halos safety-event stream into the tamper-evident black-box, then signs a
            {' '}<code className="font-mono text-[0.85em]">HalosSafetyEvidenceCredential</code> sealing the black-box head
            and entry count.
          </p>
          <div className={styles.btnRow}>
            <button className={`${styles.btn} ${styles.btnPrimary}`} onClick={record} disabled={!core}>
              {core ? 'Record and seal' : 'Loading core...'}
            </button>
          </div>
        </div>

        {built && (
          <div className={styles.panel} style={{ marginTop: '1.1rem' }}>
            <p className="eyebrow mb-3">Recorded safety events (encrypted in the black-box)</p>
            {built.entries.map((e, i) => (
              <div className={styles.eventRow} key={i}>
                <span className={styles.source}>{EVENTS[i].source}</span>
                <span>{EVENTS[i].event}</span>
                <span className={styles.mono} style={{ marginLeft: 'auto' }}>
                  #{String(e.seq)} {short(e.entryHash)}
                </span>
              </div>
            ))}
            <p className="eyebrow mt-5 mb-2">Sealed evidence credential</p>
            <div className={styles.kv}>
              <span className={styles.kvKey}>robot</span>
              <span className={styles.mono}>{short(built.subject.id)}</span>
              <span className={styles.kvKey}>black-box head</span>
              <span className={styles.mono}>{short(built.subject.blackboxHead)}</span>
              <span className={styles.kvKey}>entry count</span>
              <span className={styles.mono}>{String(built.subject.entryCount)}</span>
              <span className={styles.kvKey}>certified stack</span>
              <span className={styles.mono}>{HALOS_STACK.igxSom} · {HALOS_STACK.halosCore}</span>
            </div>

            {check && (
              <div style={{ marginTop: '1.1rem' }}>
                <span className={`${styles.badge} ${check.ok ? styles.badgeOk : styles.badgeBad}`}>
                  {check.ok ? '✓' : '✗'} {check.label}
                </span>
                <p className={styles.note}>{check.detail}</p>
              </div>
            )}

            <div className={styles.btnRow}>
              <button className={styles.btn} onClick={record}>Record again</button>
              <button className={styles.btn} onClick={tamper}>Tamper with an event</button>
              <button className={styles.btn} onClick={truncate}>Drop the last event</button>
            </div>
            <p className={styles.note}>
              The verifier checks the record from the encrypted entries and the seal, without the black-box key, so it
              confirms the record is intact and complete while the payloads stay confidential.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
