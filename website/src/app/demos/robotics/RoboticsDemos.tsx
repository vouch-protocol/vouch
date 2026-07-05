'use client';

import React, { useState } from 'react';

import styles from './RoboticsDemos.module.css';

/**
 * Interactive demos for the three robotics capabilities shipped alongside this
 * page: infrastructure access (vouch.robotics.access), fused-sensor provenance
 * (vouch.robotics.fusion), and wear and degradation (vouch.robotics.wear). Each
 * mirrors the real credential shapes and the real verification logic, rendered
 * as an on-brand illustration rather than a live signature so it runs with no
 * network call. Burgundy doubles as refuse, a parchment-harmonized green marks
 * allow, and both read on either theme.
 */

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

/* ------------------------------------------------------------------ */
/* Access: an operator grant plus a robot request, authorized offline. */
/* ------------------------------------------------------------------ */

type AccessScenario = 'open' | 'admin' | 'expired' | 'other';

const ACCESS_SCENARIOS: Array<{ id: AccessScenario; label: string }> = [
  { id: 'open', label: 'Robot A asks to open door-3, inside the window' },
  { id: 'admin', label: 'Robot A asks to unlock_admin on door-3' },
  { id: 'expired', label: 'Robot A asks to open door-3 after the window closes' },
  { id: 'other', label: 'A different robot presents Robot A’s grant' },
];

function Access() {
  const [scenario, setScenario] = useState<AccessScenario>('open');

  const request = {
    open: { robot: 'did:web:robot-a', op: 'open', when: 't+05:00' },
    admin: { robot: 'did:web:robot-a', op: 'unlock_admin', when: 't+05:00' },
    expired: { robot: 'did:web:robot-a', op: 'open', when: 't+02:00:00' },
    other: { robot: 'did:web:robot-b', op: 'open', when: 't+05:00' },
  }[scenario];

  const verdict = {
    open: { ok: true, reason: 'authorized' },
    admin: { ok: false, reason: 'operation not permitted by the grant' },
    expired: { ok: false, reason: 'grant invalid or out of window' },
    other: { ok: false, reason: 'grant and request name different robots' },
  }[scenario];

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          The facility operator signs an access grant naming the resource, the operations it permits, an optional zone,
          and a time window. The robot signs a request for one operation. The door authorizes it offline, with no call to
          a server.
        </p>
        <div className="eyebrow-faint mb-2">Choose what the robot asks for</div>
        <div className={styles.controls}>
          {ACCESS_SCENARIOS.map((s) => (
            <button
              key={s.id}
              className={`${styles.radio}${scenario === s.id ? ' ' + styles.on : ''}`}
              onClick={() => setScenario(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>
      <div className={styles.stage}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Operator grant (signed)</div>
          <div className={styles.mono}>
            robot: did:web:robot-a
            <br />
            resource: door-3 · operations: [open, close] · zone: cell-3
            <br />
            window: t0 &rarr; t0 + 3600s
          </div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Robot request (signed)</div>
          <div className={styles.mono}>
            robot: {request.robot}
            <br />
            resource: door-3 · operation: {request.op} · at: {request.when}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}>
            {verdict.ok ? '✓ AUTHORIZED' : '✕ REFUSED'}
          </span>
          <span className={styles.reason}>{verdict.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Fusion: input frames bound to a fused world model.                  */
/* ------------------------------------------------------------------ */

type FusionScenario = 'honest' | 'tamper' | 'drop';

const FUSION_SCENARIOS: Array<{ id: FusionScenario; label: string }> = [
  { id: 'honest', label: 'Fuse three signed frames into the world model' },
  { id: 'tamper', label: 'Alter the fused output after signing' },
  { id: 'drop', label: 'Fuse from an input the robot never recorded' },
];

function Fusion() {
  const [scenario, setScenario] = useState<FusionScenario>('honest');

  const verdict = {
    honest: { ok: true, reason: 'verified · digest and inputs match' },
    tamper: { ok: false, reason: 'fused output hash does not match' },
    drop: { ok: false, reason: 'input frame not in the perception log' },
  }[scenario];

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          A robot fuses camera, lidar, and radar into one world model and acts on that. The attestation binds the fused
          output to the exact set of input frame hashes and the fusion method, so a manipulated result or a dropped input
          is detectable.
        </p>
        <div className="eyebrow-faint mb-2">Try it as the robot</div>
        <div className={styles.controls}>
          {FUSION_SCENARIOS.map((s) => (
            <button
              key={s.id}
              className={`${styles.radio}${scenario === s.id ? ' ' + styles.on : ''}`}
              onClick={() => setScenario(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>
      <div className={styles.stage}>
        <div className={styles.flow}>
          <span className={styles.frame}>camera</span>
          <span className={styles.frame}>lidar</span>
          <span className={`${styles.frame}${scenario === 'drop' ? ' ' + styles.dropped : ''}`}>radar</span>
          <span className={styles.arrow}>&rarr;</span>
          <span className={`${styles.world}${scenario === 'tamper' ? ' ' + styles.tampered : ''}`}>world model</span>
        </div>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Fused attestation (signed)</div>
          <div className={styles.mono}>
            method: occupancy-grid-v1
            <br />
            inputs: [uCAM, uLID, {scenario === 'drop' ? 'uPHANTOM' : 'uRAD'}]
            <br />
            inputsDigest: uaDpZB… · outputHash: {scenario === 'tamper' ? 'u-ALTERED…' : 'u-IyAz…'}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}>
            {verdict.ok ? '✓ VERIFIED' : '✕ DETECTED'}
          </span>
          <span className={styles.reason}>{verdict.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Wear: the capability envelope shrinks with the attested wear level. */
/* ------------------------------------------------------------------ */

const BASE_CAPS: Array<{ key: string; label: string; base: number; unit: string }> = [
  { key: 'force', label: 'max force', base: 80, unit: 'N' },
  { key: 'speed', label: 'max speed', base: 1.5, unit: 'm/s' },
  { key: 'near', label: 'near humans', base: 0.25, unit: 'm/s' },
];

function Wear() {
  const [wear, setWear] = useState(25);
  const factor = 1 - wear / 100;

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          A robot signs its own wear level, bound to its identity and hash-linked over time. A deterministic rule scales
          its force and speed caps down by that level, and the narrowed scope is a valid attenuation of the original, so a
          worn robot stays inside a tighter, verifiable envelope than the limit it shipped with.
        </p>
        <div className="eyebrow-faint mb-2">Drag the attested wear level</div>
        <div className={styles.sliderRow}>
          <input
            type="range"
            min={0}
            max={100}
            value={wear}
            onChange={(e) => setWear(Number(e.target.value))}
            className={styles.slider}
            aria-label="wear level"
          />
          <span className={styles.wearVal}>{wear}%</span>
        </div>
      </div>
      <div className={styles.stage}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Narrowed capability scope</div>
          <div className={styles.capRow}>
            {BASE_CAPS.map((c) => {
              const now = c.base * factor;
              return (
                <div key={c.key} className={styles.cap}>
                  <span>{c.label}</span>
                  <span className={styles.track}>
                    <span className={styles.fill} style={{ width: `${factor * 100}%` }} />
                  </span>
                  <span className={styles.capNum}>
                    {Number(now.toFixed(3))} {c.unit}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: ALLOW, borderColor: ALLOW }}>
            {'✓ VALID ATTENUATION'}
          </span>
          <span className={styles.reason}>every cap is at or below the original</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function RoboticsDemos() {
  return (
    <>
      <section id="access" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ I</span>
            <h2>Infrastructure access</h2>
          </div>
          <p className="eyebrow mb-6">A robot opens a door with a grant the door checks offline · vouch.robotics.access</p>
          <Access />
        </div>
      </section>

      <section id="fusion" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ II</span>
            <h2>Fused-sensor provenance</h2>
          </div>
          <p className="eyebrow mb-6">The world model a robot acts on is bound to the frames that made it · vouch.robotics.fusion</p>
          <Fusion />
        </div>
      </section>

      <section id="wear" className="scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ III</span>
            <h2>Wear and degradation</h2>
          </div>
          <p className="eyebrow mb-6">A worn robot narrows its own envelope, verifiably · vouch.robotics.wear</p>
          <Wear />
        </div>
      </section>
    </>
  );
}
