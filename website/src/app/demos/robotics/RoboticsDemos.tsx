'use client';

import React, { useState } from 'react';

import styles from './RoboticsDemos.module.css';

/**
 * Interactive demos for eight robotics capabilities: infrastructure access
 * (vouch.robotics.access), fused-sensor provenance (vouch.robotics.fusion), wear
 * and degradation (vouch.robotics.wear), bystander consent (vouch.robotics.consent),
 * teleoperation handoff (vouch.robotics.teleop), operating-domain conformance
 * (vouch.robotics.odd), swarm accountability (vouch.robotics.swarm), and safe human
 * handover (vouch.robotics.handover). Each mirrors the real credential shapes and the
 * real verification logic, rendered as an on-brand illustration rather than a live
 * signature so it runs with no network call. Burgundy doubles as refuse, a
 * parchment-harmonized green marks allow, and both read on either theme.
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
/* Consent: a bystander token and the robot's evidence, bound to one capture. */
/* ------------------------------------------------------------------ */

type ConsentScenario = 'explicit' | 'replay' | 'notice' | 'redacted';

const CONSENT_SCENARIOS: Array<{ id: ConsentScenario; label: string }> = [
  { id: 'explicit', label: 'A bystander consents to this capture' },
  { id: 'replay', label: 'Reuse that consent for a different capture' },
  { id: 'notice', label: 'Record under posted notice, no token' },
  { id: 'redacted', label: 'Redact the capture instead' },
];

function Consent() {
  const [scenario, setScenario] = useState<ConsentScenario>('explicit');

  const basis = {
    explicit: 'explicit-consent',
    replay: 'explicit-consent',
    notice: 'posted-notice',
    redacted: 'redacted',
  }[scenario];

  const verdict = {
    explicit: { ok: true, reason: 'verified · token bound to this capture' },
    replay: { ok: false, reason: 'token is bound to a different capture' },
    notice: { ok: true, reason: 'verified · posted-notice basis' },
    redacted: { ok: true, reason: 'verified · redaction applied' },
  }[scenario];

  const showToken = scenario === 'explicit' || scenario === 'replay';

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          A robot that captures people records the basis it acted on, bound to the capture by its hash and holding only
          hashes, never an image or anyone&apos;s identity. A bystander signs consent over one capture, so it cannot be
          replayed to another recording.
        </p>
        <div className="eyebrow-faint mb-2">Choose the situation</div>
        <div className={styles.controls}>
          {CONSENT_SCENARIOS.map((s) => (
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
          <div className={styles.cardLabel}>Robot evidence (signed)</div>
          <div className={styles.mono}>
            captureHash: {scenario === 'replay' ? 'uCAP-B…' : 'uCAP-A…'}
            <br />
            basis: {basis}
            {scenario === 'redacted' ? (
              <>
                <br />
                redactionHash: uRED…
              </>
            ) : null}
          </div>
        </div>
        {showToken ? (
          <div className={styles.card}>
            <div className={styles.cardLabel}>Bystander token (signed)</div>
            <div className={styles.mono}>
              bystander: did:web:person-1
              <br />
              captureHash: uCAP-A… · robot: did:web:robot-a
            </div>
          </div>
        ) : null}
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}>
            {verdict.ok ? '✓ VERIFIED' : '✕ REFUSED'}
          </span>
          <span className={styles.reason}>{verdict.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Teleop: who or what was in control, across handoffs.                */
/* ------------------------------------------------------------------ */

type TeleopScenario = 'takeover' | 'return' | 'gap';

const TELEOP_SCENARIOS: Array<{ id: TeleopScenario; label: string }> = [
  { id: 'takeover', label: 'Autonomy hands control to operator Jane' },
  { id: 'return', label: 'Jane hands control back to autonomy' },
  { id: 'gap', label: 'Autonomy reclaims control while Jane still holds it' },
];

function Teleop() {
  const [scenario, setScenario] = useState<TeleopScenario>('takeover');

  const view = {
    takeover: { at: 'operator-jane', mode: 'teleoperated', ok: true, reason: 'continuous, single-held' },
    return: { at: 'autopilot', mode: 'autonomous', ok: true, reason: 'continuous, single-held' },
    gap: { at: 'autopilot', mode: 'autonomous', ok: false, reason: 'gap and overlap at the seam' },
  }[scenario];

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          Control of a robot passes between an autonomous policy and human teleoperators. Each transfer is signed by the
          party taking control, so the chain answers who or what was in control at any moment, and a continuity check
          catches a seam where no one, or everyone, held it.
        </p>
        <div className="eyebrow-faint mb-2">Choose what happens</div>
        <div className={styles.controls}>
          {TELEOP_SCENARIOS.map((s) => (
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
          <div className={styles.cardLabel}>Control handoff (signed by receiver)</div>
          <div className={styles.mono}>
            robot: did:web:robot-a
            <br />
            in control at t+05:00: {view.at} · mode: {view.mode}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: view.ok ? ALLOW : DENY, borderColor: view.ok ? ALLOW : DENY }}>
            {view.ok ? '✓ CONTINUOUS' : '✕ DISCONTINUITY'}
          </span>
          <span className={styles.reason}>{view.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* ODD: did the robot stay inside its certified operating domain.      */
/* ------------------------------------------------------------------ */

type OddScenario = 'inside' | 'speed' | 'zone' | 'weather';

const ODD_SCENARIOS: Array<{ id: OddScenario; label: string }> = [
  { id: 'inside', label: 'Ran at 2.4 m/s in yard-north, clear and midday' },
  { id: 'speed', label: 'Ran at 4.5 m/s (over the speed regime)' },
  { id: 'zone', label: 'Strayed into the street (outside the geofence)' },
  { id: 'weather', label: 'Ran with visibility below the rated minimum' },
];

function Odd() {
  const [scenario, setScenario] = useState<OddScenario>('inside');

  const verdict = {
    inside: { ok: true, reason: 'in domain' },
    speed: { ok: false, reason: 'speed_out_of_domain: 4.5 > 3.0' },
    zone: { ok: false, reason: 'zone_out_of_domain: [street]' },
    weather: { ok: false, reason: 'condition_out_of_domain: minVisibilityM' },
  }[scenario];

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          An operator certifies the robot's operating domain: the zones, a speed regime, weather bounds, and the hours it
          is rated for. The robot signs what it observed each interval, and a deterministic check confirms it stayed in
          domain, or names the dimension it left on.
        </p>
        <div className="eyebrow-faint mb-2">Choose what the robot observed</div>
        <div className={styles.controls}>
          {ODD_SCENARIOS.map((s) => (
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
          <div className={styles.cardLabel}>Certified operating domain (operator-signed)</div>
          <div className={styles.mono}>
            zones: [yard-north, yard-south] · maxSpeed: 3.0 m/s
            <br />
            conditions: minVisibilityM 50 · hours: 06:00 to 20:00
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}>
            {verdict.ok ? '✓ IN DOMAIN' : '✕ OUT OF DOMAIN'}
          </span>
          <span className={styles.reason}>{verdict.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Swarm: a collective action attributed to admitted members.          */
/* ------------------------------------------------------------------ */

type SwarmScenario = 'members' | 'nonmember';

const SWARM_SCENARIOS: Array<{ id: SwarmScenario; label: string }> = [
  { id: 'members', label: 'Robots A and B (both admitted) lift a beam' },
  { id: 'nonmember', label: 'The action names robot Z, who was never admitted' },
];

function Swarm() {
  const [scenario, setScenario] = useState<SwarmScenario>('members');

  const verdict = {
    members: { ok: true, reason: 'every participant is an admitted member' },
    nonmember: { ok: false, reason: 'unverified participant: did:web:robot-z' },
  }[scenario];

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          A coordinator admits robots to a swarm with signed memberships. When the swarm takes an action together, the
          coordinator attributes it to the participants, and each one is checked against a membership, so a collective
          action ties only to admitted members.
        </p>
        <div className="eyebrow-faint mb-2">Choose who took part</div>
        <div className={styles.controls}>
          {SWARM_SCENARIOS.map((s) => (
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
          <div className={styles.cardLabel}>Collective action (coordinator-signed)</div>
          <div className={styles.mono}>
            swarm: swarm-42 · action: lift-beam
            <br />
            participants: {scenario === 'nonmember' ? '[robot-a, robot-z]' : '[robot-a, robot-b]'}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}>
            {verdict.ok ? '✓ ATTRIBUTED' : '✕ FLAGGED'}
          </span>
          <span className={styles.reason}>{verdict.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Handover: robot-to-human release inside the near-human envelope.     */
/* ------------------------------------------------------------------ */

function Handover() {
  const [force, setForce] = useState(18);
  const [speed, setSpeed] = useState(15);
  const maxForce = 40;
  const maxSpeed = 25; // hundredths of m/s, so 0.25 m/s
  const inEnvelope = force <= maxForce && speed <= maxSpeed;

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          Handing an object to a person puts a human hand inside the robot's envelope at the instant of release. The
          robot signs the force and speed at that moment, checked against the near-human safety scope, and the recipient
          can sign a receipt bound to the one handover.
        </p>
        <div className="eyebrow-faint mb-2">Set the release conditions</div>
        <div className={styles.sliderRow}>
          <input type="range" min={5} max={90} value={force} onChange={(e) => setForce(Number(e.target.value))} className={styles.slider} aria-label="force" />
          <span className={styles.wearVal}>{force} N</span>
        </div>
        <div className={styles.sliderRow}>
          <input type="range" min={5} max={90} value={speed} onChange={(e) => setSpeed(Number(e.target.value))} className={styles.slider} aria-label="speed" />
          <span className={styles.wearVal}>{(speed / 100).toFixed(2)} m/s</span>
        </div>
      </div>
      <div className={styles.stage}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Handover (robot-signed) + receipt (recipient-signed)</div>
          <div className={styles.mono}>
            robot: did:web:robot-a → recipient: did:web:person-1
            <br />
            object: tote-7 · force: {force} N · speed: {(speed / 100).toFixed(2)} m/s
            <br />
            near-human scope: maxForce 40 N · maxSpeed 0.25 m/s
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: inEnvelope ? ALLOW : DENY, borderColor: inEnvelope ? ALLOW : DENY }}>
            {inEnvelope ? '✓ IN ENVELOPE' : '✕ OUT OF ENVELOPE'}
          </span>
          <span className={styles.reason}>{inEnvelope ? 'released safely, receipt binds to this handover' : 'force or speed exceeds the near-human limit'}</span>
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

      <section id="wear" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ III</span>
            <h2>Wear and degradation</h2>
          </div>
          <p className="eyebrow mb-6">A worn robot narrows its own envelope, verifiably · vouch.robotics.wear</p>
          <Wear />
        </div>
      </section>

      <section id="consent" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ IV</span>
            <h2>Bystander consent</h2>
          </div>
          <p className="eyebrow mb-6">Consent is bound to one capture and cannot be replayed · vouch.robotics.consent</p>
          <Consent />
        </div>
      </section>

      <section id="teleop" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ V</span>
            <h2>Teleoperation handoff</h2>
          </div>
          <p className="eyebrow mb-6">Who or what was in control of a robot at any moment · vouch.robotics.teleop</p>
          <Teleop />
        </div>
      </section>

      <section id="odd" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ VI</span>
            <h2>Operating-domain conformance</h2>
          </div>
          <p className="eyebrow mb-6">A robot proves it stayed inside its certified domain · vouch.robotics.odd</p>
          <Odd />
        </div>
      </section>

      <section id="swarm" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ VII</span>
            <h2>Swarm accountability</h2>
          </div>
          <p className="eyebrow mb-6">A collective action ties to the members that performed it · vouch.robotics.swarm</p>
          <Swarm />
        </div>
      </section>

      <section id="handover" className="scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ VIII</span>
            <h2>Safe human handover</h2>
          </div>
          <p className="eyebrow mb-6">A robot-to-human release, inside the near-human envelope · vouch.robotics.handover</p>
          <Handover />
        </div>
      </section>
    </>
  );
}
