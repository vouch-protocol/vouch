'use client';

import React, { useMemo, useState } from 'react';

import styles from './IdentityDemos.module.css';

/**
 * Interactive demos for cross-device identity (vouch.fleet: per-device keys and
 * delegation, DeviceRegistry revocation), root recovery (vouch.recovery: Shamir
 * secret sharing), and FROST(Ed25519) threshold signing (vouch.threshold). Each
 * mirrors the real credential shapes and the real verification logic, rendered
 * as an on-brand illustration rather than a live signature so it runs with no
 * network call. Burgundy doubles as deny/refuse, a parchment-harmonized green
 * marks allow, and both read on either theme.
 */

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

/* ------------------------------------------------------------------ */
/* Enrollment: a root delegates to a device, then revokes it.          */
/* ------------------------------------------------------------------ */

type EnrollScenario = 'ok' | 'revoked' | 'other-device' | 'exceeds';

const ENROLL_SCENARIOS: Array<{ id: EnrollScenario; label: string }> = [
  { id: 'ok', label: 'Phone charges within its granted scope' },
  { id: 'revoked', label: 'Phone was lost, and the root revoked it' },
  { id: 'other-device', label: 'A different device presents the phone’s grant' },
  { id: 'exceeds', label: 'Phone charges a resource the grant never named' },
];

function Enrollment() {
  const [scenario, setScenario] = useState<EnrollScenario>('ok');

  const issuer = scenario === 'other-device' ? 'did:key:z6Mk…tablet' : 'did:key:z6Mk…phone';

  const verdict = {
    ok: { ok: true, reason: 'chain verifies · resource narrows · window nests' },
    revoked: { ok: false, reason: 'delegation_revoked · phone is in the DeviceRegistry' },
    'other-device': { ok: false, reason: 'issuer_mismatch · grant names did:key:z6Mk…phone as delegatee' },
    exceeds: { ok: false, reason: 'resource_not_narrowed · invoices/42/refund is outside invoices' },
  }[scenario];

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          Each device mints its own key locally, and the root identity signs a scoped, time-bound grant to that
          device&apos;s DID. The device signs its actions with its own key, chained under the grant, so the private key
          never travels between devices. A verifier ties the action back to the trusted root.
        </p>
        <div className="eyebrow-faint mb-2">Choose what happens</div>
        <div className={styles.controls}>
          {ENROLL_SCENARIOS.map((s) => (
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
          <div className={styles.cardLabel}>Root grant (signed)</div>
          <div className={styles.mono}>
            issuer: did:web:alice.example
            <br />
            delegatee: did:key:z6Mk…phone
            <br />
            action: charge · target: api.bank · resource: https://api.bank/invoices
          </div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Device action (signed)</div>
          <div className={styles.mono}>
            issuer: {issuer}
            <br />
            action: charge · resource: https://api.bank/invoices/42
            {scenario === 'exceeds' ? '/refund' : ''}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}>
            {verdict.ok ? '✓ VERIFIED' : '✕ REJECTED'}
          </span>
          <span className={styles.reason}>{verdict.reason}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Recovery: pick which shares rebuild the root, and which do not.     */
/* ------------------------------------------------------------------ */

const TOTAL_SHARES = 5;
const THRESHOLD = 3;
const ORIGINAL_DID = 'did:key:z6MkhaXgBZD9…9F5G';
const WRONG_DIDS = ['did:key:z6MkqR3v…c2Lp', 'did:key:z6MksT8n…a91X'];

function Recovery() {
  const [held, setHeld] = useState<Set<number>>(new Set([0, 2]));

  const toggle = (i: number) => {
    setHeld((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  // A deterministic, illustrative stand-in for "wrong number of shares
  // reconstructs a different DID, not an error": the real property under
  // test is that interpolation with too few points yields the wrong value,
  // not a crash.
  const wrongDid = useMemo(() => WRONG_DIDS[held.size % WRONG_DIDS.length], [held.size]);

  const count = held.size;
  const met = count >= THRESHOLD;

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          The root identity&apos;s seed splits into {TOTAL_SHARES} shares, any {THRESHOLD} of which rebuild it exactly.
          Distribute them to guardians or separate locations. Fewer than the threshold combine to a share-length result,
          but not the original identity, and reveal nothing about it.
        </p>
        <div className="eyebrow-faint mb-2">Choose which shares you hold</div>
        <div className={styles.shareRow}>
          {Array.from({ length: TOTAL_SHARES }, (_, i) => (
            <button
              key={i}
              className={`${styles.share}${held.has(i) ? ' ' + styles.held : ''}`}
              onClick={() => toggle(i)}
            >
              share {i + 1}
            </button>
          ))}
        </div>
        <div className={styles.shareCount}>
          holding {count} of {TOTAL_SHARES} · need {THRESHOLD}
        </div>
      </div>
      <div className={styles.stage}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Original root identity</div>
          <div className={styles.mono}>{ORIGINAL_DID}</div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Recovered from {count} share{count === 1 ? '' : 's'}</div>
          <div className={styles.mono}>{count === 0 ? '· nothing to combine ·' : met ? ORIGINAL_DID : wrongDid}</div>
        </div>
        <div className={styles.verdict}>
          <span
            className={styles.badge}
            style={{ color: met ? ALLOW : DENY, borderColor: met ? ALLOW : DENY }}
          >
            {count === 0 ? '· IDLE ·' : met ? '✓ SAME IDENTITY' : '✕ WRONG IDENTITY'}
          </span>
          <span className={styles.reason}>
            {count === 0
              ? 'select at least one share'
              : met
                ? 'threshold met · recovered seed signs identically to the original'
                : 'below threshold · a structurally valid but wrong seed, not an error'}
          </span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Threshold signing: any 2 of 3 custodians sign, same group key.      */
/* ------------------------------------------------------------------ */

const CUSTODIANS = ['Custodian A', 'Custodian B', 'Custodian C'] as const;
const MIN_SIGNERS = 2;

function ThresholdSigning() {
  const [signing, setSigning] = useState<Set<number>>(new Set([0, 1]));

  const toggle = (i: number) => {
    setSigning((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  const count = signing.size;
  const met = count >= MIN_SIGNERS;
  const names = CUSTODIANS.filter((_, i) => signing.has(i));

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          A key is split among {CUSTODIANS.length} custodians so that any {MIN_SIGNERS} of them can sign together, and the
          full private key never exists whole at any point, not even during signing. Whichever {MIN_SIGNERS} sign, the
          result is the same standard Ed25519 signature over the same group public key.
        </p>
        <div className="eyebrow-faint mb-2">Choose who signs</div>
        <div className={styles.custodianRow}>
          {CUSTODIANS.map((name, i) => (
            <button
              key={name}
              className={`${styles.custodian}${signing.has(i) ? ' ' + styles.signing : ''}`}
              onClick={() => toggle(i)}
            >
              {name}
            </button>
          ))}
        </div>
      </div>
      <div className={styles.stage}>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Group public key</div>
          <div className={styles.mono}>uGrpPub7f3aC…e91D (fixed, regardless of who signs)</div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardLabel}>Ceremony</div>
          <div className={styles.mono}>
            {count === 0
              ? '· no one has committed ·'
              : `${names.join(' + ')} commit, produce a signature share each, aggregate`}
          </div>
        </div>
        <div className={styles.verdict}>
          <span className={styles.badge} style={{ color: met ? ALLOW : DENY, borderColor: met ? ALLOW : DENY }}>
            {met ? '✓ SIGNATURE VERIFIES' : '✕ BELOW THRESHOLD'}
          </span>
          <span className={styles.reason}>
            {met
              ? 'aggregate self-verifies as a standard Ed25519 signature'
              : `need at least ${MIN_SIGNERS} of ${CUSTODIANS.length} custodians to sign`}
          </span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function IdentityDemos() {
  return (
    <>
      <section id="enrollment" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ I</span>
            <h2>Cross-device enrollment and revocation</h2>
          </div>
          <p className="eyebrow mb-6">One identity across your devices, and revoking one you lost · vouch.fleet</p>
          <Enrollment />
        </div>
      </section>

      <section id="recovery" className="border-b border-rule scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ II</span>
            <h2>Root recovery</h2>
          </div>
          <p className="eyebrow mb-6">Rebuild the root from a threshold of Shamir shares · vouch.recovery</p>
          <Recovery />
        </div>
      </section>

      <section id="threshold-signing" className="scroll-mt-24">
        <div className="container-wide py-16">
          <div className="section-heading">
            <span className="num">§ III</span>
            <h2>Threshold signing</h2>
          </div>
          <p className="eyebrow mb-6">Any threshold of custodians signs, the full key never exists whole · vouch.threshold</p>
          <ThresholdSigning />
        </div>
      </section>
    </>
  );
}
