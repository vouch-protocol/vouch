'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';

import styles from './RootOfTrustDemos.module.css';

/**
 * Interactive demo for the Root of Trust for Machine Identity capability. Unlike
 * the illustrative demos elsewhere on the site, every signature and every verify
 * result here is produced by the Vouch Protocol WASM core in the visitor's own
 * browser: three throwaway did:key identities are generated, three credentials
 * are signed with real eddsa-jcs-2022 Data Integrity proofs, and a verifier that
 * pins only the root DID checks the chain offline. The forgery path signs a
 * genuine but untrusted credential and lets the verifier reject it on its own.
 *
 * Burgundy doubles as reject, a parchment-harmonized green marks verified, and
 * both read on either theme.
 */

const ALLOW = '#3f7d55';
const DENY = 'rgb(var(--color-burgundy))';

/* ------------------------------------------------------------------ */
/* WASM core loader. The build copies the published npm package          */
/* @vouch-protocol-official/core-wasm into /wasm at build time, and the   */
/* module is loaded from there at runtime so the Next static export never */
/* tries to bundle it and the binary is never committed to the repo.      */
/* ------------------------------------------------------------------ */

type Core = {
  generateEd25519: () => string;
  buildProof: (credentialJson: string, seedB64: string, verificationMethod: string, created: string) => string;
  verifyProof: (credentialJson: string, publicB64: string) => boolean;
};

let corePromise: Promise<Core> | null = null;

function loadCore(): Promise<Core> {
  if (!corePromise) {
    corePromise = (async () => {
      // new Function keeps both the bundler and the type checker out of the way,
      // so the module is fetched straight from /wasm at runtime.
      const dynamicImport = new Function('u', 'return import(u)') as (u: string) => Promise<Record<string, unknown>>;
      const mod = await dynamicImport('/wasm/vouch_core_wasm.js');
      await (mod.default as () => Promise<unknown>)();
      return mod as unknown as Core;
    })();
  }
  return corePromise;
}

/* ------------------------------------------------------------------ */
/* Credential shapes (Vouch Protocol Section 18) and the chain checks.  */
/* ------------------------------------------------------------------ */

const CONTEXT = ['https://www.w3.org/ns/credentials/v2', 'https://vouch-protocol.com/ns/v1'];
const CREATED = '2026-07-12T10:00:00Z';

const verificationMethod = (didKey: string) => `${didKey}#${didKey.slice('did:key:'.length)}`;

type Party = { seed: string; pub: string; did: string };

type SignedCredential = {
  '@context': string[];
  type: string[];
  issuer: string;
  credentialSubject: Record<string, unknown>;
  proof: { proofValue: string; [k: string]: unknown };
};

function newParty(core: Core): Party {
  const kp = JSON.parse(core.generateEd25519());
  return { seed: kp.seed_b64, pub: kp.public_b64, did: kp.did_key };
}

function signCredential(
  core: Core,
  unsigned: Omit<SignedCredential, 'proof'>,
  signer: Party,
): SignedCredential {
  const proof = JSON.parse(
    core.buildProof(JSON.stringify(unsigned), signer.seed, verificationMethod(signer.did), CREATED),
  );
  return { ...unsigned, proof };
}

type Chain = {
  root: Party;
  issuer: Party;
  agent: Party;
  attacker: Party;
  rootOfTrust: SignedCredential;
  recognition: SignedCredential;
  forgedRecognition: SignedCredential;
  identity: SignedCredential;
};

function buildChain(core: Core): Chain {
  const root = newParty(core);
  const issuer = newParty(core);
  const agent = newParty(core);
  const attacker = newParty(core);

  // The root anchors itself once: issuer, subject, and role are all the root.
  const rootOfTrust = signCredential(
    core,
    {
      '@context': CONTEXT,
      type: ['VerifiableCredential', 'VouchRootOfTrust'],
      issuer: root.did,
      credentialSubject: { id: root.did, role: 'root-of-trust' },
    },
    root,
  );

  // The root recognizes the issuer for one action.
  const recognitionSubject = {
    id: issuer.did,
    recognizedActions: ['issueAgentIdentity'],
    recognizedIn: root.did,
  };
  const recognition = signCredential(
    core,
    {
      '@context': CONTEXT,
      type: ['VerifiableCredential', 'RecognizedIssuerCredential'],
      issuer: root.did,
      credentialSubject: recognitionSubject,
    },
    root,
  );

  // A forged recognition of the same issuer, signed by an attacker's own root.
  const forgedRecognition = signCredential(
    core,
    {
      '@context': CONTEXT,
      type: ['VerifiableCredential', 'RecognizedIssuerCredential'],
      issuer: attacker.did,
      credentialSubject: { ...recognitionSubject, recognizedIn: attacker.did },
    },
    attacker,
  );

  // The recognized issuer binds the agent DID to its attributes.
  const identity = signCredential(
    core,
    {
      '@context': CONTEXT,
      type: ['VerifiableCredential', 'AgentIdentityCredential'],
      issuer: issuer.did,
      credentialSubject: {
        id: agent.did,
        identity: {
          owner: 'did:web:acme.example',
          model: 'orchestrator-v3',
          capabilityClass: 'payments.readonly',
        },
      },
    },
    issuer,
  );

  return { root, issuer, agent, attacker, rootOfTrust, recognition, forgedRecognition, identity };
}

type Check = { label: string; ok: boolean };
type Verdict = { ok: boolean; checks: Check[]; reason: string };

/**
 * A verifier that trusts exactly one key, the pinned root, checks the chain with
 * no network call: the recognition must be signed by the pinned root and name it,
 * and the identity must be signed by the issuer that recognition names.
 */
function verifyChain(core: Core, chain: Chain, mode: 'honest' | 'forged'): Verdict {
  const pinnedRootDid = chain.root.did;
  const pinnedRootPub = chain.root.pub;
  const recognition = mode === 'forged' ? chain.forgedRecognition : chain.recognition;
  const { identity, issuer } = chain;

  const recognitionSignedByRoot = core.verifyProof(JSON.stringify(recognition), pinnedRootPub);
  const recognitionNamesRoot = recognition.issuer === pinnedRootDid;
  const recognizedInRoot = recognition.credentialSubject.recognizedIn === pinnedRootDid;
  const recognizedActions = (recognition.credentialSubject.recognizedActions as string[]) || [];
  const actionRecognized = recognizedActions.includes('issueAgentIdentity');

  const recognizedIssuerDid = recognition.credentialSubject.id as string;
  const identitySignedByIssuer = core.verifyProof(JSON.stringify(identity), issuer.pub);
  const identityFromRecognizedIssuer = identity.issuer === recognizedIssuerDid;

  const checks: Check[] = [
    { label: 'recognition proof verifies against the pinned root key', ok: recognitionSignedByRoot },
    { label: 'recognition names the pinned root as issuer', ok: recognitionNamesRoot },
    { label: 'recognizedIn points at the pinned root', ok: recognizedInRoot },
    { label: 'issueAgentIdentity is a recognized action', ok: actionRecognized },
    { label: 'identity proof verifies against the recognized issuer key', ok: identitySignedByIssuer },
    { label: 'identity issuer matches the recognized issuer', ok: identityFromRecognizedIssuer },
  ];

  const ok = checks.every((c) => c.ok);
  const reason = ok
    ? 'recognition chains to the pinned root and the issuer signed the agent identity'
    : !recognitionSignedByRoot
      ? 'the recognition was signed by an unknown root, not the one this verifier pins'
      : 'the recognition does not chain to the pinned root';

  return { ok, checks, reason };
}

/* ------------------------------------------------------------------ */

const short = (did: string) => `${did.slice(0, 20)}…${did.slice(-6)}`;
const shortProof = (proofValue: string) => `${proofValue.slice(0, 28)}…`;

function RootOfTrust() {
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [chain, setChain] = useState<Chain | null>(null);
  const [mode, setMode] = useState<'honest' | 'forged'>('honest');
  const coreRef = useRef<Core | null>(null);

  const regenerate = useCallback(async () => {
    setStatus('loading');
    try {
      const core = await loadCore();
      coreRef.current = core;
      setChain(buildChain(core));
      setMode('honest');
      setStatus('ready');
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setStatus('error');
    }
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const core = await loadCore();
        if (!active) return;
        coreRef.current = core;
        setChain(buildChain(core));
        setStatus('ready');
      } catch (e) {
        if (!active) return;
        setErrorMsg(e instanceof Error ? e.message : String(e));
        setStatus('error');
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  // The core is loaded before any chain exists, so verification runs synchronously.
  const verdict = React.useMemo<Verdict | null>(() => {
    if (!chain || !coreRef.current) return null;
    return verifyChain(coreRef.current, chain, mode);
  }, [chain, mode]);

  const identityAttrs = chain
    ? (chain.identity.credentialSubject.identity as Record<string, string>)
    : null;

  return (
    <div className={styles.demo}>
      <div>
        <p className="text-ink-soft leading-relaxed mb-5">
          Machine identity anchors to a single root that is trusted once. The root recognizes an issuer for a named
          action, the issuer binds an agent&apos;s DID to its attributes, and a verifier that pins only the root DID checks
          the whole chain offline. Every key here is generated in your browser, used once, and never leaves it. The three
          signatures below are real eddsa-jcs-2022 proofs produced by the Vouch Protocol core compiled to WebAssembly.
        </p>

        <div className="eyebrow-faint mb-2">Who signed the recognition</div>
        <div className={styles.controls}>
          <button
            className={`${styles.radio}${mode === 'honest' ? ' ' + styles.on : ''}`}
            onClick={() => setMode('honest')}
            disabled={status !== 'ready'}
          >
            The real root recognizes the issuer
          </button>
          <button
            className={`${styles.radio}${mode === 'forged' ? ' ' + styles.on : ''}`}
            onClick={() => setMode('forged')}
            disabled={status !== 'ready'}
          >
            An attacker&apos;s root forges its own recognition
          </button>
        </div>

        <button className={styles.regen} onClick={regenerate} disabled={status === 'loading'}>
          {status === 'loading' ? 'generating keys…' : '↻ Mint fresh throwaway keys'}
        </button>

        <p className={styles.note}>
          The verifier trusts one key, the pinned root. Nothing else is configured. The chain verifies or fails on the
          cryptography alone.
        </p>
      </div>

      <div className={styles.stage}>
        {status === 'loading' && <div className={styles.loading}>Loading the WebAssembly core and generating identities…</div>}
        {status === 'error' && (
          <div className={styles.error}>
            The in-browser core could not load, so no signatures were produced. Nothing here is faked.
            <br />
            <span className={styles.mono}>{errorMsg}</span>
          </div>
        )}

        {status === 'ready' && chain && verdict && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel}>Three throwaway did:key identities</div>
              <div className={styles.mono}>
                root &nbsp;&nbsp;{short(chain.root.did)}
                <br />
                issuer&nbsp;{short(chain.issuer.did)}
                <br />
                agent&nbsp;&nbsp;{short(chain.agent.did)}
              </div>
            </div>

            <div className={styles.card}>
              <div className={styles.cardLabel}>Recognition · signed by {mode === 'forged' ? 'the attacker root' : 'the root'}</div>
              <div className={styles.mono}>
                type: RecognizedIssuerCredential
                <br />
                issuer: {short(mode === 'forged' ? chain.attacker.did : chain.root.did)}
                <br />
                recognizes: {short(chain.issuer.did)} · [issueAgentIdentity]
                <br />
                proofValue: {shortProof((mode === 'forged' ? chain.forgedRecognition : chain.recognition).proof.proofValue)}
              </div>
            </div>

            <div className={styles.card}>
              <div className={styles.cardLabel}>Agent identity · signed by the issuer</div>
              <div className={styles.mono}>
                type: AgentIdentityCredential
                <br />
                subject: {short(chain.agent.did)}
                <br />
                proofValue: {shortProof(chain.identity.proof.proofValue)}
              </div>
            </div>

            <div className={styles.card}>
              <div className={styles.cardLabel}>Verifier pins one key</div>
              <div className={styles.mono}>trusted root: {short(chain.root.did)}</div>
            </div>

            {verdict.ok && identityAttrs && (
              <div className={styles.card}>
                <div className={styles.cardLabel}>Recovered agent attributes</div>
                <div className={styles.mono}>
                  owner: {identityAttrs.owner}
                  <br />
                  model: {identityAttrs.model}
                  <br />
                  capabilityClass: {identityAttrs.capabilityClass}
                </div>
              </div>
            )}

            <div className={styles.checks}>
              {verdict.checks.map((c) => (
                <div key={c.label} className={styles.checkRow}>
                  <span className={styles.checkMark} style={{ color: c.ok ? ALLOW : DENY }}>
                    {c.ok ? '✓' : '✕'}
                  </span>
                  <span>{c.label}</span>
                </div>
              ))}
            </div>

            <div className={styles.verdict}>
              <span
                className={styles.badge}
                style={{ color: verdict.ok ? ALLOW : DENY, borderColor: verdict.ok ? ALLOW : DENY }}
              >
                {verdict.ok ? '✓ VERIFIED' : '✕ REJECTED'}
              </span>
              <span className={styles.reason}>{verdict.reason}</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

export default function RootOfTrustDemos() {
  return (
    <section id="anchor-once" className="scroll-mt-24">
      <div className="container-wide py-16">
        <div className="section-heading">
          <span className="num">§ I</span>
          <h2>Anchor once, verify offline</h2>
        </div>
        <p className="eyebrow mb-6">
          A pinned root recognizes an issuer, the issuer names the agent, and a verifier checks the chain · vouch.identity
        </p>
        <RootOfTrust />
      </div>
    </section>
  );
}
