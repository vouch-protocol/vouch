/*
 * Delegation chain verification for the demo, composed from the Vouch Protocol
 * WASM core. The core checks every grant's eddsa-jcs-2022 proof, resolves
 * did:key identities offline, verifies the leaf credential, and runs the
 * non-expansion rule (validateDelegationChain). The order of the checks and the
 * reason codes follow Specification 9.3 and test-vectors/delegation-chain.
 */

export type Core = {
  ed25519FromDidKey: (did: string) => string;
  verifyProof: (credentialJson: string, publicB64: string) => boolean;
  verify: (credentialJson: string, publicB64: string, nowIso: string, skewSeconds: number) => string;
  validateDelegationChain: (requestJson: string) => string;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

const SKEW_SECONDS = 30;

function issuerDid(credential: Json): string | null {
  let issuer = credential?.issuer;
  if (Array.isArray(issuer)) issuer = issuer[0];
  if (issuer && typeof issuer === 'object') issuer = issuer.id;
  return typeof issuer === 'string' ? issuer : null;
}

function didKeyPublic(core: Core, did: string): string | null {
  if (!did.startsWith('did:key:')) return null;
  try {
    return core.ed25519FromDidKey(did);
  } catch {
    return null;
  }
}

function proofMembers(grant: Json): Json[] {
  const raw = grant.proof;
  return (Array.isArray(raw) ? raw : [raw]).filter((p) => p && typeof p === 'object');
}

function grantProofValid(core: Core, grant: Json, issuer: string, publicB64: string): boolean {
  for (const proof of proofMembers(grant)) {
    if (proof.cryptosuite != null && proof.cryptosuite !== 'eddsa-jcs-2022') continue;
    if (proof.proofPurpose !== 'assertionMethod') continue;
    const vm = proof.verificationMethod;
    if (typeof vm !== 'string' || vm.split('#')[0] !== issuer) continue;
    const rest = { ...grant };
    delete rest.proof;
    try {
      if (core.verifyProof(JSON.stringify({ ...rest, proof }), publicB64)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

function proofBinding(grant: Json): string {
  const members = proofMembers(grant);
  const classical = members.find((p) => p.cryptosuite === 'eddsa-jcs-2022');
  const pick = classical ?? members.find((p) => p.proofValue);
  return pick?.proofValue ?? '';
}

function parseTime(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

function capabilityView(credential: Json): Json {
  const intent = credential?.credentialSubject?.intent ?? {};
  const view: Json = {
    issuer: issuerDid(credential),
    subject: intent.delegatee,
    intent: {} as Json,
  };
  for (const k of ['action', 'target', 'resource', 'amount']) {
    if (k in intent) view.intent[k] = intent[k];
  }
  for (const k of ['validFrom', 'validUntil']) {
    if (k in credential) view[k] = credential[k];
  }
  for (const k of ['rate', 'policy']) {
    if (k in intent) view[k] = intent[k];
  }
  return view;
}

/** Returns null for a valid chain, otherwise a stable reason code. */
export function verifyDelegationChain(
  core: Core,
  credential: Json,
  trustedRoots: string[],
  nowIso: string,
): string | null {
  const chain = credential?.credentialSubject?.delegationChain;
  if (!chain) return null;
  if (!Array.isArray(chain)) return 'malformed_delegation';
  const now = Date.parse(nowIso);
  const grants: Json[] = [];

  for (const link of chain) {
    if (!link || typeof link.issuer !== 'string' || typeof link.subject !== 'string') {
      return 'malformed_delegation';
    }
    const grant = link.parentCredential;
    if (!grant || typeof grant !== 'object' || !grant.proof) return 'delegation_link_unsigned';
    const grantIssuer = issuerDid(grant);
    if (grantIssuer === null || grantIssuer !== link.issuer) return 'delegation_link_issuer_mismatch';
    const publicB64 = didKeyPublic(core, grantIssuer);
    if (!publicB64) return 'delegation_issuer_key_unresolved';
    if (!grantProofValid(core, grant, grantIssuer, publicB64)) return 'delegation_signature_invalid';
    if (link.parentProofValue != null && link.parentProofValue !== proofBinding(grant).slice(0, 64)) {
      return 'delegation_link_tampered';
    }
    const delegatee = grant.credentialSubject?.intent?.delegatee;
    if (!delegatee) return 'delegation_no_delegatee';
    if (delegatee !== link.subject) return 'delegation_subject_mismatch';
    const from = parseTime(grant.validFrom);
    const until = parseTime(grant.validUntil);
    if (from === null || until === null) return 'malformed_delegation';
    if ((now - until) / 1000 > SKEW_SECONDS) return 'delegation_expired';
    if ((from - now) / 1000 > SKEW_SECONDS) return 'delegation_not_yet_valid';
    grants.push(grant);
  }

  for (let i = 1; i < chain.length; i++) {
    if (chain[i - 1].subject !== chain[i].issuer) return 'delegation_subject_issuer_mismatch';
  }
  if (chain[chain.length - 1].subject !== issuerDid(credential)) return 'delegation_subject_issuer_mismatch';
  if (!trustedRoots.includes(chain[0].issuer)) return 'untrusted_principal';

  // Non-expansion: every grant, then the credential itself, must stay inside its parent.
  const views = [...grants, credential].map(capabilityView);
  views[views.length - 1].subject = views[views.length - 1].issuer;
  const verdict = JSON.parse(
    core.validateDelegationChain(JSON.stringify({ chain: views, nowIso, clockSkewSeconds: SKEW_SECONDS })),
  );
  if (!verdict.valid) {
    return verdict.code === 'scope_exceeds_parent' ? `scope_exceeds_parent:${verdict.dimension}` : verdict.code;
  }
  return null;
}

export type Verdict = {
  allowed: boolean;
  /** Reason code from the chain check, or null when the chain verified. */
  chainReason: string | null;
  /** Whether the holder's own signature and validity window checked out. */
  holderValid: boolean;
  /** The core's own all-in-one verdict (proof, window, and embedded chain). */
  coreAccepts: boolean;
};

/** Verify the way a calendar API would: holder signature, chain, root. */
export function verifyAction(core: Core, credential: Json, trustedRoots: string[], nowIso: string): Verdict {
  const chainReason = verifyDelegationChain(core, credential, trustedRoots, nowIso);
  let holderValid = false;
  let coreAccepts = false;
  const pub = didKeyPublic(core, issuerDid(credential) ?? '');
  if (pub) {
    try {
      const r = JSON.parse(core.verify(JSON.stringify(credential), pub, nowIso, SKEW_SECONDS));
      holderValid = r.proofValid === true && r.timeValid === true;
      coreAccepts = r.valid === true;
    } catch {
      holderValid = false;
    }
  }
  return { allowed: chainReason === null && holderValid && coreAccepts, chainReason, holderValid, coreAccepts };
}

/** Edit the root grant after it was signed, as an attacker would. */
export function tamperRootGrant(credential: Json, action: string[]): Json {
  const copy = JSON.parse(JSON.stringify(credential));
  copy.credentialSubject.delegationChain[0].parentCredential.credentialSubject.intent.action = action;
  return copy;
}
