/**
 * Root of Trust for Machine Identity (Vouch Protocol, TypeScript).
 *
 * Lets Vouch Protocol act as the trust anchor for AI agent and robot identity.
 * A verifier pins ONE Vouch root, then verifies any agent offline by walking:
 *
 *     action credential  ->  authority-issued identity credential
 *         ->  recognized-issuer credential  ->  Vouch root
 *
 * Three credential types compose this chain, all secured with the same
 * `eddsa-jcs-2022` Data Integrity proof used elsewhere in Vouch Protocol:
 *
 *   1. Root of Trust credential      self-issued by the root (issuer == subject)
 *   2. Recognized-issuer credential  issued by the root, naming an issuer that
 *                                    may attest agent or robot identity
 *   3. Agent identity credential     issued by a recognized issuer, binding an
 *                                    agent key to real attributes (issuer != subject)
 *
 * Mirrors `vouch/root_of_trust.py` with byte-identical output. Cross-language
 * interop is REQUIRED: Python and TypeScript produce identical proofValues and
 * verify each other's credentials.
 */

import * as crypto from 'crypto';

import { verifyProof } from './data-integrity';
import { decode as decodeMultikey } from './multikey';
import type { Signer } from './signer';
import type { CredentialPassport } from './types';
import { PROTOCOL_VERSION, VC_CONTEXT_V2, VC_TYPE, VOUCH_CONTEXT_V1 } from './vc';
import { verify as verifyCredential, Verifier } from './verifier';

// Credential type identifiers (the second entry in each `type` array).
export const ROOT_OF_TRUST_TYPE = 'VouchRootOfTrust';
export const RECOGNIZED_ISSUER_TYPE = 'RecognizedIssuerCredential';
export const AGENT_IDENTITY_TYPE = 'AgentIdentityCredential';

// Actions an issuer can be recognized to perform.
export const ACTION_ISSUE_AGENT_IDENTITY = 'issueAgentIdentity';
export const ACTION_ISSUE_ROBOT_IDENTITY = 'issueRobotIdentity';

// The three trust-layer credential types. A single credential must carry
// exactly one of these, otherwise one signed object could be replayed into a
// different slot of the chain (type confusion).
const TRUST_TYPES: readonly string[] = [
  ROOT_OF_TRUST_TYPE,
  RECOGNIZED_ISSUER_TYPE,
  AGENT_IDENTITY_TYPE,
];

// Default validity windows. Roots are long lived; issuer and identity
// credentials rotate more often. All are overridable per call.
const ROOT_VALID_SECONDS = 10 * 365 * 24 * 3600;
const ISSUER_VALID_SECONDS = 365 * 24 * 3600;
const IDENTITY_VALID_SECONDS = 365 * 24 * 3600;

/** Outcome of {@link verifyIdentityChain}. */
export interface IdentityChainResult {
  /** True only if every link verified and anchored to the pinned root. */
  ok: boolean;
  /** Structured failure reason when `ok` is false, else undefined. */
  reason?: string;
  /** The subject DID of the identity credential (the agent). */
  agentDid?: string;
  /** The recognized issuer that attested the agent identity. */
  issuerDid?: string;
  /** The pinned Vouch root the chain anchored to. */
  rootDid?: string;
  /** The identity attributes bound to the agent. */
  attributes?: Record<string, unknown>;
  /** The verified action passport when an action credential was supplied. */
  action?: CredentialPassport;
}

export interface BuildRootOfTrustOptions {
  /** Human-readable name of the root. */
  name: string;
  /** What the root anchors. Defaults to ["ai-agent", "robot"]. */
  scope?: string[];
  /** Validity window. Defaults to ten years. */
  validSeconds?: number;
  /** Override the issued-at moment (default: now). */
  validFrom?: Date;
  /** Override the proof timestamp (for reproducible test vectors). */
  created?: Date;
  /** Optional credential id. Defaults to a fresh UUID URN. */
  credentialId?: string;
}

export interface BuildRecognizedIssuerOptions {
  /** The DID being recognized as an issuer. */
  issuerDid: string;
  /** Actions the issuer may perform. Defaults to [ACTION_ISSUE_AGENT_IDENTITY]. */
  recognizedActions?: string[];
  /** Validity window. Defaults to one year. */
  validSeconds?: number;
  validFrom?: Date;
  created?: Date;
  /** Optional W3C `credentialStatus` entry for revocation. */
  credentialStatus?: Record<string, unknown>;
  credentialId?: string;
}

export interface BuildAgentIdentityOptions {
  /** The agent's DID (the subject of this credential). */
  subjectDid: string;
  /** Identity attributes to bind (owner, model, capabilityClass, and so on). */
  attributes: Record<string, unknown>;
  /** Validity window. Defaults to one year. */
  validSeconds?: number;
  validFrom?: Date;
  created?: Date;
  /** Optional W3C `credentialStatus` entry for revocation. */
  credentialStatus?: Record<string, unknown>;
  credentialId?: string;
}

export interface VerifyIdentityChainOptions {
  /** The Vouch root DID the verifier pins. */
  trustedRoot: string;
  /** Optional agent action credential to bind to the identity. */
  actionCredential?: Record<string, unknown>;
  /** Optional Root of Trust credential to check for self-consistency. */
  rootCredential?: Record<string, unknown>;
  /** Action the issuer must be recognized for. Defaults to issueAgentIdentity. */
  requiredAction?: string;
  /** Allow network did:web resolution. Defaults false. */
  allowDidResolution?: boolean;
  /** Optional map of DID -> public key (JWK JSON or Multikey) for offline pinning. */
  trustedRoots?: Record<string, string>;
  /** Allowed clock drift for temporal checks. */
  clockSkewSeconds?: number;
  /** Optional callback returning true if a credential is revoked. */
  isRevoked?: (credential: Record<string, unknown>) => boolean;
}

// ---------------------------------------------------------------------------
// Credential builders
// ---------------------------------------------------------------------------

/**
 * Self-issue the Vouch Root of Trust credential.
 *
 * Issuer and subject are both the root's own DID. Verifiers pin the root DID
 * and MAY keep this credential to display what the root anchors.
 */
export async function buildRootOfTrust(
  rootSigner: Signer,
  opts: BuildRootOfTrustOptions
): Promise<Record<string, unknown>> {
  const rootDid = rootSigner.getDid();
  const subject: Record<string, unknown> = {
    id: rootDid,
    vouchVersion: PROTOCOL_VERSION,
    rootOfTrust: {
      name: opts.name,
      scope: opts.scope ?? ['ai-agent', 'robot'],
    },
  };
  const credential = envelope({
    credentialId: opts.credentialId,
    types: [VC_TYPE, ROOT_OF_TRUST_TYPE],
    issuer: rootDid,
    subject,
    validSeconds: opts.validSeconds ?? ROOT_VALID_SECONDS,
    validFrom: opts.validFrom,
  });
  return rootSigner.attachProof(credential, { created: opts.created });
}

/**
 * Issue a recognized-issuer credential from the root.
 *
 * The root attests that `issuerDid` may issue the given identity actions.
 * `recognizedIn` chains back to the root DID so a verifier can trace the
 * recognition to the anchor it pinned.
 */
export async function buildRecognizedIssuer(
  rootSigner: Signer,
  opts: BuildRecognizedIssuerOptions
): Promise<Record<string, unknown>> {
  if (!opts.issuerDid) {
    throw new Error('issuerDid is required');
  }
  const rootDid = rootSigner.getDid();
  const subject: Record<string, unknown> = {
    id: opts.issuerDid,
    recognizedActions: [...(opts.recognizedActions ?? [ACTION_ISSUE_AGENT_IDENTITY])],
    recognizedIn: rootDid,
  };
  const credential = envelope({
    credentialId: opts.credentialId,
    types: [VC_TYPE, RECOGNIZED_ISSUER_TYPE],
    issuer: rootDid,
    subject,
    validSeconds: opts.validSeconds ?? ISSUER_VALID_SECONDS,
    validFrom: opts.validFrom,
    credentialStatus: opts.credentialStatus,
  });
  return rootSigner.attachProof(credential, { created: opts.created });
}

/**
 * Issue an authority-issued identity credential for an agent.
 *
 * Here the issuer differs from the subject: a recognized issuer binds the
 * agent's DID to real attributes. This turns a self-asserted agent DID into an
 * identity a third party stands behind.
 */
export async function buildAgentIdentity(
  issuerSigner: Signer,
  opts: BuildAgentIdentityOptions
): Promise<Record<string, unknown>> {
  if (!opts.subjectDid) {
    throw new Error('subjectDid is required');
  }
  if (
    !opts.attributes ||
    typeof opts.attributes !== 'object' ||
    Array.isArray(opts.attributes) ||
    Object.keys(opts.attributes).length === 0
  ) {
    throw new Error('attributes must be a non-empty object');
  }
  const subject: Record<string, unknown> = {
    id: opts.subjectDid,
    identity: { ...opts.attributes },
  };
  const credential = envelope({
    credentialId: opts.credentialId,
    types: [VC_TYPE, AGENT_IDENTITY_TYPE],
    issuer: issuerSigner.getDid(),
    subject,
    validSeconds: opts.validSeconds ?? IDENTITY_VALID_SECONDS,
    validFrom: opts.validFrom,
    credentialStatus: opts.credentialStatus,
  });
  return issuerSigner.attachProof(credential, { created: opts.created });
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify an agent identity against a pinned Vouch root.
 *
 * Walks the chain: the recognized-issuer credential must be signed by the
 * pinned root and grant `requiredAction`; the identity credential must be
 * signed by that recognized issuer; the optional action credential must be
 * signed by the agent the identity describes. Everything anchors at
 * `trustedRoot`, the ONE DID the verifier trusts up front.
 *
 * With did:key identities this runs fully offline.
 */
export async function verifyIdentityChain(
  identityCredential: Record<string, unknown>,
  recognizedIssuerCredential: Record<string, unknown>,
  opts: VerifyIdentityChainOptions
): Promise<IdentityChainResult> {
  const trustedRoot = opts.trustedRoot;
  if (!trustedRoot) {
    return { ok: false, reason: 'no_trusted_root' };
  }

  const requiredAction = opts.requiredAction ?? ACTION_ISSUE_AGENT_IDENTITY;
  const clockSkew = opts.clockSkewSeconds ?? 30;
  const trustedRoots = opts.trustedRoots;
  const allowDidResolution = opts.allowDidResolution ?? false;
  const resolveOpts = { trustedRoots, allowDidResolution, clockSkew };

  // 1. The recognition must be signed by the pinned root.
  let check = await verifyTrustCredential(
    recognizedIssuerCredential,
    RECOGNIZED_ISSUER_TYPE,
    resolveOpts
  );
  if (!check.ok) {
    return { ok: false, reason: `recognized_issuer_${check.reason}` };
  }
  if (issuerOf(recognizedIssuerCredential) !== trustedRoot) {
    return { ok: false, reason: 'recognized_issuer_not_from_root' };
  }

  const recSubject = recognizedIssuerCredential.credentialSubject;
  if (!isPlainObject(recSubject)) {
    return { ok: false, reason: 'recognized_issuer_bad_subject' };
  }
  const recognizedDid = recSubject.id;
  if (!recognizedDid || typeof recognizedDid !== 'string') {
    return { ok: false, reason: 'recognized_issuer_no_subject' };
  }
  const actions = recSubject.recognizedActions;
  if (!Array.isArray(actions) || !actions.includes(requiredAction)) {
    return { ok: false, reason: 'issuer_not_recognized_for_action' };
  }
  if (opts.isRevoked && opts.isRevoked(recognizedIssuerCredential)) {
    return { ok: false, reason: 'recognized_issuer_revoked' };
  }

  // 2. The identity must be signed by the recognized issuer.
  check = await verifyTrustCredential(identityCredential, AGENT_IDENTITY_TYPE, resolveOpts);
  if (!check.ok) {
    return { ok: false, reason: `identity_${check.reason}` };
  }
  if (issuerOf(identityCredential) !== recognizedDid) {
    return { ok: false, reason: 'identity_not_from_recognized_issuer' };
  }
  if (opts.isRevoked && opts.isRevoked(identityCredential)) {
    return { ok: false, reason: 'identity_revoked' };
  }

  const idSubject = identityCredential.credentialSubject;
  if (!isPlainObject(idSubject)) {
    return { ok: false, reason: 'identity_bad_subject' };
  }
  const agentDid = idSubject.id;
  if (!agentDid || typeof agentDid !== 'string') {
    return { ok: false, reason: 'identity_no_subject' };
  }
  const attributes = isPlainObject(idSubject.identity)
    ? (idSubject.identity as Record<string, unknown>)
    : undefined;

  // 3. Optional: confirm the root credential is genuinely self-issued.
  if (opts.rootCredential !== undefined && opts.rootCredential !== null) {
    check = await verifyTrustCredential(opts.rootCredential, ROOT_OF_TRUST_TYPE, resolveOpts);
    if (!check.ok) {
      return { ok: false, reason: `root_${check.reason}` };
    }
    const rootSub = opts.rootCredential.credentialSubject;
    if (!isPlainObject(rootSub)) {
      return { ok: false, reason: 'root_bad_subject' };
    }
    if (issuerOf(opts.rootCredential) !== trustedRoot || rootSub.id !== trustedRoot) {
      return { ok: false, reason: 'root_not_self_issued' };
    }
  }

  // 4. Optional: bind the agent's own action to this identity.
  let actionPassport: CredentialPassport | undefined;
  if (opts.actionCredential !== undefined && opts.actionCredential !== null) {
    const passport = await verifyActionCredential(
      opts.actionCredential,
      trustedRoots,
      clockSkew
    );
    if (!passport) {
      return { ok: false, reason: 'action_proof_invalid' };
    }
    if (passport.iss !== agentDid) {
      return { ok: false, reason: 'action_not_from_agent' };
    }
    actionPassport = passport;
  }

  return {
    ok: true,
    agentDid,
    issuerDid: recognizedDid,
    rootDid: trustedRoot,
    attributes,
    action: actionPassport,
  };
}

/**
 * Consume a recognized-issuer credential into a Vouch Shield TrustRegistry.
 *
 * The caller should verify the credential first (via {@link verifyIdentityChain}).
 * This adds the recognized issuer DID to the registry's trusted set and returns
 * it.
 */
export function registerRecognizedIssuer(
  registry: { trust: (did: string) => void },
  recognizedIssuerCredential: Record<string, unknown>
): string {
  const subject = recognizedIssuerCredential.credentialSubject;
  const issuerDid = isPlainObject(subject) ? subject.id : undefined;
  if (!issuerDid || typeof issuerDid !== 'string') {
    throw new Error('recognized-issuer credential has no subject id');
  }
  registry.trust(issuerDid);
  return issuerDid;
}

// ---------------------------------------------------------------------------
// Module-private helpers
// ---------------------------------------------------------------------------

interface EnvelopeOptions {
  credentialId?: string;
  types: string[];
  issuer: string;
  subject: Record<string, unknown>;
  validSeconds: number;
  validFrom?: Date;
  credentialStatus?: Record<string, unknown>;
}

/** Build the unsigned VC envelope shared by all three credential types. */
function envelope(opts: EnvelopeOptions): Record<string, unknown> {
  const issuedAt = opts.validFrom ?? new Date();
  const expiresAt = new Date(issuedAt.getTime() + opts.validSeconds * 1000);
  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    id: opts.credentialId ?? newUuidUrn(),
    type: opts.types,
    issuer: opts.issuer,
    validFrom: iso(issuedAt),
    validUntil: iso(expiresAt),
    credentialSubject: opts.subject,
  };
  if (opts.credentialStatus !== undefined) {
    credential.credentialStatus = opts.credentialStatus;
  }
  return credential;
}

interface ResolveContext {
  trustedRoots?: Record<string, string>;
  allowDidResolution: boolean;
  clockSkew: number;
}

/**
 * Verify a trust-layer credential (root, recognized-issuer, or identity).
 *
 * Checks the proof, the proof purpose, that the verification method belongs to
 * the issuer, the credential type, and the validity window. Returns
 * {ok, reason}.
 */
async function verifyTrustCredential(
  credential: unknown,
  expectedType: string,
  ctx: ResolveContext
): Promise<{ ok: boolean; reason?: string }> {
  if (!isPlainObject(credential)) {
    return { ok: false, reason: 'not_a_credential' };
  }

  const types = credential.type;
  if (!Array.isArray(types) || !types.includes(expectedType)) {
    return { ok: false, reason: 'wrong_type' };
  }
  // Exactly one trust-layer type, so the credential cannot double as another
  // link in the chain.
  if (TRUST_TYPES.filter((t) => types.includes(t)).length !== 1) {
    return { ok: false, reason: 'ambiguous_type' };
  }

  const issuer = issuerOf(credential);
  if (!issuer) {
    return { ok: false, reason: 'no_issuer' };
  }

  const proof = credential.proof;
  if (!isPlainObject(proof)) {
    return { ok: false, reason: 'no_proof' };
  }
  if (proof.proofPurpose !== 'assertionMethod') {
    return { ok: false, reason: 'bad_proof_purpose' };
  }
  const vm = proof.verificationMethod;
  if (typeof vm !== 'string' || !vm || vm.split('#', 1)[0] !== issuer) {
    return { ok: false, reason: 'vm_mismatch' };
  }

  const publicKey = await resolveKey(issuer, vm, ctx.trustedRoots, ctx.allowDidResolution);
  if (!publicKey) {
    return { ok: false, reason: 'unresolved_key' };
  }

  try {
    if (!verifyProof(credential, publicKey)) {
      return { ok: false, reason: 'proof_invalid' };
    }
  } catch {
    return { ok: false, reason: 'proof_malformed' };
  }

  const now = Date.now();
  const validFrom = parseIso8601(credential.validFrom);
  const validUntil = parseIso8601(credential.validUntil);
  if (validFrom === null || validUntil === null) {
    return { ok: false, reason: 'no_validity_window' };
  }
  const skewMs = ctx.clockSkew * 1000;
  if (now - validUntil > skewMs) {
    return { ok: false, reason: 'expired' };
  }
  if (validFrom - now > skewMs) {
    return { ok: false, reason: 'not_yet_valid' };
  }

  return { ok: true };
}

/**
 * Verify the agent's own action credential and return its passport, or null on
 * failure. did:key issuers resolve offline; other issuers use trusted roots.
 */
async function verifyActionCredential(
  actionCredential: Record<string, unknown>,
  trustedRoots: Record<string, string> | undefined,
  clockSkew: number
): Promise<CredentialPassport | null> {
  const issuer = issuerOf(actionCredential);
  try {
    if (issuer && issuer.startsWith('did:key:')) {
      const res = await verifyCredential(actionCredential, undefined, {
        clockSkewSeconds: clockSkew,
      });
      return res.isValid && res.passport ? res.passport : null;
    }
    const verifier = new Verifier({ trustedRoots, clockSkewSeconds: clockSkew });
    const res = await verifier.checkVouchCredential(actionCredential);
    return res.isValid && res.passport ? res.passport : null;
  } catch {
    return null;
  }
}

/**
 * Resolve an issuer's Ed25519 public key. did:key resolves offline from the
 * identifier; pinned keys come from `trustedRoots`.
 */
async function resolveKey(
  did: string,
  _vmId: string,
  trustedRoots: Record<string, string> | undefined,
  _allowDidResolution: boolean
): Promise<crypto.KeyObject | null> {
  if (trustedRoots && trustedRoots[did]) {
    const key = coercePublicKey(trustedRoots[did]);
    if (key) return key;
  }
  if (did.startsWith('did:key:')) {
    return coercePublicKey(did.slice('did:key:'.length));
  }
  // did:web resolution over the network is not implemented in this offline
  // port; pin the key via `trustedRoots` instead.
  return null;
}

/** Coerce a Multikey string or JWK JSON string into an Ed25519 public key. */
function coercePublicKey(value: string): crypto.KeyObject | null {
  try {
    if (value.startsWith('z')) {
      const { algorithm, rawKey } = decodeMultikey(value);
      if (algorithm !== 'Ed25519') return null;
      return crypto.createPublicKey({
        key: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: Buffer.from(rawKey).toString('base64url'),
        } as crypto.JsonWebKey,
        format: 'jwk',
      });
    }
    const jwk = JSON.parse(value) as Record<string, unknown>;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return null;
    return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
  } catch {
    return null;
  }
}

function issuerOf(credential: Record<string, unknown>): string | null {
  const issuer = credential.issuer;
  if (Array.isArray(issuer)) {
    return issuer.length > 0 && typeof issuer[0] === 'string' ? issuer[0] : null;
  }
  return typeof issuer === 'string' ? issuer : null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseIso8601(value: unknown): number | null {
  if (typeof value !== 'string' || !value) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function newUuidUrn(): string {
  const webCrypto: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto;
  if (webCrypto && typeof webCrypto.randomUUID === 'function') {
    return `urn:uuid:${webCrypto.randomUUID()}`;
  }
  throw new Error(
    'No Web Crypto RNG available to generate a credential id. Pass ' +
      '`credentialId` explicitly.'
  );
}
