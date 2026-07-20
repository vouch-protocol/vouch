/**
 * Disconnected-edge / DTN trust primitives (TypeScript), PAD-106 to PAD-124.
 *
 * Mirrors `vouch/robotics` (Python) and `core/vouch-core/src/robotics_dtn.rs`
 * with byte-identical credential shapes, so a disconnected-edge credential signed
 * in any language verifies in every other. Covers bounded-staleness revocation,
 * presenter freshness + graded decay, channel-geometry presence, ephemeris-scoped
 * authority, two-body kinematic plausibility, distributed proof-of-location, beam
 * presence, dead-man revocation, a dynamic sparse-Merkle revocation accumulator,
 * swarm quarantine, quorum-of-orbits trust distribution, offline key continuity,
 * time-quality, connectivity-scaled autonomy, integrity-risk, perception
 * consensus, mutual-attestation mesh, and DTN bundle custody.
 *
 * The open layer only: signed formats and deterministic verifier predicates.
 * Hardware acquisition (ranging, TPM, orbital state) is the caller's concern.
 */

import * as crypto from 'crypto';

import { verifyProof } from '../data-integrity';
import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

import { attenuates, checkPhysicalAction } from './capability';
import type { PhysicalAction } from './capability';
import { RoboticsError } from './identity';

type Obj = Record<string, unknown>;
type Vec3 = [number, number, number];

// Types --------------------------------------------------------------------
export const FRESHNESS_TOKEN_TYPE = 'FreshnessToken';
export const PRESENCE_ATTESTATION_TYPE = 'ChannelGeometryPresenceAttestation';
export const GEOSCOPED_GRANT_TYPE = 'EphemerisScopedGrantCredential';
export const RANGE_OBSERVATION_TYPE = 'RangeObservationCredential';
export const PROOF_OF_LOCATION_TYPE = 'ProofOfLocationCredential';
export const BEAM_PRESENCE_TYPE = 'BeamPresenceAttestation';
export const CONDITIONAL_REVOCATION_TYPE = 'ConditionalRevocationCredential';
export const REVOCATION_ACCUMULATOR_TYPE = 'RevocationAccumulatorRoot';
export const DISTRESS_TYPE = 'DistressAttestation';
export const TRUST_STATE_UPDATE_TYPE = 'TrustStateUpdate';
export const KEY_CONTINUITY_PREDELEGATION_TYPE = 'KeyContinuityPredelegation';
export const CONTINUITY_APPROVAL_TYPE = 'ContinuityApproval';
export const TIME_QUALITY_TYPE = 'TimeQualityAttestation';
export const AUTONOMY_SCHEDULE_TYPE = 'AutonomyDecaySchedule';
export const INTEGRITY_RISK_TYPE = 'IntegrityRiskAttestation';
export const PERCEPTION_CLAIM_TYPE = 'SharedPerceptionClaim';
export const INTERACTION_ATTESTATION_TYPE = 'InteractionAttestation';
export const BUNDLE_CREDENTIAL_TYPE = 'BundleTrustCredential';
export const CUSTODY_TRANSFER_TYPE = 'BundleCustodyTransfer';

export const CONSEQUENCE_ROUTINE = 'routine';
export const CONSEQUENCE_SENSITIVE = 'sensitive';
export const CONSEQUENCE_CRITICAL = 'critical';
export const SPEED_OF_LIGHT_MPS = 299792458.0;
export const MU_EARTH = 3.986004418e14;
export const INTEGRITY_FULL = 'full';
export const INTEGRITY_NARROWED = 'narrowed';
export const INTEGRITY_SUSPECT = 'suspect';

// Helpers ------------------------------------------------------------------
function tierOrCritical(t: string): string {
  return t === CONSEQUENCE_ROUTINE || t === CONSEQUENCE_SENSITIVE || t === CONSEQUENCE_CRITICAL
    ? t
    : CONSEQUENCE_CRITICAL;
}

function typesOf(credential: Obj): unknown[] {
  const t = credential.type;
  return Array.isArray(t) ? t : [t];
}

function hasType(credential: Obj, want: string): boolean {
  return typesOf(credential).includes(want);
}

async function signSubject(signer: Signer, credType: string, subject: Obj): Promise<Obj> {
  const credential: Obj = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', credType],
    issuer: signer.getDid(),
    credentialSubject: subject,
  };
  return signer.attachProof(credential);
}

function verifyTyped(credential: Obj, publicKey: crypto.KeyObject, credType: string): Obj | undefined {
  if (!hasType(credential, credType)) return undefined;
  if (!publicKey) return undefined;
  try {
    if (!verifyProof(credential, publicKey)) return undefined;
  } catch {
    return undefined;
  }
  const s = credential.credentialSubject;
  return s && typeof s === 'object' && !Array.isArray(s) ? (s as Obj) : undefined;
}

function parseIsoSeconds(s: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(s);
  if (!m) throw new RoboticsError(`malformed timestamp: ${s}`);
  return Math.floor(
    Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000
  );
}

function asVec3(v: unknown): Vec3 | undefined {
  if (Array.isArray(v) && v.length === 3 && v.every((x) => typeof x === 'number')) {
    return [v[0], v[1], v[2]] as Vec3;
  }
  return undefined;
}

// PAD-106: bounded-staleness revocation ------------------------------------
export function defaultStalenessBudgetSeconds(tier: string): number {
  switch (tierOrCritical(tier)) {
    case CONSEQUENCE_ROUTINE:
      return 30 * 24 * 60 * 60;
    case CONSEQUENCE_SENSITIVE:
      return 24 * 60 * 60;
    default:
      return 60 * 60;
  }
}

export interface FreshnessVerdict {
  allow: boolean;
  tier: string;
  reason: string;
  stalenessSeconds?: number;
  budgetSeconds: number;
}

function snapshotAsOf(snapshot: Obj, nowEpoch: number): number | undefined {
  const vf = snapshot.validFrom;
  if (typeof vf !== 'string') return undefined;
  let validFrom: number;
  try {
    validFrom = parseIsoSeconds(vf);
  } catch {
    return undefined;
  }
  const vu = snapshot.validUntil;
  if (typeof vu === 'string') {
    try {
      if (nowEpoch > parseIsoSeconds(vu)) return undefined;
    } catch {
      return undefined;
    }
  }
  return validFrom;
}

/** Bounded-staleness gate (PAD-106). Fails closed on every ambiguous state. */
export function evaluateFreshness(
  tier: string,
  snapshot: Obj | undefined,
  now: Date,
  budgetOverride?: number
): FreshnessVerdict {
  const t = tierOrCritical(tier);
  const budget = budgetOverride ?? defaultStalenessBudgetSeconds(t);
  const nowEpoch = Math.floor(now.getTime() / 1000);
  const asOf = snapshot ? snapshotAsOf(snapshot, nowEpoch) : undefined;
  if (asOf === undefined) {
    if (t === CONSEQUENCE_ROUTINE) {
      return { allow: true, tier: t, reason: 'no usable revocation snapshot; routine tier tolerates it', budgetSeconds: budget };
    }
    return { allow: false, tier: t, reason: `no usable revocation snapshot; ${t} tier fails closed`, budgetSeconds: budget };
  }
  const staleness = nowEpoch - asOf;
  const allow = staleness <= budget;
  const reason = allow
    ? `snapshot age ${staleness}s within ${t} budget ${budget}s`
    : `snapshot age ${staleness}s exceeds ${t} budget ${budget}s; fails closed`;
  return { allow, tier: t, reason, stalenessSeconds: staleness, budgetSeconds: budget };
}

// PAD-107 / 119: freshness token + graded decay ----------------------------
export function defaultMaxEpochGap(tier: string): number {
  switch (tierOrCritical(tier)) {
    case CONSEQUENCE_ROUTINE:
      return 100;
    case CONSEQUENCE_SENSITIVE:
      return 10;
    default:
      return 1;
  }
}

export async function buildFreshnessToken(
  relaySigner: Signer,
  opts: { subjectDid: string; epoch: number; nonce: string }
): Promise<Obj> {
  if (!Number.isInteger(opts.epoch) || opts.epoch < 0) throw new RoboticsError('epoch must be a non-negative integer');
  return signSubject(relaySigner, FRESHNESS_TOKEN_TYPE, { id: opts.subjectDid, epoch: opts.epoch, nonce: opts.nonce });
}

export function verifyFreshnessToken(
  token: Obj,
  relayPublicKey: crypto.KeyObject,
  opts: { verifierEpoch: number; tier?: string; maxEpochGap?: number; expectedSubject?: string; seenEpoch?: number }
): Obj | undefined {
  const subject = verifyTyped(token, relayPublicKey, FRESHNESS_TOKEN_TYPE);
  if (!subject) return undefined;
  if (opts.expectedSubject !== undefined && subject.id !== opts.expectedSubject) return undefined;
  const tokenEpoch = subject.epoch;
  if (typeof tokenEpoch !== 'number' || !Number.isInteger(tokenEpoch)) return undefined;
  if (opts.seenEpoch !== undefined && tokenEpoch < opts.seenEpoch) return undefined;
  const budget = opts.maxEpochGap ?? defaultMaxEpochGap(opts.tier ?? CONSEQUENCE_CRITICAL);
  const gap = opts.verifierEpoch - tokenEpoch;
  if (gap < 0 || gap > budget) return undefined;
  return subject;
}

export function decayWeight(elapsedEpochs: number, halfLifeEpochs: number, form = 'exponential'): number {
  if (elapsedEpochs < 0) throw new RoboticsError('elapsedEpochs must be non-negative');
  if (halfLifeEpochs <= 0) throw new RoboticsError('halfLifeEpochs must be positive');
  if (form === 'exponential') return Math.pow(0.5, elapsedEpochs / halfLifeEpochs);
  if (form === 'linear') return Math.max(0, 1 - elapsedEpochs / (2 * halfLifeEpochs));
  throw new RoboticsError(`unknown decay form: ${form}`);
}

export function defaultWeightThreshold(tier: string): number {
  switch (tierOrCritical(tier)) {
    case CONSEQUENCE_ROUTINE:
      return 0.1;
    case CONSEQUENCE_SENSITIVE:
      return 0.5;
    default:
      return 0.9;
  }
}

export function decayPermits(
  elapsedEpochs: number,
  halfLifeEpochs: number,
  tier = CONSEQUENCE_CRITICAL,
  form = 'exponential',
  thresholdOverride?: number
): boolean {
  const w = decayWeight(elapsedEpochs, halfLifeEpochs, form);
  return w >= (thresholdOverride ?? defaultWeightThreshold(tier));
}

// PAD-108: channel-geometry presence ---------------------------------------
export function expectedRangeM(a: Vec3, b: Vec3): number {
  return Math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2);
}

export function radialVelocityMps(verifier: Vec3, peer: Vec3, peerVel: Vec3): number {
  const los: Vec3 = [peer[0] - verifier[0], peer[1] - verifier[1], peer[2] - verifier[2]];
  const dist = Math.sqrt(los[0] ** 2 + los[1] ** 2 + los[2] ** 2);
  if (dist === 0) return 0;
  return (los[0] * peerVel[0] + los[1] * peerVel[1] + los[2] * peerVel[2]) / dist;
}

export function expectedDopplerHz(verifier: Vec3, peer: Vec3, peerVel: Vec3, carrierHz: number, propagationMps = SPEED_OF_LIGHT_MPS): number {
  return -(radialVelocityMps(verifier, peer, peerVel) / propagationMps) * carrierHz;
}

export function checkPresence(verifierPosition: Vec3, claimedPeerPosition: Vec3, measuredRangeM: number, toleranceM: number): boolean {
  return Math.abs(measuredRangeM - expectedRangeM(verifierPosition, claimedPeerPosition)) <= toleranceM;
}

export async function buildPresenceAttestation(
  signer: Signer,
  opts: { peerDid: string; nonce: string; claimedPosition: Vec3; measuredRangeM: number; toleranceM: number; claimedVelocity?: Vec3 }
): Promise<Obj> {
  const geometry: Obj = {
    claimedPosition: opts.claimedPosition,
    measuredRangeM: opts.measuredRangeM,
    toleranceM: opts.toleranceM,
  };
  if (opts.claimedVelocity) geometry.claimedVelocity = opts.claimedVelocity;
  return signSubject(signer, PRESENCE_ATTESTATION_TYPE, { id: opts.peerDid, nonce: opts.nonce, geometry });
}

export function verifyPresenceAttestation(
  attestation: Obj,
  publicKey: crypto.KeyObject,
  opts: { verifierPosition: Vec3; expectedNonce?: string }
): Obj | undefined {
  const subject = verifyTyped(attestation, publicKey, PRESENCE_ATTESTATION_TYPE);
  if (!subject) return undefined;
  if (opts.expectedNonce !== undefined && subject.nonce !== opts.expectedNonce) return undefined;
  const geometry = subject.geometry as Obj | undefined;
  if (!geometry) return undefined;
  const claimed = asVec3(geometry.claimedPosition);
  const measured = geometry.measuredRangeM;
  const tolerance = geometry.toleranceM;
  if (!claimed || typeof measured !== 'number' || typeof tolerance !== 'number') return undefined;
  if (!checkPresence(opts.verifierPosition, claimed, measured, tolerance)) return undefined;
  return subject;
}

// PAD-109: ephemeris-scoped authority --------------------------------------
export function regionContains(region: Obj, position: Vec3): boolean {
  const kind = region.type;
  if (kind === 'sphere') {
    const center = asVec3(region.centerM);
    const radius = region.radiusM;
    if (!center || typeof radius !== 'number') throw new RoboticsError('sphere needs centerM and radiusM');
    if (radius < 0) throw new RoboticsError('region.radiusM must be non-negative');
    return expectedRangeM(position, center) <= radius;
  }
  if (kind === 'box') {
    const lo = asVec3(region.minM);
    const hi = asVec3(region.maxM);
    if (!lo || !hi) throw new RoboticsError('box needs minM and maxM');
    return [0, 1, 2].every((i) => lo[i] <= position[i] && position[i] <= hi[i]);
  }
  if (kind === 'altitudeBand') {
    const lo = region.minM;
    const hi = region.maxM;
    if (typeof lo !== 'number' || typeof hi !== 'number') throw new RoboticsError('altitudeBand needs minM and maxM');
    return lo <= position[2] && position[2] <= hi;
  }
  throw new RoboticsError(`unknown region type: ${String(kind)}`);
}

export function regionAttenuates(parent: Obj, child: Obj): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'sphere') {
    const pc = asVec3(parent.centerM);
    const cc = asVec3(child.centerM);
    const pr = parent.radiusM;
    const cr = child.radiusM;
    if (!pc || !cc || typeof pr !== 'number' || typeof cr !== 'number') return false;
    if (pr < 0 || cr < 0) throw new RoboticsError('radii must be non-negative');
    return expectedRangeM(cc, pc) + cr <= pr;
  }
  if (parent.type === 'box') {
    const plo = asVec3(parent.minM);
    const phi = asVec3(parent.maxM);
    const clo = asVec3(child.minM);
    const chi = asVec3(child.maxM);
    if (!plo || !phi || !clo || !chi) return false;
    return [0, 1, 2].every((i) => plo[i] <= clo[i] && chi[i] <= phi[i]);
  }
  if (parent.type === 'altitudeBand') {
    const plo = parent.minM;
    const phi = parent.maxM;
    const clo = child.minM;
    const chi = child.maxM;
    if ([plo, phi, clo, chi].some((x) => typeof x !== 'number')) return false;
    return (plo as number) <= (clo as number) && (chi as number) <= (phi as number);
  }
  throw new RoboticsError(`unknown region type: ${String(parent.type)}`);
}

export async function buildGeoscopedGrant(
  signer: Signer,
  opts: { holderDid: string; grantId: string; region: Obj; physicalScope?: Obj; parentGrantId?: string }
): Promise<Obj> {
  if (!opts.grantId) throw new RoboticsError('grantId is required');
  regionContains(opts.region, [0, 0, 0]);
  const subject: Obj = { id: opts.holderDid, grantId: opts.grantId, region: opts.region };
  if (opts.physicalScope) subject.physicalScope = opts.physicalScope;
  if (opts.parentGrantId !== undefined) subject.parentGrantId = opts.parentGrantId;
  return signSubject(signer, GEOSCOPED_GRANT_TYPE, subject);
}

export function verifyGeoscopedGrant(credential: Obj, publicKey: crypto.KeyObject, parentRegion?: Obj): Obj | undefined {
  const subject = verifyTyped(credential, publicKey, GEOSCOPED_GRANT_TYPE);
  if (!subject) return undefined;
  const region = subject.region as Obj | undefined;
  if (!region) return undefined;
  if (parentRegion !== undefined && !regionAttenuates(parentRegion, region)) return undefined;
  return subject;
}

export function geoscopePermits(subject: Obj, position: Vec3): boolean {
  const region = subject.region as Obj | undefined;
  if (!region) return false;
  try {
    return regionContains(region, position);
  } catch {
    return false;
  }
}

// PAD-114: two-body propagation + kinematic plausibility -------------------
function stumpffC(z: number): number {
  if (z > 1e-12) return (1 - Math.cos(Math.sqrt(z))) / z;
  if (z < -1e-12) return (Math.cosh(Math.sqrt(-z)) - 1) / -z;
  return 0.5;
}
function stumpffS(z: number): number {
  if (z > 1e-12) {
    const s = Math.sqrt(z);
    return (s - Math.sin(s)) / s ** 3;
  }
  if (z < -1e-12) {
    const s = Math.sqrt(-z);
    return (Math.sinh(s) - s) / s ** 3;
  }
  return 1 / 6;
}
const dot3 = (a: Vec3, b: Vec3): number => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const norm3 = (a: Vec3): number => Math.sqrt(dot3(a, a));

export function propagateTwoBody(r0: Vec3, v0: Vec3, dt: number, mu = MU_EARTH): [Vec3, Vec3] {
  if (mu <= 0) throw new RoboticsError('mu must be positive');
  if (dt === 0) return [r0, v0];
  const r0mag = norm3(r0);
  if (r0mag === 0) throw new RoboticsError('degenerate state: |r0| = 0');
  const v0mag = norm3(v0);
  const sqrtMu = Math.sqrt(mu);
  const vr0 = dot3(r0, v0) / r0mag;
  const alpha = 2 / r0mag - (v0mag * v0mag) / mu;
  let chi = sqrtMu * Math.abs(alpha) * dt;
  let converged = false;
  for (let i = 0; i < 100; i++) {
    const z = alpha * chi * chi;
    const c = stumpffC(z);
    const s = stumpffS(z);
    const f = (r0mag * vr0) / sqrtMu * chi * chi * c + (1 - alpha * r0mag) * chi ** 3 * s + r0mag * chi - sqrtMu * dt;
    const df = (r0mag * vr0) / sqrtMu * chi * (1 - alpha * chi * chi * s) + (1 - alpha * r0mag) * chi * chi * c + r0mag;
    if (df === 0) throw new RoboticsError('two-body propagation stalled');
    const dchi = f / df;
    chi -= dchi;
    if (Math.abs(dchi) < 1e-8) {
      converged = true;
      break;
    }
  }
  if (!converged) throw new RoboticsError('two-body propagation did not converge');
  const z = alpha * chi * chi;
  const c = stumpffC(z);
  const s = stumpffS(z);
  const fl = 1 - (chi * chi / r0mag) * c;
  const gl = dt - (chi ** 3 / sqrtMu) * s;
  const r: Vec3 = [fl * r0[0] + gl * v0[0], fl * r0[1] + gl * v0[1], fl * r0[2] + gl * v0[2]];
  const rmag = norm3(r);
  if (rmag === 0) throw new RoboticsError('degenerate propagated state');
  const fdot = (sqrtMu / (rmag * r0mag)) * (alpha * chi ** 3 * s - chi);
  const gdot = 1 - (chi * chi / rmag) * c;
  const v: Vec3 = [fdot * r0[0] + gdot * v0[0], fdot * r0[1] + gdot * v0[1], fdot * r0[2] + gdot * v0[2]];
  return [r, v];
}

export function reachableTwoBody(
  priorPosition: Vec3,
  priorVelocity: Vec3,
  claimedPosition: Vec3,
  elapsedSeconds: number,
  mu = MU_EARTH,
  maxDeltaVMps = 0,
  toleranceM = 0
): boolean {
  if (elapsedSeconds < 0) throw new RoboticsError('elapsedSeconds must be non-negative');
  const [rPred] = propagateTwoBody(priorPosition, priorVelocity, elapsedSeconds, mu);
  return expectedRangeM(claimedPosition, rPred) <= maxDeltaVMps * elapsedSeconds + toleranceM;
}

export function kinematicallyReachable(
  priorPosition: Vec3,
  claimedPosition: Vec3,
  elapsedSeconds: number,
  envelope: Obj,
  priorVelocity?: Vec3,
  toleranceM = 0
): boolean {
  if (elapsedSeconds < 0) throw new RoboticsError('elapsedSeconds must be non-negative');
  if (envelope.model === 'two-body') {
    if (!priorVelocity) throw new RoboticsError('two-body model requires priorVelocity');
    const mu = typeof envelope.muM3S2 === 'number' ? envelope.muM3S2 : MU_EARTH;
    const dv = typeof envelope.maxDeltaVMps === 'number' ? envelope.maxDeltaVMps : 0;
    return reachableTwoBody(priorPosition, priorVelocity, claimedPosition, elapsedSeconds, mu, dv, toleranceM);
  }
  const d = expectedRangeM(priorPosition, claimedPosition);
  let reach: number;
  if (typeof envelope.maxDeltaVMps === 'number') {
    const v0 = priorVelocity ? norm3(priorVelocity) : 0;
    reach = (v0 + envelope.maxDeltaVMps) * elapsedSeconds;
  } else {
    reach = (typeof envelope.maxSpeedMps === 'number' ? envelope.maxSpeedMps : 0) * elapsedSeconds;
  }
  return d <= reach + toleranceM;
}

// PAD-113: distributed proof of location -----------------------------------
export async function buildRangeObservation(
  observerSigner: Signer,
  opts: { targetDid: string; observerPosition: Vec3; measuredRangeM: number; nonce: string; epoch: number }
): Promise<Obj> {
  return signSubject(observerSigner, RANGE_OBSERVATION_TYPE, {
    id: opts.targetDid,
    observer: observerSigner.getDid(),
    observerPosition: opts.observerPosition,
    measuredRangeM: opts.measuredRangeM,
    nonce: opts.nonce,
    epoch: opts.epoch,
  });
}

export function verifyRangeObservation(observation: Obj, observerPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(observation, observerPublicKey, RANGE_OBSERVATION_TYPE);
}

export function countConsistent(subjects: Obj[], claimedPosition: Vec3, toleranceM: number): number {
  let n = 0;
  for (const s of subjects) {
    const p = asVec3(s.observerPosition);
    const m = s.measuredRangeM;
    if (p && typeof m === 'number' && Math.abs(m - expectedRangeM(p, claimedPosition)) <= toleranceM) n += 1;
  }
  return n;
}

export function locationConfirmed(subjects: Obj[], claimedPosition: Vec3, toleranceM: number, threshold: number): boolean {
  return threshold > 0 && countConsistent(subjects, claimedPosition, toleranceM) >= threshold;
}

export async function buildProofOfLocation(
  combinerSigner: Signer,
  opts: { targetDid: string; position: Vec3; observerDids: string[]; epoch: number }
): Promise<Obj> {
  return signSubject(combinerSigner, PROOF_OF_LOCATION_TYPE, {
    id: opts.targetDid,
    position: opts.position,
    observers: opts.observerDids,
    epoch: opts.epoch,
  });
}

// PAD-121: narrow-beam presence --------------------------------------------
export function withinBeam(pointing: Vec3, peerDirection: Vec3, beamwidthRad: number): boolean {
  if (beamwidthRad < 0) return false;
  const na = norm3(pointing);
  const nb = norm3(peerDirection);
  if (na === 0 || nb === 0) return false;
  const cos = Math.min(1, Math.max(-1, dot3(pointing, peerDirection) / (na * nb)));
  return Math.acos(cos) <= beamwidthRad / 2;
}

export async function buildBeamPresence(
  signer: Signer,
  opts: { peerDid: string; nonce: string; pointing: Vec3; beamwidthRad: number }
): Promise<Obj> {
  return signSubject(signer, BEAM_PRESENCE_TYPE, {
    id: opts.peerDid,
    nonce: opts.nonce,
    pointing: opts.pointing,
    beamwidthRad: opts.beamwidthRad,
  });
}

export function verifyBeamPresence(
  attestation: Obj,
  publicKey: crypto.KeyObject,
  opts: { peerDirection: Vec3; expectedNonce?: string }
): Obj | undefined {
  const subject = verifyTyped(attestation, publicKey, BEAM_PRESENCE_TYPE);
  if (!subject) return undefined;
  if (opts.expectedNonce !== undefined && subject.nonce !== opts.expectedNonce) return undefined;
  const pointing = asVec3(subject.pointing);
  const beamwidth = subject.beamwidthRad;
  if (!pointing || typeof beamwidth !== 'number') return undefined;
  if (!withinBeam(pointing, opts.peerDirection, beamwidth)) return undefined;
  return subject;
}

// PAD-112: conditional dead-man revocation ---------------------------------
export async function buildConditionalRevocation(
  authoritySigner: Signer,
  opts: { targetCredentialId: string; subjectDid: string; deadlineEpoch: number }
): Promise<Obj> {
  if (!opts.targetCredentialId) throw new RoboticsError('targetCredentialId is required');
  if (!Number.isInteger(opts.deadlineEpoch) || opts.deadlineEpoch < 0) throw new RoboticsError('deadlineEpoch must be non-negative integer');
  return signSubject(authoritySigner, CONDITIONAL_REVOCATION_TYPE, {
    id: opts.subjectDid,
    targetCredentialId: opts.targetCredentialId,
    deadlineEpoch: opts.deadlineEpoch,
    renewalPredicate: 'renewal_epoch_gte_deadline',
  });
}

export function verifyConditionalRevocation(credential: Obj, authorityPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(credential, authorityPublicKey, CONDITIONAL_REVOCATION_TYPE);
}

export function conditionalRevocationActive(subject: Obj, currentEpoch: number, lastRenewalEpoch?: number): boolean {
  const deadline = subject.deadlineEpoch;
  if (typeof deadline !== 'number') throw new RoboticsError('subject missing integer deadlineEpoch');
  if (currentEpoch <= deadline) return false;
  const renewed = lastRenewalEpoch !== undefined && lastRenewalEpoch >= deadline;
  return !renewed;
}

// PAD-120: dynamic revocation accumulator (sparse Merkle tree) --------------
const SMT_DEPTH = 256;
function sha256(...parts: Buffer[]): Buffer {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}
const EMPTY_LEAF = Buffer.alloc(32);
const REVOKED_LEAF = sha256(Buffer.from('vouch:smt:revoked-leaf:v1'));
let _defaults: Buffer[] | undefined;
function smtDefaults(): Buffer[] {
  if (!_defaults) {
    const d: Buffer[] = new Array(SMT_DEPTH + 1);
    d[SMT_DEPTH] = EMPTY_LEAF;
    for (let i = SMT_DEPTH - 1; i >= 0; i--) d[i] = sha256(d[i + 1], d[i + 1]);
    _defaults = d;
  }
  return _defaults;
}
function smtKey(credentialId: string): Buffer {
  return sha256(Buffer.from(credentialId, 'utf8'));
}
function smtBit(key: Buffer, level: number): number {
  return (key[level >> 3] >> (7 - (level & 7))) & 1;
}
function smtNode(level: number, keys: Buffer[]): Buffer {
  if (keys.length === 0) return smtDefaults()[level];
  if (level === SMT_DEPTH) return REVOKED_LEAF;
  const left: Buffer[] = [];
  const right: Buffer[] = [];
  for (const k of keys) (smtBit(k, level) === 0 ? left : right).push(k);
  return sha256(smtNode(level + 1, left), smtNode(level + 1, right));
}
function mb64(b: Buffer): string {
  return 'u' + b.toString('base64url');
}
function unmb64(s: string): Buffer {
  if (!s.startsWith('u')) throw new RoboticsError("expected multibase 'u' prefix");
  return Buffer.from(s.slice(1), 'base64url');
}

export class SparseMerkleTree {
  private revoked = new Map<string, Buffer>();
  revoke(credentialId: string): void {
    const k = smtKey(credentialId);
    this.revoked.set(k.toString('hex'), k);
  }
  unrevoke(credentialId: string): void {
    this.revoked.delete(smtKey(credentialId).toString('hex'));
  }
  isRevoked(credentialId: string): boolean {
    return this.revoked.has(smtKey(credentialId).toString('hex'));
  }
  root(): Buffer {
    return smtNode(0, [...this.revoked.values()]);
  }
  rootMultibase(): string {
    return mb64(this.root());
  }
  nonRevocationProof(credentialId: string): Obj {
    const key = smtKey(credentialId);
    let keys = [...this.revoked.values()];
    const bitmap = Buffer.alloc(SMT_DEPTH / 8);
    const siblings: string[] = [];
    for (let level = 0; level < SMT_DEPTH; level++) {
      const left: Buffer[] = [];
      const right: Buffer[] = [];
      for (const k of keys) (smtBit(k, level) === 0 ? left : right).push(k);
      let sib: Buffer;
      if (smtBit(key, level) === 0) {
        sib = smtNode(level + 1, right);
        keys = left;
      } else {
        sib = smtNode(level + 1, left);
        keys = right;
      }
      if (!sib.equals(smtDefaults()[level + 1])) {
        bitmap[level >> 3] |= 1 << (7 - (level & 7));
        siblings.push(mb64(sib));
      }
    }
    return { bitmap: mb64(bitmap), siblings };
  }
}

export function verifyNonRevocationProof(credentialId: string, proof: Obj, root: Buffer): boolean {
  try {
    const key = smtKey(credentialId);
    const bitmap = unmb64(String(proof.bitmap));
    if (bitmap.length !== SMT_DEPTH / 8) return false;
    const sibList = (proof.siblings as unknown[]).map((s) => unmb64(String(s)));
    const sibByLevel: Buffer[] = new Array(SMT_DEPTH);
    let idx = 0;
    for (let level = 0; level < SMT_DEPTH; level++) {
      if ((bitmap[level >> 3] >> (7 - (level & 7))) & 1) {
        if (idx >= sibList.length || sibList[idx].length !== 32) return false;
        sibByLevel[level] = sibList[idx++];
      } else {
        sibByLevel[level] = smtDefaults()[level + 1];
      }
    }
    if (idx !== sibList.length) return false;
    let current: Buffer = EMPTY_LEAF;
    for (let level = SMT_DEPTH - 1; level >= 0; level--) {
      const sibling = sibByLevel[level];
      current = smtBit(key, level) === 0 ? sha256(current, sibling) : sha256(sibling, current);
    }
    return current.equals(root);
  } catch {
    return false;
  }
}

export async function buildRevocationAccumulatorRoot(
  authoritySigner: Signer,
  opts: { tree: SparseMerkleTree; epoch: number }
): Promise<Obj> {
  if (!Number.isInteger(opts.epoch) || opts.epoch < 0) throw new RoboticsError('epoch must be non-negative');
  return signSubject(authoritySigner, REVOCATION_ACCUMULATOR_TYPE, {
    id: authoritySigner.getDid(),
    epoch: opts.epoch,
    revocationRoot: opts.tree.rootMultibase(),
  });
}

export function buildNonRevocationProof(opts: { tree: SparseMerkleTree; credentialId: string }): Obj {
  return opts.tree.nonRevocationProof(opts.credentialId);
}

export function verifyNonRevocation(
  credentialId: string,
  proof: Obj,
  signedRootCredential: Obj,
  authorityPublicKey: crypto.KeyObject
): boolean {
  const subject = verifyTyped(signedRootCredential, authorityPublicKey, REVOCATION_ACCUMULATOR_TYPE);
  if (!subject) return false;
  const rootMb = subject.revocationRoot;
  if (typeof rootMb !== 'string') return false;
  let root: Buffer;
  try {
    root = unmb64(rootMb);
  } catch {
    return false;
  }
  if (root.length !== 32) return false;
  return verifyNonRevocationProof(credentialId, proof, root);
}

// PAD-110/111/116: quarantine, quorum, key continuity ----------------------
export async function buildDistressAttestation(
  observerSigner: Signer,
  opts: { targetDid: string; reason: string; evidenceRef: string; epoch: number }
): Promise<Obj> {
  if (!opts.targetDid || !opts.reason || !opts.evidenceRef) throw new RoboticsError('targetDid, reason, evidenceRef required');
  return signSubject(observerSigner, DISTRESS_TYPE, {
    id: opts.targetDid,
    observer: observerSigner.getDid(),
    reason: opts.reason,
    evidenceRef: opts.evidenceRef,
    epoch: opts.epoch,
  });
}

export function verifyDistressAttestation(attestation: Obj, observerPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(attestation, observerPublicKey, DISTRESS_TYPE);
}

export function isQuarantined(
  distressSubjects: Obj[],
  targetDid: string,
  threshold: number,
  memberDids: Set<string>,
  window?: [number, number]
): boolean {
  if (threshold === 0) return false;
  const signers = new Set<string>();
  for (const s of distressSubjects) {
    if (s.id !== targetDid) continue;
    const observer = s.observer;
    if (typeof observer !== 'string' || !memberDids.has(observer)) continue;
    if (window) {
      const e = s.epoch;
      if (typeof e !== 'number' || e < window[0] || e > window[1]) continue;
    }
    signers.add(observer);
  }
  return signers.size >= threshold;
}

export async function buildTrustStateUpdate(
  anchorSigner: Signer,
  opts: { scope: string; change: Obj; epoch: number; failureDomain: string }
): Promise<Obj> {
  if (!opts.scope || !opts.failureDomain) throw new RoboticsError('scope and failureDomain required');
  return signSubject(anchorSigner, TRUST_STATE_UPDATE_TYPE, {
    id: anchorSigner.getDid(),
    scope: opts.scope,
    change: opts.change,
    epoch: opts.epoch,
    failureDomain: opts.failureDomain,
  });
}

export function verifyTrustStateUpdate(update: Obj, anchorPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(update, anchorPublicKey, TRUST_STATE_UPDATE_TYPE);
}

export function acceptTrustStateUpdate(corroboratingSubjects: Obj[], currentEpoch: number, threshold: number): boolean {
  if (threshold === 0 || corroboratingSubjects.length === 0) return false;
  const ref = corroboratingSubjects[0];
  const scope = JSON.stringify(ref.scope);
  const change = JSON.stringify(ref.change);
  const epoch = ref.epoch;
  if (typeof epoch !== 'number' || epoch < currentEpoch) return false;
  const domains = new Set<string>();
  for (const s of corroboratingSubjects) {
    if (JSON.stringify(s.scope) !== scope || JSON.stringify(s.change) !== change || s.epoch !== epoch) continue;
    if (typeof s.failureDomain === 'string') domains.add(s.failureDomain);
  }
  return domains.size >= threshold;
}

export async function buildKeyContinuityPredelegation(
  authoritySigner: Signer,
  opts: { missionCredentialId: string; memberDids: string[]; threshold: number }
): Promise<Obj> {
  const members = [...new Set(opts.memberDids)].sort();
  if (opts.threshold === 0 || opts.threshold > members.length) throw new RoboticsError('threshold must be in 1..=len(members)');
  return signSubject(authoritySigner, KEY_CONTINUITY_PREDELEGATION_TYPE, {
    id: opts.missionCredentialId,
    members,
    threshold: opts.threshold,
    bound: 'preserve_or_narrow',
  });
}

export async function buildContinuityApproval(
  memberSigner: Signer,
  opts: { reissuanceId: string; supersedes: string; epoch: number }
): Promise<Obj> {
  return signSubject(memberSigner, CONTINUITY_APPROVAL_TYPE, {
    id: opts.reissuanceId,
    member: memberSigner.getDid(),
    supersedes: opts.supersedes,
    epoch: opts.epoch,
  });
}

export function verifyKeyContinuity(predelegationSubject: Obj, reissuanceId: string, supersedes: string, approvalSubjects: Obj[]): boolean {
  const members = new Set((Array.isArray(predelegationSubject.members) ? predelegationSubject.members : []).filter((m): m is string => typeof m === 'string'));
  const threshold = predelegationSubject.threshold;
  if (typeof threshold !== 'number' || threshold <= 0) return false;
  const approvers = new Set<string>();
  for (const s of approvalSubjects) {
    if (s.id !== reissuanceId || s.supersedes !== supersedes) continue;
    if (typeof s.member === 'string' && members.has(s.member)) approvers.add(s.member);
  }
  return approvers.size >= threshold;
}

// PAD-115/117/118: time-quality, autonomy, integrity -----------------------
export function defaultTimeUncertaintyBudget(tier: string): number {
  switch (tierOrCritical(tier)) {
    case CONSEQUENCE_ROUTINE:
      return 3600;
    case CONSEQUENCE_SENSITIVE:
      return 60;
    default:
      return 1;
  }
}

export async function buildTimeQualityAttestation(
  signer: Signer,
  opts: { sourceClass: string; sinceDisciplineS: number; uncertaintyS: number }
): Promise<Obj> {
  if (opts.uncertaintyS < 0 || opts.sinceDisciplineS < 0) throw new RoboticsError('uncertaintyS and sinceDisciplineS must be non-negative');
  return signSubject(signer, TIME_QUALITY_TYPE, {
    id: signer.getDid(),
    sourceClass: opts.sourceClass,
    sinceDisciplineS: opts.sinceDisciplineS,
    uncertaintyS: opts.uncertaintyS,
  });
}

export function verifyTimeQualityAttestation(attestation: Obj, publicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(attestation, publicKey, TIME_QUALITY_TYPE);
}

export function timeQualityPermits(subject: Obj, tier = CONSEQUENCE_CRITICAL, budgetOverride?: number): boolean {
  const unc = subject.uncertaintyS;
  if (typeof unc !== 'number') return false;
  return unc <= (budgetOverride ?? defaultTimeUncertaintyBudget(tier));
}

export async function buildAutonomySchedule(
  authoritySigner: Signer,
  opts: { subjectDid: string; steps: Obj[] }
): Promise<Obj> {
  if (!Array.isArray(opts.steps) || opts.steps.length === 0) throw new RoboticsError('steps must be non-empty');
  let prevThresh = -1;
  let prevScope: Obj | undefined;
  for (const st of opts.steps) {
    const thresh = st.maxStalenessEpochs;
    if (typeof thresh !== 'number' || !Number.isInteger(thresh) || thresh <= prevThresh) throw new RoboticsError('maxStalenessEpochs must be strictly ascending integers');
    const scope = st.physicalScope as Obj | undefined;
    if (!scope || typeof scope !== 'object') throw new RoboticsError('each step needs a physicalScope object');
    if (prevScope && !attenuates(prevScope as Record<string, any>, scope as Record<string, any>)) throw new RoboticsError('each step scope must attenuate the previous');
    prevThresh = thresh;
    prevScope = scope;
  }
  return signSubject(authoritySigner, AUTONOMY_SCHEDULE_TYPE, { id: opts.subjectDid, steps: opts.steps });
}

export function verifyAutonomySchedule(schedule: Obj, authorityPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(schedule, authorityPublicKey, AUTONOMY_SCHEDULE_TYPE);
}

export function selectEnvelope(scheduleSubject: Obj, stalenessEpochs: number): Obj | undefined {
  const steps = scheduleSubject.steps;
  if (!Array.isArray(steps)) return undefined;
  for (const st of steps) {
    const t = (st as Obj).maxStalenessEpochs;
    if (typeof t === 'number' && stalenessEpochs <= t) return (st as Obj).physicalScope as Obj;
  }
  return steps.length ? ((steps[steps.length - 1] as Obj).physicalScope as Obj) : undefined;
}

export function autonomyPermits(scheduleSubject: Obj, stalenessEpochs: number, action: PhysicalAction): boolean {
  const scope = selectEnvelope(scheduleSubject, stalenessEpochs);
  if (!scope) return false;
  return checkPhysicalAction(scope as Record<string, any>, action).ok;
}

export async function buildIntegrityRiskAttestation(
  signer: Signer,
  opts: { cumulativeRisk: number; metrics?: Obj; prevHash?: string }
): Promise<Obj> {
  if (opts.cumulativeRisk < 0) throw new RoboticsError('cumulativeRisk must be non-negative');
  const subject: Obj = { id: signer.getDid(), cumulativeRisk: opts.cumulativeRisk };
  if (opts.metrics) subject.metrics = opts.metrics;
  if (opts.prevHash !== undefined) subject.prevHash = opts.prevHash;
  return signSubject(signer, INTEGRITY_RISK_TYPE, subject);
}

export function verifyIntegrityRiskAttestation(attestation: Obj, publicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(attestation, publicKey, INTEGRITY_RISK_TYPE);
}

export function integrityAuthorityLevel(cumulativeRisk: number, narrowThreshold = 0.3, suspectThreshold = 0.7): string {
  if (cumulativeRisk >= suspectThreshold) return INTEGRITY_SUSPECT;
  if (cumulativeRisk >= narrowThreshold) return INTEGRITY_NARROWED;
  return INTEGRITY_FULL;
}

// PAD-122/123: perception consensus + mesh ---------------------------------
export async function buildPerceptionClaim(
  signer: Signer,
  opts: { sceneNonce: string; feature: string; value: unknown; epoch: number }
): Promise<Obj> {
  if (!opts.sceneNonce || !opts.feature) throw new RoboticsError('sceneNonce and feature required');
  return signSubject(signer, PERCEPTION_CLAIM_TYPE, {
    id: signer.getDid(),
    sceneNonce: opts.sceneNonce,
    feature: opts.feature,
    value: opts.value,
    epoch: opts.epoch,
  });
}

export function verifyPerceptionClaim(claim: Obj, publicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(claim, publicKey, PERCEPTION_CLAIM_TYPE);
}

function valueDistance(a: unknown, b: unknown): number | undefined {
  if (typeof a === 'number' && typeof b === 'number') return Math.abs(a - b);
  if (Array.isArray(a) && Array.isArray(b) && a.length === b.length) {
    let sum = 0;
    for (let i = 0; i < a.length; i++) {
      if (typeof a[i] !== 'number' || typeof b[i] !== 'number') return undefined;
      sum += ((a[i] as number) - (b[i] as number)) ** 2;
    }
    return Math.sqrt(sum);
  }
  return undefined;
}

export function crossCheckPerception(claimSubjects: Obj[], tolerance: number, threshold: number): { corroborated: string[]; flagged: string[] } {
  const entries = claimSubjects
    .filter((s) => typeof s.id === 'string' && 'value' in s)
    .map((s) => ({ did: s.id as string, value: s.value }));
  const corroborated: string[] = [];
  const flagged: string[] = [];
  for (const e of entries) {
    let agree = 0;
    for (const o of entries) {
      if (o.did === e.did) continue;
      const d = valueDistance(e.value, o.value);
      if (d !== undefined && d <= tolerance) agree += 1;
    }
    (agree >= threshold ? corroborated : flagged).push(e.did);
  }
  corroborated.sort();
  flagged.sort();
  return { corroborated, flagged };
}

export async function buildInteractionAttestation(
  signer: Signer,
  opts: { peerDid: string; outcome: string; epoch: number }
): Promise<Obj> {
  if (!opts.peerDid) throw new RoboticsError('peerDid required');
  return signSubject(signer, INTERACTION_ATTESTATION_TYPE, {
    id: opts.peerDid,
    attestor: signer.getDid(),
    outcome: opts.outcome,
    epoch: opts.epoch,
  });
}

export function verifyInteractionAttestation(attestation: Obj, attestorPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(attestation, attestorPublicKey, INTERACTION_ATTESTATION_TYPE);
}

export function nodeStanding(
  attestationSubjects: Obj[],
  nodeDid: string,
  currentEpoch: number,
  halfLifeEpochs: number,
  positiveOutcomes: string[] = ['ok', 'success', 'authenticated']
): number {
  const freshest = new Map<string, number>();
  for (const s of attestationSubjects) {
    if (s.id !== nodeDid) continue;
    if (typeof s.outcome !== 'string' || !positiveOutcomes.includes(s.outcome)) continue;
    const attestor = s.attestor;
    const e = s.epoch;
    if (typeof attestor !== 'string' || typeof e !== 'number' || e > currentEpoch) continue;
    const cur = freshest.get(attestor);
    if (cur === undefined || e > cur) freshest.set(attestor, e);
  }
  let total = 0;
  for (const e of freshest.values()) total += decayWeight(currentEpoch - e, halfLifeEpochs);
  return total;
}

// PAD-124: DTN bundle custody ----------------------------------------------
export async function bindCredentialToBundle(
  originatorSigner: Signer,
  opts: { bundleId: string; payloadHash: string; intent: Obj }
): Promise<Obj> {
  if (!opts.bundleId || !opts.payloadHash) throw new RoboticsError('bundleId and payloadHash required');
  return signSubject(originatorSigner, BUNDLE_CREDENTIAL_TYPE, {
    id: opts.bundleId,
    originator: originatorSigner.getDid(),
    payloadHash: opts.payloadHash,
    intent: opts.intent,
  });
}

export function verifyBundleTrust(bundleCredential: Obj, originatorPublicKey: crypto.KeyObject, payloadHash: string): Obj | undefined {
  const subject = verifyTyped(bundleCredential, originatorPublicKey, BUNDLE_CREDENTIAL_TYPE);
  if (!subject) return undefined;
  if (subject.payloadHash !== payloadHash) return undefined;
  return subject;
}

export async function buildCustodyTransfer(
  relaySigner: Signer,
  opts: { bundleId: string; previousCustodian: string | null; epoch: number }
): Promise<Obj> {
  return signSubject(relaySigner, CUSTODY_TRANSFER_TYPE, {
    id: opts.bundleId,
    custodian: relaySigner.getDid(),
    previousCustodian: opts.previousCustodian,
    epoch: opts.epoch,
  });
}

export function verifyCustodyTransfer(transfer: Obj, custodianPublicKey: crypto.KeyObject): Obj | undefined {
  return verifyTyped(transfer, custodianPublicKey, CUSTODY_TRANSFER_TYPE);
}

export function custodyChainOk(transferSubjects: Obj[], bundleId: string, originator: string): boolean {
  const chain = transferSubjects.filter((s) => s.id === bundleId);
  if (chain.length === 0) return false;
  let expectedPrev = originator;
  for (const s of chain) {
    if (s.previousCustodian !== expectedPrev) return false;
    if (typeof s.custodian !== 'string') return false;
    expectedPrev = s.custodian;
  }
  return true;
}
