/**
 * Physical capability scope for robots (Phase 5.3), TypeScript.
 *
 * Mirrors `vouch/robotics/capability.py`. Extends capability attenuation to the
 * physical world: max force and speed, a slower speed cap near humans, allowed
 * zones, and shift windows, carried in a signed credential so the bound is
 * cryptographically enforceable. A controller checks a proposed action against
 * the granted scope before actuating, and a delegated scope must attenuate
 * (narrow, never broaden) its parent.
 */

import type { Signer } from '../signer';
import { VC_CONTEXT_V2, VOUCH_CONTEXT_V1 } from '../vc';

export const PHYSICAL_SCOPE_TYPE = 'PhysicalCapabilityScope';

export interface PhysicalAction {
  forceN?: number;
  speedMps?: number;
  nearHumans?: boolean;
  zone?: string;
  timeHm?: string; // "HH:MM" local
}

export interface CheckResult {
  ok: boolean;
  reasons: string[];
}

export interface ShiftWindow {
  start: string;
  end: string;
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export interface BuildPhysicalScopeOptions {
  subjectDid: string;
  maxForceN?: number;
  maxSpeedMps?: number;
  maxSpeedNearHumansMps?: number;
  allowedZones?: string[];
  shiftWindows?: ShiftWindow[];
  validSeconds?: number;
  validFrom?: Date;
}

/** Build a signed PhysicalCapabilityScope credential. */
export async function buildPhysicalScopeCredential(
  signer: Signer,
  opts: BuildPhysicalScopeOptions
): Promise<Record<string, unknown>> {
  const scope: Record<string, unknown> = {};
  if (opts.maxForceN !== undefined) scope.maxForceN = opts.maxForceN;
  if (opts.maxSpeedMps !== undefined) scope.maxSpeedMps = opts.maxSpeedMps;
  if (opts.maxSpeedNearHumansMps !== undefined) {
    scope.maxSpeedNearHumansMps = opts.maxSpeedNearHumansMps;
  }
  if (opts.allowedZones !== undefined) scope.allowedZones = [...opts.allowedZones];
  if (opts.shiftWindows !== undefined) scope.shiftWindows = opts.shiftWindows.map((w) => ({ ...w }));

  const issued = opts.validFrom ?? new Date();
  const credential: Record<string, unknown> = {
    '@context': [VC_CONTEXT_V2, VOUCH_CONTEXT_V1],
    type: ['VerifiableCredential', PHYSICAL_SCOPE_TYPE],
    issuer: signer.getDid(),
    validFrom: iso(issued),
    credentialSubject: { id: opts.subjectDid, physicalScope: scope },
  };
  if (opts.validSeconds !== undefined) {
    credential.validUntil = iso(new Date(issued.getTime() + opts.validSeconds * 1000));
  }
  return signer.attachProof(credential);
}

function inWindow(hm: string, w: { start?: string; end?: string }): boolean {
  return (w.start ?? '00:00') <= hm && hm <= (w.end ?? '23:59');
}

/** Check a proposed physical action against a physical scope object. */
export function checkPhysicalAction(
  scope: Record<string, any>,
  action: PhysicalAction
): CheckResult {
  const reasons: string[] = [];

  if (action.forceN !== undefined && 'maxForceN' in scope) {
    if (action.forceN > scope.maxForceN) {
      reasons.push(`force_exceeded: ${action.forceN}N > ${scope.maxForceN}N`);
    }
  }

  if (action.speedMps !== undefined) {
    let cap = scope.maxSpeedMps;
    if (action.nearHumans && 'maxSpeedNearHumansMps' in scope) {
      cap = scope.maxSpeedNearHumansMps;
    }
    if (cap !== undefined && action.speedMps > cap) {
      const label = action.nearHumans ? 'near_humans ' : '';
      reasons.push(`${label}speed_exceeded: ${action.speedMps} m/s > ${cap} m/s`);
    }
  }

  if (action.zone !== undefined && 'allowedZones' in scope) {
    if (!scope.allowedZones.includes(action.zone)) {
      reasons.push(`zone_not_allowed: ${action.zone}`);
    }
  }

  if (action.timeHm !== undefined && 'shiftWindows' in scope) {
    const windows = scope.shiftWindows as ShiftWindow[];
    if (windows.length && !windows.some((w) => inWindow(action.timeHm as string, w))) {
      reasons.push(`outside_shift_window: ${action.timeHm}`);
    }
  }

  return { ok: reasons.length === 0, reasons };
}

/**
 * True if `child` is a valid attenuation of `parent`: never broader on any
 * physical dimension. Numeric caps may only shrink; allowed zones may only be a
 * subset; shift windows must each fit inside some parent window.
 */
export function attenuates(
  parent: Record<string, any>,
  child: Record<string, any>
): boolean {
  for (const key of ['maxForceN', 'maxSpeedMps', 'maxSpeedNearHumansMps']) {
    if (key in parent) {
      if (!(key in child)) return false;
      if (child[key] > parent[key]) return false;
    }
  }

  if ('allowedZones' in parent) {
    const pZones = new Set<string>(parent.allowedZones);
    const cZones: string[] = child.allowedZones ?? [];
    if (cZones.length === 0 || !cZones.every((z) => pZones.has(z))) return false;
  }

  if ('shiftWindows' in parent) {
    const pWindows = parent.shiftWindows as ShiftWindow[];
    for (const cw of (child.shiftWindows ?? []) as ShiftWindow[]) {
      const fits = pWindows.some(
        (pw) => (pw.start ?? '00:00') <= (cw.start ?? '00:00') && (cw.end ?? '23:59') <= (pw.end ?? '23:59')
      );
      if (!fits) return false;
    }
  }

  return true;
}
