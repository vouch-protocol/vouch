/**
 * v1.7 capability attenuation: the non-expansion rule over the six delegation
 * dimensions, verifier cost budgets, and chain-cascade revocation
 * (Specification 9.3-9.6).
 *
 * Faithful port of core/vouch-core/src/attenuation.rs; the two MUST agree
 * verdict-for-verdict against test-vectors/delegation-attenuation.
 *
 * Security posture: default-deny. Any malformed input or ambiguous comparison
 * rejects, because delegation grants authority and a false "valid" is an
 * authority-escalation bug.
 */

const RATE_EPSILON = 1e-9;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

export interface Verdict {
  valid: boolean;
  code?: string;
  dimension?: string;
  limit?: string;
  linkIndex?: number;
  detail?: string;
}

function isoToEpoch(s: string): number {
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) throw new Error(`invalid datetime: ${s}`);
  return Math.floor(ms / 1000);
}

/** null => absent; string or string[] => Set; else throws. */
function stringSet(v: Json): Set<string> | null {
  if (v === undefined || v === null) return null;
  if (typeof v === 'string') return new Set([v]);
  if (Array.isArray(v)) {
    const out = new Set<string>();
    for (const item of v) {
      if (typeof item !== 'string') throw new Error('action/target array must be strings');
      out.add(item);
    }
    return out;
  }
  throw new Error('action/target must be a string or array');
}

function isSubResource(child: string, parent: string): boolean {
  const c = child.replace(/\/+$/, '');
  const p = parent.replace(/\/+$/, '');
  if (c === p) return true;
  return c.length > p.length && c.startsWith(p) && c[p.length] === '/';
}

function parseDurationSeconds(s: string): number {
  if (!s || s[0] !== 'P') throw new Error(`invalid duration: ${s}`);
  let total = 0;
  let num = '';
  let inTime = false;
  let sawField = false;
  for (const ch of s.slice(1)) {
    if (ch === 'T') {
      inTime = true;
    } else if (ch >= '0' && ch <= '9') {
      num += ch;
    } else if (ch === 'D' || ch === 'H' || ch === 'M' || ch === 'S') {
      if (num === '') throw new Error(`invalid duration: ${s}`);
      const n = parseInt(num, 10);
      if (ch === 'D') total += n * 86400;
      else if (ch === 'H') total += n * 3600;
      else if (ch === 'M') total += inTime ? n * 60 : n * 2592000;
      else total += n;
      num = '';
      sawField = true;
    } else {
      throw new Error(`invalid duration: ${s}`);
    }
  }
  if (!sawField || num !== '') throw new Error(`invalid duration: ${s}`);
  return total;
}

function rateEventsPerSec(rate: Json): number {
  if (typeof rate !== 'object' || rate === null) throw new Error('rate must be an object');
  const limit = rate.limit;
  if (typeof limit !== 'number' || limit < 0) throw new Error('rate.limit must be non-negative');
  if (typeof rate.window !== 'string') throw new Error('rate.window must be an ISO-8601 duration');
  const secs = parseDurationSeconds(rate.window);
  if (secs <= 0) throw new Error('rate.window must be positive');
  return limit / secs;
}

function policyNotWeaker(parent: Json, child: Json): boolean {
  if (typeof parent !== 'object' || parent === null || typeof child !== 'object' || child === null) {
    return false;
  }
  for (const k of Object.keys(parent)) {
    if (!(k in child)) return false;
    const pv = parent[k];
    const cv = child[k];
    const pNum = typeof pv === 'number';
    const cNum = typeof cv === 'number';
    if (pNum && cNum) {
      if (cv < pv) return false;
    } else if (pNum !== cNum) {
      return false;
    } else if (JSON.stringify(pv) !== JSON.stringify(cv)) {
      return false;
    }
  }
  return true;
}

function windowOf(link: Json): [number | null, number | null] {
  const vf = typeof link.validFrom === 'string' ? isoToEpoch(link.validFrom) : null;
  const vu = typeof link.validUntil === 'string' ? isoToEpoch(link.validUntil) : null;
  return [vf, vu];
}

/** Returns the offending dimension if `child` broadens `parent`, else null. */
export function nonExpansion(parent: Json, child: Json): string | null {
  const pIntent = (parent.intent as Json) ?? {};
  const cIntent = (child.intent as Json) ?? {};

  for (const dim of ['action', 'target'] as const) {
    if (cIntent[dim] !== undefined) {
      let cSet: Set<string> | null;
      try {
        cSet = stringSet(cIntent[dim]);
      } catch {
        return dim;
      }
      let pSet: Set<string> | null = null;
      try {
        pSet = stringSet(pIntent[dim]);
      } catch {
        pSet = null;
      }
      if (cSet && pSet) {
        for (const a of cSet) if (!pSet.has(a)) return dim;
      }
    }
  }

  if (cIntent.resource !== undefined) {
    if (typeof cIntent.resource !== 'string') return 'resource';
    if (typeof pIntent.resource === 'string' && !isSubResource(cIntent.resource, pIntent.resource)) {
      return 'resource';
    }
  }

  let cf: number | null, cu: number | null, pf: number | null, pu: number | null;
  try {
    [cf, cu] = windowOf(child);
    [pf, pu] = windowOf(parent);
  } catch {
    return 'time';
  }
  if (cf !== null && pf !== null && cf < pf) return 'time';
  if (cu !== null && pu !== null && cu > pu) return 'time';

  if (child.rate !== undefined && child.rate !== null) {
    let ce: number;
    try {
      ce = rateEventsPerSec(child.rate);
    } catch {
      return 'rate';
    }
    if (parent.rate !== undefined && parent.rate !== null) {
      let pe: number;
      try {
        pe = rateEventsPerSec(parent.rate);
      } catch {
        return 'rate';
      }
      if (ce > pe + RATE_EPSILON) return 'rate';
    }
  }

  if (child.policy !== undefined && child.policy !== null) {
    if (parent.policy !== undefined && parent.policy !== null && !policyNotWeaker(parent.policy, child.policy)) {
      return 'policy';
    }
  }

  return null;
}

export function validateChain(
  chain: Json[],
  trustedRoots: string[] = [],
  revokedIndices: number[] = [],
  budget: Json = {},
  nowIso = '',
  clockSkewSeconds = 30,
): Verdict {
  if (chain.length === 0) {
    return { valid: false, code: 'malformed_delegation', detail: 'empty delegation chain' };
  }
  if (typeof budget?.maxDepth === 'number' && chain.length > budget.maxDepth) {
    return { valid: false, code: 'verifier_budget_exceeded', limit: 'depth' };
  }
  for (let i = 0; i < chain.length; i++) {
    const link = chain[i];
    if (typeof link !== 'object' || link === null || typeof link.issuer !== 'string' || typeof link.subject !== 'string') {
      return { valid: false, code: 'malformed_delegation', detail: `link ${i} malformed` };
    }
  }
  if (trustedRoots.length > 0 && !trustedRoots.includes(chain[0].issuer)) {
    return { valid: false, code: 'untrusted_principal' };
  }
  const revoked = revokedIndices.filter((i) => i >= 0 && i < chain.length);
  if (revoked.length > 0) {
    return { valid: false, code: 'delegation_revoked', linkIndex: Math.min(...revoked) };
  }
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1];
    const child = chain[i];
    if (parent.subject !== child.issuer) {
      return { valid: false, code: 'subject_issuer_mismatch', linkIndex: i };
    }
    const dim = nonExpansion(parent, child);
    if (dim !== null) return { valid: false, code: 'scope_exceeds_parent', dimension: dim };
  }

  let effStart: number | null = null;
  let effEnd: number | null = null;
  let cumulativeTtl = 0;
  let now: number;
  try {
    for (const link of chain) {
      const [vf, vu] = windowOf(link);
      if (vf !== null) effStart = effStart === null ? vf : Math.max(effStart, vf);
      if (vu !== null) effEnd = effEnd === null ? vu : Math.min(effEnd, vu);
      if (vf !== null && vu !== null && vu >= vf) cumulativeTtl += vu - vf;
    }
    now = isoToEpoch(nowIso);
  } catch (e) {
    return { valid: false, code: 'malformed_delegation', detail: String(e) };
  }
  if (effStart !== null && now < effStart - clockSkewSeconds) {
    return { valid: false, code: 'outside_validity_window' };
  }
  if (effEnd !== null && now > effEnd + clockSkewSeconds) {
    return { valid: false, code: 'outside_validity_window' };
  }
  if (typeof budget?.maxCumulativeTtlSeconds === 'number' && cumulativeTtl > budget.maxCumulativeTtlSeconds) {
    return { valid: false, code: 'verifier_budget_exceeded', limit: 'cumulative_ttl' };
  }
  return { valid: true };
}

/** JSON boundary matching the core. Infallible. */
export function validateChainJson(requestJson: string): string {
  let req: Json;
  try {
    req = JSON.parse(requestJson);
  } catch (e) {
    return JSON.stringify({ valid: false, code: 'malformed_delegation', detail: `request json: ${e}` });
  }
  if (!Array.isArray(req.chain)) {
    return JSON.stringify({ valid: false, code: 'malformed_delegation', detail: 'missing chain array' });
  }
  const verdict = validateChain(
    req.chain,
    req.trustedRoots ?? [],
    req.revokedIndices ?? [],
    req.budget ?? {},
    req.nowIso ?? '',
    typeof req.clockSkewSeconds === 'number' ? req.clockSkewSeconds : 30,
  );
  return JSON.stringify(verdict);
}
