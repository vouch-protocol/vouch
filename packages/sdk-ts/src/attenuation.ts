/**
 * Capability attenuation for delegation chains (TypeScript).
 *
 * Specification v1.7, Sections 9.3 to 9.5 (see
 * docs/specs/w3c-cg-report-v1.7-draft.md).
 *
 * Core rule (settled): every delegated capability MUST be a proper subset of
 * its parent across at least one of {action, target, resource, time, rate,
 * policy}, and MUST NOT be broader on any dimension. A chain ends naturally
 * when nothing remains to narrow; there is no fixed maximum depth (the v1.6.2
 * depth cap is removed). Cost control moves to optional, verifier-local
 * budgets.
 *
 * This module mirrors vouch/attenuation.py byte-for-byte: identical
 * accept/reject decisions and identical rejection-reason strings on every
 * shared interop vector.
 *
 * Three edge policies are intentionally left open (pending Alan Karp's input),
 * exposed here as configuration hooks rather than hardcoded rules:
 *   - meaningful-narrowing threshold (CH-001 open question 1): see
 *     `meaningfulNarrowing`.
 *   - leaf/termination wording (CH-001 open question 2): falls out of the
 *     subset rule.
 *   - chain-cascade revocation (CH-003): see `cascadeRevocationHook`.
 * Do not freeze these as final behavior until the open questions resolve.
 */

// ---------------------------------------------------------------------------
// Structured rejection reasons (stable strings, shared across the three SDKs).
// ---------------------------------------------------------------------------

export const REASON_CAPABILITY_NOT_ATTENUATED = 'capability_not_attenuated';
export const REASON_RESOURCE_NOT_NARROWED = 'resource_not_narrowed';
export const REASON_VERIFIER_BUDGET_EXCEEDED = 'verifier_budget_exceeded';

// NOTE: "chain_depth_exceeded" is removed as a protocol-level hard error in
// v1.7. Depth is now a verifier-budget concern and surfaces, when a verifier
// chooses to cap it, as REASON_VERIFIER_BUDGET_EXCEEDED with limit "max_depth".

export const ATTENUATION_DIMENSIONS = [
  'action',
  'target',
  'resource',
  'time',
  'rate',
  'policy',
] as const;

/**
 * Optional, verifier-local cost cap (Specification v1.7 Section 9.4).
 *
 * undefined on every field means unlimited: there is NO protocol-level cap. A
 * verifier MAY set any subset of these to bound the work it spends on a chain.
 * Exceeding a set limit yields REASON_VERIFIER_BUDGET_EXCEEDED with the
 * specific limit named, so the delegating agent narrows earlier instead of
 * routing around the block.
 */
export interface VerifierBudget {
  maxDepth?: number;
  maxVerificationSeconds?: number;
  maxCumulativeTtlSeconds?: number;
}

/** Outcome of an attenuation/budget check. */
export interface AttenuationResult {
  ok: boolean;
  reason?: string;
  detail?: string;
  /** Dimensions on which the child was strictly narrower than its parent. */
  narrowedOn: string[];
}

// A capability is a plain object with any of:
//   action: string | string[]
//   target: string | string[]
//   resource: string
//   validFrom / validUntil: ISO-8601 str (the time dimension)
//   rate: { limit: number, window: ISO-8601 duration or seconds }
//   policy: object
export type Capability = Record<string, unknown>;

/**
 * Optional hook: meaningful-narrowing threshold (CH-001 open question 1).
 * Receives (parent, child, narrowedOn) and returns true if the narrowing is
 * "meaningful" per verifier policy. Default (undefined) accepts any proper
 * subset on at least one dimension (the permissive rule). A verifier MAY supply
 * a stricter hook, for example requiring narrowing on action/target/resource
 * rather than a trivial rate 100 -> 99.
 * TODO(CH-001 Q1): do not hardcode a final threshold.
 */
export type MeaningfulNarrowingHook = (
  parent: Capability,
  child: Capability,
  narrowedOn: string[]
) => boolean;

/**
 * Optional hook: policy-dimension comparator. Returns one of "narrower",
 * "equal", "broader", "incomparable". Default comparator is conservative
 * (see comparePolicy). Supplied so deployments with domain-specific policy
 * fields can define strictness without changing this module.
 */
export type PolicyComparator = (
  parent: Record<string, unknown>,
  child: Record<string, unknown>
) => 'narrower' | 'equal' | 'broader' | 'incomparable';

/**
 * Optional extension point: chain-cascade revocation (CH-003). Receives the
 * full ordered capability chain and returns an AttenuationResult; return
 * ok=true to accept. Default (undefined) performs NO cascade check.
 * TODO(CH-003): the cascade semantics (does revoking/rotating a mid-chain link
 * invalidate everything downstream) are not yet specified. Do not assume a
 * final rule here.
 */
export type CascadeRevocationHook = (
  capabilities: Capability[]
) => AttenuationResult;

export interface CheckAttenuationOptions {
  meaningfulNarrowing?: MeaningfulNarrowingHook;
  policyComparator?: PolicyComparator;
}

export interface ValidateChainOptions {
  budget?: VerifierBudget;
  meaningfulNarrowing?: MeaningfulNarrowingHook;
  policyComparator?: PolicyComparator;
  cascadeRevocationHook?: CascadeRevocationHook;
  elapsedSeconds?: number;
}

// ---------------------------------------------------------------------------
// Per-dimension subset tests. Each returns [isSubset, isStrict].
// "isSubset" means the child does NOT broaden this dimension.
// "isStrict" means the child is strictly narrower on this dimension.
// A dimension absent on the child is inherited unchanged (subset, not strict).
// ---------------------------------------------------------------------------

function asSet(value: unknown): Set<unknown> | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (Array.isArray(value)) {
    return new Set(value);
  }
  return new Set([value]);
}

function setEquals(a: Set<unknown>, b: Set<unknown>): boolean {
  if (a.size !== b.size) return false;
  for (const v of a) {
    if (!b.has(v)) return false;
  }
  return true;
}

// True if every member of "sub" is in "sup" (sub is a subset of sup).
function isSubsetOf(sub: Set<unknown>, sup: Set<unknown>): boolean {
  for (const v of sub) {
    if (!sup.has(v)) return false;
  }
  return true;
}

function checkAction(parent: Capability, child: Capability): [boolean, boolean] {
  const p = asSet(parent.action);
  const c = asSet(child.action);
  if (c === null || (p !== null && setEquals(c, p))) {
    return [true, false]; // inherited or unchanged
  }
  if (p === null) {
    // Parent unconstrained, child constrains: narrower.
    return [true, true];
  }
  if (isSubsetOf(c, p)) {
    return [true, !setEquals(c, p)];
  }
  return [false, false]; // child has actions the parent lacks: broader
}

function checkTarget(parent: Capability, child: Capability): [boolean, boolean] {
  const p = asSet(parent.target);
  const c = asSet(child.target);
  if (c === null || (p !== null && setEquals(c, p))) {
    return [true, false];
  }
  if (p === null) {
    return [true, true];
  }
  if (isSubsetOf(c, p)) {
    return [true, !setEquals(c, p)];
  }
  return [false, false];
}

/**
 * True if `child` is a sub-resource of (or equal to) `parent`. Conservative
 * URL-prefix match: child must equal parent or extend it after a path
 * separator. Mirrors the v1.6.2 resource-narrowing rule (Section 9.3 step 5).
 */
export function isSubResource(child: string, parent: string): boolean {
  // Reject relative path-traversal segments (".."): a child like
  // "https://api/v1/../admin" passes a naive prefix check yet resolves outside
  // the granted scope, so it must not count as a sub-resource.
  if (hasPathTraversal(child) || hasPathTraversal(parent)) {
    return false;
  }
  if (child === parent) {
    return true;
  }
  if (child.startsWith(parent.replace(/\/+$/, '') + '/')) {
    return true;
  }
  return false;
}

function hasPathTraversal(uri: string): boolean {
  return uri.split('/').includes('..');
}

function checkResource(
  parent: Capability,
  child: Capability
): [boolean, boolean] {
  const p = parent.resource as string | undefined;
  const c = child.resource as string | undefined;
  if (!c || c === p) {
    return [true, false];
  }
  if (!p) {
    return [true, true];
  }
  if (isSubResource(c, p)) {
    return [true, c !== p];
  }
  return [false, false];
}

function parseIso(value: unknown): number | null {
  if (!value || typeof value !== 'string') {
    return null;
  }
  // Date.parse handles the trailing "Z" (UTC) and explicit offsets. A value
  // with no zone is treated as UTC to match the Python reference (which forces
  // tzinfo=UTC on naive datetimes).
  const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(value);
  const normalized = hasZone ? value : value + 'Z';
  const t = Date.parse(normalized);
  if (Number.isNaN(t)) {
    return null;
  }
  return t; // milliseconds since epoch
}

function checkTime(parent: Capability, child: Capability): [boolean, boolean] {
  const pf = parseIso(parent.validFrom);
  const pu = parseIso(parent.validUntil);
  const cf = parseIso(child.validFrom);
  const cu = parseIso(child.validUntil);
  if (cf === null && cu === null) {
    return [true, false]; // inherited
  }
  // Child interval must lie within the parent interval on both ends.
  if (pf !== null && cf !== null && cf < pf) {
    return [false, false];
  }
  if (pu !== null && cu !== null && cu > pu) {
    return [false, false];
  }
  const strict =
    (pf !== null && cf !== null && cf > pf) ||
    (pu !== null && cu !== null && cu < pu);
  return [true, strict];
}

function ratePerSecond(rate: unknown): number | null {
  if (!rate || typeof rate !== 'object') {
    return null;
  }
  const r = rate as Record<string, unknown>;
  const limit = r.limit;
  if (limit === null || limit === undefined) {
    return null;
  }
  const window = r.window === undefined ? 1 : r.window;
  const seconds = durationSeconds(window);
  if (seconds === null || seconds <= 0) {
    return null;
  }
  const limitNum = Number(limit);
  if (Number.isNaN(limitNum)) {
    return null;
  }
  return limitNum / seconds;
}

/** Parse a rate window: a number of seconds, or a simple ISO-8601 duration. */
function durationSeconds(window: unknown): number | null {
  if (typeof window === 'number') {
    return window;
  }
  if (typeof window !== 'string') {
    return null;
  }
  const s = window.trim().toUpperCase();
  if (!s.startsWith('P')) {
    const n = Number(s);
    return Number.isNaN(n) ? null : n;
  }
  // Minimal ISO-8601 duration parse for the common PT#H/PT#M/PT#S and P#D forms.
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(s);
  if (!m) {
    return null;
  }
  const days = m[1] ? parseInt(m[1], 10) : 0;
  const hours = m[2] ? parseInt(m[2], 10) : 0;
  const mins = m[3] ? parseInt(m[3], 10) : 0;
  const secs = m[4] ? parseInt(m[4], 10) : 0;
  const total = days * 86400 + hours * 3600 + mins * 60 + secs;
  return total > 0 ? total : null;
}

function checkRate(parent: Capability, child: Capability): [boolean, boolean] {
  const childHasRate = child.rate !== undefined && child.rate !== null;
  const p = ratePerSecond(parent.rate);
  const c = ratePerSecond(child.rate);
  if (!childHasRate) {
    return [true, false]; // absent: inherited
  }
  if (c === null) {
    // rate present but unparseable (for example window 0): cannot prove it
    // narrows, so treat as broadening rather than silently inheriting (a bypass).
    return [false, false];
  }
  if (p === null) {
    return [true, true]; // parent unconstrained, child caps: narrower
  }
  if (c <= p) {
    return [true, c < p];
  }
  return [false, false];
}

/**
 * Conservative default policy comparator.
 *
 * A policy is "narrower" (stricter) when the child keeps every constraint the
 * parent had AND adds at least one. It is "equal" when identical. It is
 * "broader" when the child relaxes or removes a parent constraint. Numeric
 * fields are treated as constraints whose values must match unless a deployment
 * supplies its own PolicyComparator that knows the strictness direction of a
 * given field.
 * TODO(CH-001 Q1): policy strictness direction is deployment-specific; do not
 * assume a global numeric direction here.
 */
function comparePolicy(
  parent: Record<string, unknown>,
  child: Record<string, unknown>
): 'narrower' | 'equal' | 'broader' | 'incomparable' {
  if (deepEqual(parent, child)) {
    return 'equal';
  }
  const parentKeys = Object.keys(parent);
  const childKeys = new Set(Object.keys(child));
  // Any parent key dropped, or any shared key whose value changed, is broader
  // under the conservative default (we cannot prove it got stricter).
  for (const k of parentKeys) {
    if (!childKeys.has(k)) {
      return 'broader';
    }
  }
  for (const k of parentKeys) {
    if (!deepEqual(parent[k], child[k])) {
      return 'broader';
    }
  }
  // Child kept all parent constraints and added more: stricter.
  if (childKeys.size > parentKeys.length) {
    return 'narrower';
  }
  return 'equal';
}

function checkPolicy(
  parent: Capability,
  child: Capability,
  comparator?: PolicyComparator
): [boolean, boolean] {
  const p = parent.policy as Record<string, unknown> | undefined;
  const c = child.policy as Record<string, unknown> | undefined;
  if (c === null || c === undefined) {
    return [true, false]; // inherited
  }
  if (!p || Object.keys(p).length === 0) {
    // parent unconstrained, child adds policy: narrower
    return [true, Object.keys(c).length > 0];
  }
  const cmp = (comparator ?? comparePolicy)(p, c);
  if (cmp === 'broader' || cmp === 'incomparable') {
    return [false, false];
  }
  return [true, cmp === 'narrower'];
}

type DimensionCheck = (
  parent: Capability,
  child: Capability,
  comparator?: PolicyComparator
) => [boolean, boolean];

const DIMENSION_CHECKS: Record<string, DimensionCheck> = {
  action: (p, c) => checkAction(p, c),
  target: (p, c) => checkTarget(p, c),
  resource: (p, c) => checkResource(p, c),
  time: (p, c) => checkTime(p, c),
  rate: (p, c) => checkRate(p, c),
  policy: (p, c, pc) => checkPolicy(p, c, pc),
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check the attenuation rule for one (parent, child) capability pair.
 *
 * Returns ok=true iff the child is a proper subset of the parent across at
 * least one dimension and broader on none. On failure, `reason` is
 * REASON_RESOURCE_NOT_NARROWED when the offending dimension is the resource,
 * else REASON_CAPABILITY_NOT_ATTENUATED.
 */
export function checkAttenuation(
  parent: Capability,
  child: Capability,
  opts: CheckAttenuationOptions = {}
): AttenuationResult {
  const narrowedOn: string[] = [];
  for (const dim of ATTENUATION_DIMENSIONS) {
    const [isSubset, isStrict] = DIMENSION_CHECKS[dim](
      parent,
      child,
      opts.policyComparator
    );
    if (!isSubset) {
      const reason =
        dim === 'resource'
          ? REASON_RESOURCE_NOT_NARROWED
          : REASON_CAPABILITY_NOT_ATTENUATED;
      return { ok: false, reason, detail: `broader on ${dim}`, narrowedOn: [] };
    }
    if (isStrict) {
      narrowedOn.push(dim);
    }
  }

  if (narrowedOn.length === 0) {
    // Subset on every dimension but strictly narrower on none: not attenuated.
    return {
      ok: false,
      reason: REASON_CAPABILITY_NOT_ATTENUATED,
      detail: 'no dimension narrowed',
      narrowedOn: [],
    };
  }

  // TODO(CH-001 Q1): optional stricter "meaningful narrowing" policy. The
  // permissive default accepts a proper subset on any single dimension.
  if (
    opts.meaningfulNarrowing &&
    !opts.meaningfulNarrowing(parent, child, narrowedOn)
  ) {
    return {
      ok: false,
      reason: REASON_CAPABILITY_NOT_ATTENUATED,
      detail: 'narrowing not meaningful (verifier policy)',
      narrowedOn,
    };
  }

  return { ok: true, narrowedOn };
}

/**
 * Return the first dimension on which `child` BROADENS `parent`, or null.
 *
 * Builder-side helper: a delegator can never grant more than it holds, so the
 * builder blocks any outright broadening. It does NOT require strict narrowing
 * (the full attenuation rule, narrowing on at least one dimension, is enforced
 * by the verifier via `checkAttenuation` / `validateChain`). This keeps the
 * builder permissive enough for equal-capability pass-through while still
 * refusing to widen authority.
 */
export function findBroadenedDimension(
  parent: Capability,
  child: Capability,
  opts: { policyComparator?: PolicyComparator } = {}
): string | null {
  for (const dim of ATTENUATION_DIMENSIONS) {
    const [isSubset] = DIMENSION_CHECKS[dim](parent, child, opts.policyComparator);
    if (!isSubset) {
      return dim;
    }
  }
  return null;
}

/**
 * Validate a full delegation chain, ordered broadest (root) to narrowest (leaf).
 *
 * Each adjacent pair (capabilities[i], capabilities[i+1]) must satisfy the
 * attenuation rule. The chain terminates naturally at a leaf where nothing can
 * narrow further (CH-001 Q2: this falls out of the subset rule; no explicit
 * leaf condition is hardcoded). Verifier cost budgets are applied first and, on
 * breach, return REASON_VERIFIER_BUDGET_EXCEEDED naming the limit hit.
 */
export function validateChain(
  capabilities: Capability[],
  opts: ValidateChainOptions = {}
): AttenuationResult {
  const budget = opts.budget;
  // "depth" is the number of capability nodes in the chain (for a delegation
  // chain, the number of delegation links). Adjacent attenuation is checked
  // over the depth-1 edges between them.
  const depth = capabilities.length;

  // Verifier cost budget: depth (replaces the removed protocol depth cap).
  if (budget && budget.maxDepth !== undefined && depth > budget.maxDepth) {
    return {
      ok: false,
      reason: REASON_VERIFIER_BUDGET_EXCEEDED,
      detail: `max_depth=${budget.maxDepth}`,
      narrowedOn: [],
    };
  }

  // Verifier cost budget: cumulative validity (TTL) across the chain.
  if (budget && budget.maxCumulativeTtlSeconds !== undefined) {
    const totalTtl = cumulativeTtlSeconds(capabilities);
    if (totalTtl !== null && totalTtl > budget.maxCumulativeTtlSeconds) {
      return {
        ok: false,
        reason: REASON_VERIFIER_BUDGET_EXCEEDED,
        detail: `max_cumulative_ttl_seconds=${budget.maxCumulativeTtlSeconds}`,
        narrowedOn: [],
      };
    }
  }

  // Verifier cost budget: total verification time (caller measures, passes in).
  if (
    budget &&
    budget.maxVerificationSeconds !== undefined &&
    opts.elapsedSeconds !== undefined &&
    opts.elapsedSeconds > budget.maxVerificationSeconds
  ) {
    return {
      ok: false,
      reason: REASON_VERIFIER_BUDGET_EXCEEDED,
      detail: `max_verification_seconds=${budget.maxVerificationSeconds}`,
      narrowedOn: [],
    };
  }

  for (let i = 0; i < Math.max(0, depth - 1); i++) {
    const result = checkAttenuation(capabilities[i], capabilities[i + 1], {
      meaningfulNarrowing: opts.meaningfulNarrowing,
      policyComparator: opts.policyComparator,
    });
    if (!result.ok) {
      return result;
    }
  }

  // TODO(CH-003): chain-cascade revocation. The cascade semantics (mid-chain
  // revocation or key rotation invalidating downstream links) are not yet
  // specified. The hook is an extension point only; default does nothing.
  if (opts.cascadeRevocationHook) {
    const cascade = opts.cascadeRevocationHook(capabilities);
    if (cascade && !cascade.ok) {
      return cascade;
    }
  }

  return { ok: true, narrowedOn: [] };
}

function cumulativeTtlSeconds(capabilities: Capability[]): number | null {
  let total = 0;
  let seen = false;
  for (const cap of capabilities) {
    const cf = parseIso(cap.validFrom);
    const cu = parseIso(cap.validUntil);
    if (cf !== null && cu !== null) {
      total += Math.max(0, (cu - cf) / 1000); // ms to seconds
      seen = true;
    }
  }
  return seen ? total : null;
}

// ---------------------------------------------------------------------------
// Credential / link projection helpers (mirror the Python signer/verifier).
// ---------------------------------------------------------------------------

/**
 * Project a credential (and its intent) onto a capability for the attenuation
 * checks: action/target/resource from intent, time from the credential, and the
 * optional rate/policy from the credentialSubject. Builder-side helper.
 */
export function capabilityFromCredential(
  intent: unknown,
  credential: unknown
): Capability {
  const cap: Capability = {};
  if (intent && typeof intent === 'object') {
    const i = intent as Record<string, unknown>;
    for (const k of ['action', 'target', 'resource']) {
      if (i[k] !== undefined && i[k] !== null) cap[k] = i[k];
    }
  }
  if (credential && typeof credential === 'object') {
    const c = credential as Record<string, unknown>;
    if (c.validFrom) cap.validFrom = c.validFrom;
    if (c.validUntil) cap.validUntil = c.validUntil;
    const subj = (c.credentialSubject ?? {}) as Record<string, unknown>;
    if (subj.rate !== undefined && subj.rate !== null) cap.rate = subj.rate;
    if (subj.policy !== undefined && subj.policy !== null) cap.policy = subj.policy;
  }
  return cap;
}

/**
 * Project a delegation link onto a capability: action/target/resource from
 * intent, time from validFrom/validUntil, and the optional rate/policy
 * dimensions (Specification v1.7, Section 9.2). Verifier-side helper.
 */
export function linkCapability(link: unknown): Capability {
  const cap: Capability = {};
  const l = (link ?? {}) as Record<string, unknown>;
  const intent = (l.intent ?? {}) as Record<string, unknown>;
  for (const k of ['action', 'target', 'resource']) {
    if (intent[k] !== undefined && intent[k] !== null) cap[k] = intent[k];
  }
  for (const k of ['validFrom', 'validUntil', 'rate', 'policy']) {
    if (l[k] !== undefined && l[k] !== null) cap[k] = l[k];
  }
  return cap;
}

/**
 * Verifier-side capability-attenuation check (Specification v1.7, 9.3 to 9.5).
 *
 * Extracts the ordered capability list from the credential's delegationChain and
 * applies the attenuation rule plus any optional verifier cost budget. A chain
 * of 0 or 1 link has nothing to attenuate (the root grant has no parent in the
 * chain). There is no fixed depth limit; depth, when a verifier caps it, is part
 * of the budget and surfaces as verifier_budget_exceeded.
 */
export function validateDelegationChain(
  credential: unknown,
  budget?: VerifierBudget
): AttenuationResult {
  const c = (credential ?? {}) as Record<string, unknown>;
  const subject = (c.credentialSubject ?? {}) as Record<string, unknown>;
  const rawChain = Array.isArray(subject.delegationChain)
    ? subject.delegationChain
    : [];
  const capabilities = rawChain
    .filter((l) => l && typeof l === 'object')
    .map(linkCapability);
  return validateChain(capabilities, { budget });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Structural deep-equality for plain JSON values (objects, arrays, scalars).
// Used by the conservative policy comparator to compare policy field values.
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || a === undefined || b === undefined) {
    return a === b;
  }
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const aKeys = Object.keys(ao);
  const bKeys = Object.keys(bo);
  if (aKeys.length !== bKeys.length) return false;
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(bo, k)) return false;
    if (!deepEqual(ao[k], bo[k])) return false;
  }
  return true;
}
