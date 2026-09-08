/**
 * Vouch Shield rules: action / target / resource, with globs on resource.
 *
 * Faithful port of vouch/shield/rules.py; the two MUST agree verdict for
 * verdict, and reason string for reason string, against
 * test-vectors/shield/cases.json.
 *
 * Shield matches on the same three fields a Vouch Credential binds in
 * `credentialSubject.intent`. The policy asks the question the evidence
 * answers, so there is no translation step in between where authority can
 * quietly widen.
 *
 * Security posture: default-deny. A missing file, a malformed file, an unknown
 * key, an unparseable resource, or simply no matching rule all produce DENY.
 * There is no path through this module that turns a failure into an allow.
 *
 * Glob semantics on `resource` are segment based:
 *
 * - a **segment** is the text between `/` separators, so `reports/2026/q3.txt`
 *   has three;
 * - `*` matches exactly one segment and never crosses a `/`;
 * - `**` matches zero or more segments and does cross `/`;
 * - everything else is literal, including `.`;
 * - matching is case sensitive.
 *
 * A resource with no `/` at all is one segment, which is what lets `public.*`
 * match a table name like `public.customers`.
 */

/** Stable, greppable reason strings. Callers branch on these, so they are API. */
export const ALLOWED = 'allowed';
export const REASON_UNKNOWN_DID = 'unknown did';
export const REASON_NO_MATCHING_RULE = 'no matching rule';
export const REASON_RESOURCE_OUTSIDE_SCOPE = 'resource outside scope';
export const REASON_INVALID_RESOURCE = 'invalid resource';
export const REASON_MALFORMED_RULES = 'malformed rules';

/** A pattern deeper than this is past legible, and bounds the backtracking. */
const MAX_PATTERN_SEGMENTS = 64;

const RULE_KEYS = new Set(['id', 'action', 'target', 'resource']);

/** Raised when a rules document cannot be loaded. */
export class RuleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuleError';
  }
}

/** The result of a Shield check. `allow` is the whole answer. */
export interface Decision {
  allow: boolean;
  reason: string;
  ruleId?: string;
}

/** One allow entry. `action` and `target` match exactly; `resource` globs. */
export interface Rule {
  action: string;
  target: string;
  resource: string;
  id: string;
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

function hasControlChars(value: string): boolean {
  for (const ch of value) {
    const code = ch.codePointAt(0) as number;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

/**
 * Normalise a resource string for matching, or return null if unusable.
 *
 * Lexical only: no filesystem access and no symlink resolution, because this is
 * a policy string rather than a path on disk. A server that maps a resource
 * onto a real path MUST additionally confine that path to its own root;
 * symlinks are outside what this can see.
 *
 * Returns null (meaning "invalid, deny") for a non-string, an empty string,
 * control characters, or a path that climbs above its root.
 */
export function normalizeResource(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (hasControlChars(value)) return null;

  const parts: string[] = [];
  for (const segment of value.split('/')) {
    // Empty segments come from a leading '/', a trailing '/', or '//'.
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (parts.length > 0) {
        parts.pop();
      } else {
        // Climbed above the root. Refuse rather than clamping to it, so
        // 'reports/../..' can never be read as 'reports'.
        return null;
      }
      continue;
    }
    parts.push(segment);
  }

  if (parts.length === 0) return null;
  return parts.join('/');
}

/**
 * Normalise a rule's resource pattern. Throws RuleError if unusable.
 *
 * Deliberately stricter than normalizeResource: a pattern containing `.` or
 * `..` segments is a mistake in the rules file, not something to silently
 * resolve, because the author's intent is ambiguous.
 */
export function normalizePattern(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RuleError('resource pattern must be a non-empty string');
  }
  if (hasControlChars(value)) {
    throw new RuleError('resource pattern contains control characters');
  }

  const segments = value.split('/').filter((s) => s !== '');
  if (segments.length === 0) {
    throw new RuleError(`resource pattern is empty after normalisation: ${JSON.stringify(value)}`);
  }
  if (segments.length > MAX_PATTERN_SEGMENTS) {
    throw new RuleError(`resource pattern has too many segments: ${JSON.stringify(value)}`);
  }

  for (const segment of segments) {
    if (segment === '.' || segment === '..') {
      throw new RuleError(
        `resource pattern must not contain '.' or '..' segments: ${JSON.stringify(value)}`,
      );
    }
    if (segment.includes('**') && segment !== '**') {
      throw new RuleError(`'**' must be a whole segment, not part of one: ${JSON.stringify(value)}`);
    }
  }
  return segments.join('/');
}

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Within one segment, '*' is any run of non-slash characters. */
function matchOne(patternSegment: string, segment: string): boolean {
  if (patternSegment === '*') return true;
  if (!patternSegment.includes('*')) return patternSegment === segment;
  const body = patternSegment
    .split('*')
    .map((piece) => escapeRegex(piece))
    .join('[^/]*');
  return new RegExp(`^${body}$`).test(segment);
}

function matchSegments(pattern: string[], resource: string[]): boolean {
  if (pattern.length === 0) return resource.length === 0;
  const head = pattern[0];
  if (head === '**') {
    // Zero or more segments. Try every split; patterns are tiny and bounded by
    // MAX_PATTERN_SEGMENTS, so the branching is not a concern.
    const rest = pattern.slice(1);
    for (let index = 0; index <= resource.length; index += 1) {
      if (matchSegments(rest, resource.slice(index))) return true;
    }
    return false;
  }
  if (resource.length === 0) return false;
  if (!matchOne(head, resource[0])) return false;
  return matchSegments(pattern.slice(1), resource.slice(1));
}

/**
 * Does a normalised resource match a normalised pattern?
 *
 * Both arguments are expected to have been through the relevant normaliser.
 */
export function resourceMatches(pattern: string, resource: string): boolean {
  return matchSegments(pattern.split('/'), resource.split('/'));
}

// ---------------------------------------------------------------------------
// Rule sets
// ---------------------------------------------------------------------------

/** Parsed rules. A RuleSet that failed to load denies everything. */
export class RuleSet {
  readonly byDid: Map<string, Rule[]>;
  readonly malformedReason?: string;

  constructor(byDid?: Map<string, Rule[]>, malformedReason?: string) {
    this.byDid = byDid ?? new Map();
    this.malformedReason = malformedReason;
  }

  get ok(): boolean {
    return this.malformedReason === undefined;
  }

  /** Decide one call. See the module comment for glob semantics. */
  check(did: string, action: string, target: string, resource: string): Decision {
    if (this.malformedReason !== undefined) {
      return { allow: false, reason: REASON_MALFORMED_RULES };
    }

    const normalised = normalizeResource(resource);
    if (normalised === null) {
      return { allow: false, reason: REASON_INVALID_RESOURCE };
    }

    const rules = this.byDid.get(did);
    if (rules === undefined || rules.length === 0) {
      return { allow: false, reason: REASON_UNKNOWN_DID };
    }

    // Track whether anything matched action+target, so the caller can be told
    // the difference between "you may not do this" and "you may do this, but
    // not there".
    let actMatched = false;
    for (const rule of rules) {
      if (rule.action !== action || rule.target !== target) continue;
      actMatched = true;
      if (resourceMatches(rule.resource, normalised)) {
        return { allow: true, reason: ALLOWED, ruleId: rule.id };
      }
    }

    return {
      allow: false,
      reason: actMatched ? REASON_RESOURCE_OUTSIDE_SCOPE : REASON_NO_MATCHING_RULE,
    };
  }
}

function denyAll(reason: string): RuleSet {
  // eslint-disable-next-line no-console
  console.error(`Vouch Shield: denying all calls - ${reason}`);
  return new RuleSet(new Map(), reason);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Build a RuleSet from an already-parsed document.
 *
 * Any structural problem yields a deny-all RuleSet rather than throwing, so a
 * bad rules file degrades to "nothing is permitted" instead of taking the
 * server down in a state where its posture is unclear.
 */
export function loadRules(document: unknown, source = '<memory>'): RuleSet {
  try {
    return loadRulesStrict(document, source);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return denyAll(`${source}: ${message}`);
  }
}

function loadRulesStrict(document: unknown, source: string): RuleSet {
  if (!isPlainObject(document)) {
    throw new RuleError('rules document must be a mapping');
  }

  if (document.version !== 2) {
    throw new RuleError(
      `unsupported rules version ${JSON.stringify(document.version)}; this Shield reads ` +
        'version 2. See docs/design/shield-v2-and-protected-mcp.md for the format.',
    );
  }

  const denyDefault = document.deny_default === undefined ? true : document.deny_default;
  if (denyDefault !== true) {
    throw new RuleError('deny_default must be true; Shield has no allow-by-default mode');
  }

  const rawRules = document.rules === undefined || document.rules === null ? [] : document.rules;
  if (!Array.isArray(rawRules)) {
    throw new RuleError('rules must be a list');
  }

  const byDid = new Map<string, Rule[]>();
  rawRules.forEach((block, blockIndex) => {
    if (!isPlainObject(block)) {
      throw new RuleError(`rules[${blockIndex}] must be a mapping`);
    }
    const unknownBlockKeys = Object.keys(block).filter((k) => k !== 'did' && k !== 'allow');
    if (unknownBlockKeys.length > 0) {
      throw new RuleError(`rules[${blockIndex}] has unknown keys: ${unknownBlockKeys.sort()}`);
    }
    const did = block.did;
    if (typeof did !== 'string' || did.length === 0) {
      throw new RuleError(`rules[${blockIndex}].did must be a non-empty string`);
    }

    const allow = block.allow;
    if (!Array.isArray(allow)) {
      throw new RuleError(`rules[${blockIndex}].allow must be a list`);
    }

    const parsed: Rule[] = [];
    allow.forEach((entry, entryIndex) => {
      const where = `rules[${blockIndex}].allow[${entryIndex}]`;
      if (!isPlainObject(entry)) {
        throw new RuleError(`${where} must be a mapping`);
      }
      const unknown = Object.keys(entry).filter((k) => !RULE_KEYS.has(k));
      if (unknown.length > 0) {
        // A typo like 'resourse:' must not become an allow-anything rule by
        // having its constraint silently ignored.
        throw new RuleError(`${where} has unknown keys: ${unknown.sort()}`);
      }
      for (const required of ['action', 'target', 'resource'] as const) {
        const value = entry[required];
        if (typeof value !== 'string' || value.length === 0) {
          throw new RuleError(`${where}.${required} must be a non-empty string`);
        }
      }
      const rawId = entry.id;
      if (rawId !== undefined && typeof rawId !== 'string') {
        throw new RuleError(`${where}.id must be a string`);
      }
      parsed.push({
        action: entry.action as string,
        target: entry.target as string,
        resource: normalizePattern(entry.resource),
        id: (rawId as string) || `${did}#${entryIndex}`,
      });
    });

    const existing = byDid.get(did);
    if (existing) {
      existing.push(...parsed);
    } else {
      byDid.set(did, parsed);
    }
  });

  return new RuleSet(byDid);
}

/**
 * Parse a rules document from text, then load it.
 *
 * JSON is understood natively. YAML needs a parser passed in, because this
 * package stays dependency-free and browser-safe; a Node caller can pass
 * `require('yaml').parse`. Without one, a YAML document denies everything with
 * a message saying so rather than pretending to have loaded.
 *
 * File reading deliberately lives outside this module. The SDK runs in a
 * browser as well as Node, so the caller owns the I/O and hands the text here.
 */
export function parseRules(
  text: string,
  source = '<memory>',
  yamlParse?: (text: string) => unknown,
): RuleSet {
  const trimmed = text.trimStart();
  const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');

  if (!looksJson) {
    if (!yamlParse) {
      return denyAll(
        `${source}: this does not look like JSON, and no YAML parser was supplied. ` +
          "Pass require('yaml').parse, or write the rules as JSON.",
      );
    }
    try {
      return loadRules(yamlParse(text), source);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return denyAll(`${source}: invalid YAML: ${message}`);
    }
  }

  try {
    return loadRules(JSON.parse(text), source);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return denyAll(`${source}: invalid JSON: ${message}`);
  }
}
