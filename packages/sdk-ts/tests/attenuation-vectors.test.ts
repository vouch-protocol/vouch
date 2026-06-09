/**
 * Cross-language interop vectors for capability attenuation (Specification v1.7,
 * Sections 9.3 to 9.5, CH-001).
 *
 * Runs the shared vectors in test-vectors/delegation-attenuation/vector.json.
 * The Python and Go SDKs run the SAME vectors and MUST produce identical
 * accept/reject decisions and identical rejection reasons. Do not fork the
 * expectations per language.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

import {
  validateChain,
  validateDelegationChain,
  type Capability,
  type VerifierBudget,
} from '../src/attenuation';

const vectorPath = fileURLToPath(
  new URL(
    '../../../test-vectors/delegation-attenuation/vector.json',
    import.meta.url
  )
);
const data = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
  vectors: Array<{
    name: string;
    chain: Capability[];
    budget: Record<string, number> | null;
    accept: boolean;
    reason: string | null;
  }>;
};

function toBudget(b: Record<string, number> | null): VerifierBudget | undefined {
  if (!b) return undefined;
  const budget: VerifierBudget = {};
  if (b.max_depth !== undefined) budget.maxDepth = b.max_depth;
  if (b.max_verification_seconds !== undefined)
    budget.maxVerificationSeconds = b.max_verification_seconds;
  if (b.max_cumulative_ttl_seconds !== undefined)
    budget.maxCumulativeTtlSeconds = b.max_cumulative_ttl_seconds;
  return budget;
}

function capToLink(cap: Capability): Record<string, unknown> {
  const link: Record<string, unknown> = { intent: {} };
  const intent = link.intent as Record<string, unknown>;
  for (const k of ['action', 'target', 'resource']) {
    if (cap[k] !== undefined) intent[k] = cap[k];
  }
  for (const k of ['validFrom', 'validUntil', 'rate', 'policy']) {
    if (cap[k] !== undefined) link[k] = cap[k];
  }
  return link;
}

describe('delegation-attenuation interop vectors (module)', () => {
  for (const vec of data.vectors) {
    it(vec.name, () => {
      const result = validateChain(vec.chain, { budget: toBudget(vec.budget) });
      expect(result.ok).toBe(vec.accept);
      if (!vec.accept) {
        expect(result.reason).toBe(vec.reason);
      }
    });
  }
});

describe('delegation-attenuation interop vectors (via verifier wiring)', () => {
  for (const vec of data.vectors) {
    it(vec.name, () => {
      const credential = {
        credentialSubject: { delegationChain: vec.chain.map(capToLink) },
      };
      const result = validateDelegationChain(credential, toBudget(vec.budget));
      expect(result.ok).toBe(vec.accept);
      if (!vec.accept) {
        expect(result.reason).toBe(vec.reason);
      }
    });
  }
});
