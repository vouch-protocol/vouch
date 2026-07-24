/**
 * Vouch <-> Amnesia bridge (TypeScript SDK).
 *
 * Optional: when an Amnesia EgressDecision is available, wrap it in a W3C
 * Verifiable Credential 2.0 with a Data Integrity proof, producing a
 * verifiable, replayable audit artifact in the Vouch ecosystem.
 *
 * This is the "pro mode" cryptographic attestation referenced in
 * PAD-050 section 5.3.
 *
 * Usage:
 *
 *  import { attestDecision } from '@vouch-protocol-official/sdk/integrations/amnesia';
 *  import { Signer } from '@vouch-protocol-official/sdk';
 *
 *  const signer = await Signer.fromDidWeb('did:web:agent.example.com');
 *  const vc = await attestDecision(decision, signer);
 *  // vc is a VC ready to POST, store, or pass to a verifier.
 */

import type { Signer } from '../signer.js';

/**
 * Shape of the Amnesia EgressDecision (matches amnesia/src/shared/policy.ts).
 * Imported as a structural type so this module has no hard dependency on
 * the @vouch-protocol/amnesia package.
 */
export interface AmnesiaEgressDecision {
  workspace: string;
  decided_at: string;
  diff_hash: string;
  policy_hash: string;
  rule_decisions: Array<{
    rule_id: string;
    rule_body: string;
    severity: 'advisory' | 'block' | 'attest';
    matched: boolean;
    matched_patterns: string[];
    matched_lines: Array<{ file: string; line: number; content: string }>;
  }>;
  overall: 'allow' | 'block' | 'attest';
  block_reason?: string;
}

export interface AttestOptions {
  /** Override `vc.issuer`. Defaults to the signer's DID. */
  issuer?: string;
  /**
   * 'eddsa-jcs-2022' (classical, the default) or 'mldsa44-jcs-2024'
   * (post-quantum). The post-quantum choice attaches a proof SET: an
   * `eddsa-jcs-2022` proof alongside an `mldsa44-jcs-2024` proof.
   *
   * 'hybrid-eddsa-mldsa44-jcs-2026' is the pre-alignment composite identifier.
   * It is still accepted here and treated as a request for the post-quantum
   * profile, so existing callers keep working, but the composite proof itself
   * is verify-only and is no longer emitted.
   */
  cryptosuite?:
    | 'eddsa-jcs-2022'
    | 'mldsa44-jcs-2024'
    | 'hybrid-eddsa-mldsa44-jcs-2026';
  /** Extra `@context` entries appended to the VC. */
  extraContexts?: string[];
}

export interface AmnesiaEgressAttestation {
  credential: Record<string, unknown>;
  decisionOverall: 'allow' | 'block' | 'attest';
  matchedRuleCount: number;
}

const DEFAULT_CONTEXTS = [
  'https://www.w3.org/ns/credentials/v2',
  'https://vouch-protocol.com/contexts/amnesia/v1',
];

/**
 * Wrap an Amnesia EgressDecision in a signed VC 2.0.
 */
export async function attestDecision(
  decision: AmnesiaEgressDecision,
  signer: Signer,
  options: AttestOptions = {},
): Promise<AmnesiaEgressAttestation> {
  validateDecision(decision);

  const cryptosuite = options.cryptosuite ?? 'eddsa-jcs-2022';
  const issuer = options.issuer ?? signer.getDid();
  const matched = decision.rule_decisions.filter((r) => r.matched);

  const contexts = [...DEFAULT_CONTEXTS];
  if (options.extraContexts) contexts.push(...options.extraContexts);

  const vc: Record<string, unknown> = {
    '@context': contexts,
    type: ['VerifiableCredential', 'AmnesiaEgressAttestation'],
    issuer,
    issuanceDate: nowIso(),
    credentialSubject: {
      type: 'AmnesiaEgressAttestation',
      policyVersion: decision.policy_hash,
      diffHash: decision.diff_hash,
      evaluatedAt: decision.decided_at,
      decision: decision.overall,
      blockReason: decision.block_reason,
      ruleDecisions: decision.rule_decisions,
      matchedRuleCount: matched.length,
      evaluator: 'amnesia-cortex/0.1',
    },
  };

  let credential: Record<string, unknown>;
  if (cryptosuite === 'eddsa-jcs-2022') {
    credential = await signer.attachProof(vc);
  } else if (
    cryptosuite === 'mldsa44-jcs-2024' ||
    cryptosuite === 'hybrid-eddsa-mldsa44-jcs-2026'
  ) {
    // Both requests mean "post-quantum": attach the proof set. The composite
    // identifier is honoured rather than ignored, but its wire format is
    // verify-only and is never emitted.
    credential = await signer.attachProofHybrid(vc);
  } else {
    throw new Error(`unsupported cryptosuite: ${String(cryptosuite)}`);
  }

  return {
    credential,
    decisionOverall: decision.overall,
    matchedRuleCount: matched.length,
  };
}

/**
 * Read all decisions from a `.vouch/blocks.log` file (one JSON object per line)
 * and sign each one. Returns one attestation per parseable line.
 */
export async function attestDecisionsFromLog(
  logPath: string,
  signer: Signer,
  options: AttestOptions = {},
): Promise<AmnesiaEgressAttestation[]> {
  const { readFile } = await import('node:fs/promises');
  let raw = '';
  try {
    raw = await readFile(logPath, 'utf8');
  } catch {
    return [];
  }
  const out: AmnesiaEgressAttestation[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const entry = JSON.parse(trimmed) as {
        ts?: string;
        decision?: AmnesiaEgressDecision;
      };
      if (!entry.decision) continue;
      const att = await attestDecision(entry.decision, signer, options);
      out.push(att);
    } catch {
      // skip malformed lines silently
    }
  }
  return out;
}

function validateDecision(d: AmnesiaEgressDecision): void {
  const required: Array<keyof AmnesiaEgressDecision> = [
    'workspace',
    'decided_at',
    'diff_hash',
    'policy_hash',
    'overall',
  ];
  for (const key of required) {
    if (d[key] === undefined || d[key] === null) {
      throw new Error(`decision is missing required field: ${key}`);
    }
  }
  if (!['allow', 'block', 'attest'].includes(d.overall)) {
    throw new Error(
      `unexpected overall value: ${String(d.overall)}; expected allow|block|attest`,
    );
  }
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d+/, '');
}
