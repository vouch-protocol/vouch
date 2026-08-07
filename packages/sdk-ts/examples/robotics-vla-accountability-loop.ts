/**
 * VLA accountability loop: provenance on load, a pre-actuation scope gate, and
 * a tamper-evident black box (TypeScript). Mirrors
 * examples/robotics_vla_accountability_loop.py.
 *
 * A robot driven by a vision-language-action model (here Gemini Robotics ER 2)
 * composes three Vouch robotics primitives into one accountable control loop:
 *
 *   1. Provenance on load: before autonomy is enabled, the robot verifies the
 *      signed ModelProvenanceAttestation for the exact weights and config it
 *      is about to run.
 *   2. Pre-actuation scope gate: every action the planner proposes is checked
 *      against the robot's signed PhysicalCapabilityScope before actuating;
 *      an over-speed or out-of-zone action is denied, not attempted.
 *   3. Tamper-evident black box: every decision, allowed or denied, is
 *      appended to an encrypted, hash-linked black-box log. Anyone can verify
 *      the chain; only a holder of the key can read the payloads.
 *
 * Run it:  npx tsx examples/robotics-vla-accountability-loop.ts   (from packages/sdk-ts)
 */

import * as crypto from 'crypto';

import {
  BlackBoxLog,
  Signer,
  buildPhysicalScopeCredential,
  buildProvenanceAttestation,
  checkPhysicalAction,
  generateIdentity,
  verifyBlackboxChain,
  verifyProvenanceAttestation,
  type CheckResult,
  type PhysicalAction,
} from '../src';

export const VLA_MODEL_NAME = 'Gemini Robotics ER 2';
export const VLA_CONFIG = { planner: 'er-2', temperature: 0.0, max_plan_steps: 8 };

// What the planner proposes during one task episode. The first two stay inside
// the envelope; the sprint exceeds the near-human speed cap and the loading-bay
// fetch leaves the allowed zone, so the gate must deny both.
export const PLANNED_ACTIONS: Array<[string, PhysicalAction]> = [
  ['pick up the cup', { forceN: 20.0, speedMps: 0.3, nearHumans: true, zone: 'cell-3' }],
  ['hand cup to operator', { forceN: 10.0, speedMps: 0.2, nearHumans: true, zone: 'cell-3' }],
  ['sprint to the dock', { speedMps: 2.5, nearHumans: true, zone: 'cell-3' }],
  ['fetch from loading bay', { forceN: 15.0, speedMps: 0.5, zone: 'loading-bay' }],
];

export interface Party {
  signer: Signer;
  did: string;
  pub: crypto.KeyObject;
}

/** Generate an identity for one party and wrap it in a Signer. */
export async function makeParty(domain: string): Promise<Party> {
  const keys = await generateIdentity(domain);
  const did = keys.did as string;
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = crypto.createPublicKey({
    key: JSON.parse(keys.publicKeyJwk) as crypto.JsonWebKey,
    format: 'jwk',
  });
  return { signer, did, pub };
}

/** Multibase (base64url) SHA-256, the hash form Vouch credentials carry. */
export function digest(data: Buffer | string): string {
  return 'u' + crypto.createHash('sha256').update(data).digest('base64url');
}

/** Sign the model's provenance and verify it before enabling autonomy. */
export async function loadModelWithProvenance(robot: Party): Promise<{
  ok: boolean;
  attestation: Record<string, unknown>;
  subject?: Record<string, unknown>;
}> {
  const attestation = await buildProvenanceAttestation(robot.signer, {
    robotDid: robot.did,
    modelName: VLA_MODEL_NAME,
    weightsHash: digest('gemini-robotics-er-2-weights'),
    safetyPolicy: digest('factory-floor-safety-policy-v3'),
    config: VLA_CONFIG,
    version: '2.0',
  });
  const res = verifyProvenanceAttestation(attestation, robot.pub, VLA_CONFIG);
  return { ok: res.ok, attestation, subject: res.subject };
}

/**
 * Gate each proposed action against the physical scope, record every decision
 * in the black box, and return the per-action decisions.
 */
export function runAccountabilityLoop(
  scope: Record<string, unknown>,
  blackbox: BlackBoxLog,
  actions: Array<[string, PhysicalAction]> = PLANNED_ACTIONS
): Array<[string, CheckResult]> {
  const decisions: Array<[string, CheckResult]> = [];
  for (const [task, action] of actions) {
    const result = checkPhysicalAction(scope, action);
    blackbox.append(result.ok ? 'actuation_allowed' : 'actuation_denied', {
      task,
      zone: action.zone ?? null,
      speedMps: action.speedMps ?? null,
      nearHumans: action.nearHumans ?? false,
      reasons: result.reasons,
    });
    decisions.push([task, result]);
  }
  return decisions;
}

export async function main(): Promise<void> {
  const robot = await makeParty('ar7.example.com');

  // 1. provenance on load: no verified provenance, no autonomy.
  const loaded = await loadModelWithProvenance(robot);
  const vla = loaded.subject?.vla as Record<string, unknown> | undefined;
  console.log(`provenance verifies: ${loaded.ok}  model=${vla?.modelName}`);
  if (!loaded.ok) {
    throw new Error('refusing to enable autonomy without verified provenance');
  }

  // 2. pre-actuation scope gate, with every decision black-boxed.
  const scopeCred = await buildPhysicalScopeCredential(robot.signer, {
    subjectDid: robot.did,
    maxForceN: 80.0,
    maxSpeedMps: 1.5,
    maxSpeedNearHumansMps: 0.5,
    allowedZones: ['cell-3'],
  });
  const subject = scopeCred.credentialSubject as Record<string, unknown>;
  const scope = subject.physicalScope as Record<string, unknown>;
  const blackbox = new BlackBoxLog(crypto.randomBytes(32));
  for (const [task, result] of runAccountabilityLoop(scope, blackbox)) {
    const verdict = result.ok ? 'ALLOW' : 'DENY ';
    const why = result.reasons.length ? `  (${result.reasons.join('; ')})` : '';
    console.log(`  [${verdict}] ${task}${why}`);
  }

  // 3. the black box is tamper-evident without the key.
  const entries = blackbox.entries();
  const chain = verifyBlackboxChain(entries);
  console.log(`black-box chain verifies: ${chain.ok}  entries=${entries.length}`);

  // Rewriting history (the denied sprint becomes "allowed") breaks the chain.
  const tampered = entries.map((e) => ({ ...e }));
  tampered[2].event = 'actuation_allowed';
  const detected = verifyBlackboxChain(tampered);
  console.log(`tampered chain detected: ${!detected.ok}  (${detected.reason})`);
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
