/**
 * Tests for the runnable robotics examples (examples/robotics-evidence-pack.ts
 * and examples/robotics-vla-accountability-loop.ts). Mirrors the Python
 * tests/test_examples_robotics.py: every profile conforms on the full evidence
 * pack, each signed attestation verifies, the VLA gate allows the safe actions
 * and denies the over-speed and out-of-zone ones, and the black-box chain
 * verifies and detects tampering.
 */

import * as crypto from 'crypto';

import { BlackBoxLog, verifyBlackboxChain, verifyConformanceAttestation } from '../src';

import {
  ALL_PROFILE_IDS,
  buildBaseCredentials,
  buildEvidencePack,
  buildMonitoringCredentials,
  checkAllProfiles,
  makeParty,
  signAttestations,
} from '../examples/robotics-evidence-pack';

import {
  VLA_MODEL_NAME,
  loadModelWithProvenance,
  runAccountabilityLoop,
} from '../examples/robotics-vla-accountability-loop';

import { buildPhysicalScopeCredential } from '../src';

describe('evidence pack example', () => {
  it('covers all five profiles and every profile conforms', async () => {
    const robot = await makeParty('ar7.example.com');
    const assessor = await makeParty('assessor.example.com');
    const credentials = await buildEvidencePack(robot, assessor);
    const reports = checkAllProfiles(credentials);

    expect(Object.keys(reports).sort()).toEqual([...ALL_PROFILE_IDS].sort());
    for (const [pid, report] of Object.entries(reports)) {
      expect(report.conforms, `${pid} does not conform`).toBe(true);
      expect(report.satisfiedCount).toBe(report.totalCount);
    }
  });

  it('leaves the expected gaps on the base credential set', async () => {
    const robot = await makeParty('ar7.example.com');
    const assessor = await makeParty('assessor.example.com');
    const base = await buildBaseCredentials(robot, assessor);
    const reports = checkAllProfiles(base);

    expect(reports['iso-ts-15066'].conforms).toBe(false);
    expect(reports['ul-3300'].conforms).toBe(false);
    expect(reports['eu-ai-act-high-risk'].conforms).toBe(true);
  });

  it('signs one attestation per profile and each verifies', async () => {
    const robot = await makeParty('ar7.example.com');
    const assessor = await makeParty('assessor.example.com');
    const base = await buildBaseCredentials(robot, assessor);
    const credentials = [...base, ...(await buildMonitoringCredentials(robot, base[2]))];
    const reports = checkAllProfiles(credentials);
    const attestations = await signAttestations(assessor, robot.did, reports);

    expect(Object.keys(attestations)).toHaveLength(5);
    for (const [pid, attestation] of Object.entries(attestations)) {
      const res = verifyConformanceAttestation(attestation, assessor.pub);
      expect(res.ok, `${pid} attestation does not verify`).toBe(true);
      expect(res.subject?.conforms).toBe(true);
      expect(res.subject?.profileId).toBe(pid);
    }
  });

  it('rejects an attestation under the wrong key', async () => {
    const robot = await makeParty('ar7.example.com');
    const assessor = await makeParty('assessor.example.com');
    const credentials = await buildEvidencePack(robot, assessor);
    const reports = checkAllProfiles(credentials);
    const attestations = await signAttestations(assessor, robot.did, reports);
    const res = verifyConformanceAttestation(attestations['eu-ai-act-high-risk'], robot.pub);
    expect(res.ok).toBe(false);
  });
});

describe('VLA accountability loop example', () => {
  async function runLoop() {
    const robot = await makeParty('ar7.example.com');
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
    const decisions = runAccountabilityLoop(scope, blackbox);
    return { decisions, blackbox };
  }

  it('verifies model provenance on load', async () => {
    const robot = await makeParty('ar7.example.com');
    const loaded = await loadModelWithProvenance(robot);
    expect(loaded.ok).toBe(true);
    const vla = loaded.subject?.vla as Record<string, unknown>;
    expect(vla.modelName).toBe(VLA_MODEL_NAME);
    expect(loaded.attestation.proof).toBeDefined();
  });

  it('allows the safe actions and denies the over-speed and out-of-zone ones', async () => {
    const { decisions } = await runLoop();
    const byTask = new Map(decisions);
    expect(byTask.get('pick up the cup')?.ok).toBe(true);
    expect(byTask.get('hand cup to operator')?.ok).toBe(true);
    expect(byTask.get('sprint to the dock')?.ok).toBe(false);
    expect(
      byTask.get('sprint to the dock')?.reasons.some((r) => r.includes('speed_exceeded'))
    ).toBe(true);
    expect(byTask.get('fetch from loading bay')?.ok).toBe(false);
    expect(
      byTask.get('fetch from loading bay')?.reasons.some((r) => r.startsWith('zone_not_allowed'))
    ).toBe(true);
  });

  it('black-box chain verifies and detects tampering', async () => {
    const { decisions, blackbox } = await runLoop();
    const entries = blackbox.entries();
    expect(entries).toHaveLength(decisions.length);

    expect(verifyBlackboxChain(entries).ok).toBe(true);

    const tampered = entries.map((e) => ({ ...e }));
    tampered[2].event = 'actuation_allowed';
    const res = verifyBlackboxChain(tampered);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('tampered');
  });
});
