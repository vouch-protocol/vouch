// Robotics accountability examples for core-wasm: ports both flows the Python
// reference runs (examples/robotics_ai_act_evidence_pack.py and
// examples/robotics_vla_accountability_loop.py) onto the WASM producer surface.
//
//   1. Regulatory evidence pack: assemble the six credentials (identity, model
//      provenance, physical scope, safety record, heartbeat with a motion
//      digest, perception provenance), check them against all five built-in
//      conformance profiles, and sign plus verify one point-in-time
//      conformance attestation per profile.
//   2. VLA accountability loop: provenance verified on load, the pre-actuation
//      scope gate denying the over-speed and out-of-zone actions, and the
//      encrypted hash-linked black box, including the tamper-detection case.
//
// Follows smoke.mjs: the ok(name, cond) PASS/FAIL harness, the Node ESM crypto
// polyfill, and fixed seeds so the run is deterministic and needs no RNG.
//
// Run:  node robotics-examples.mjs   (after ./build-npm.sh)
import init, * as core from './pkg/vouch_core_wasm.js';
import { readFileSync } from 'fs';
import { webcrypto } from 'node:crypto';
// Node ESM RNG polyfill for getrandom (browsers expose this natively).
if (!globalThis.crypto) globalThis.crypto = webcrypto;

await init({ module_or_path: readFileSync(new URL('./pkg/vouch_core_wasm_bg.wasm', import.meta.url)) });

let pass = 0, fail = 0;
const ok = (name, cond) => { console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`); cond ? pass++ : fail++; };

// Fixed Ed25519 seeds (0x01/0x07/0x03 repeated) and their public keys, so the
// whole run is reproducible. The assessor pair is the same one the C++
// robotics example pins.
const ROBOT_SEED = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';
const ROBOT_PUB = 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=';
const ROOT_SEED = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=';
const ROOT_PUB = '6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=';
const ASSESSOR_SEED = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=';
const ASSESSOR_PUB = '7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=';
const OTHER_PUB = 'T7LUicUOAmZaTdRW8bYFPLoLNRUeDVaJRq1cyfw8jSU=';
const BLACKBOX_KEY = 'CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=';

const ROBOT_DID = 'did:web:ar7.example.com';
const ASSESSOR_DID = 'did:web:assessor.example.com';
const NOW = '2026-01-01T00:00:00Z';

const ALL_PROFILE_IDS = [
  'eu-ai-act-high-risk',
  'iso-10218',
  'iso-ts-15066',
  'eu-machinery-2023-1230',
  'ul-3300',
];

// Multibase (base64url, 'u' prefix) of raw bytes, the hash/signature form Vouch
// credentials carry.
const mb64 = (buf) => 'u' + Buffer.from(buf).toString('base64url');
const digest = async (text) =>
  mb64(new Uint8Array(await webcrypto.subtle.digest('SHA-256', Buffer.from(text))));

console.log('vouch core-wasm', core.version(), '- robotics accountability examples\n');
console.log('evidence pack:');

// ---- identity -------------------------------------------------------------
// The hardware root signs the binding of the robot DID to the robot key. WASM
// exposes ed25519Sign, so the attestation here is genuine, not a placeholder.
const robotMultikey = core.didKeyFromEd25519(ROBOT_PUB).replace('did:key:', '');
const binding = core.canonicalize(JSON.stringify({ key: robotMultikey, robotDid: ROBOT_DID }));
const attestation = mb64(
  Buffer.from(core.ed25519Sign(ROOT_SEED, Buffer.from(binding).toString('base64')), 'base64')
);
const rootMultikey = core.didKeyFromEd25519(ROOT_PUB).replace('did:key:', '');

const identity = core.roboticsMintIdentity(ROBOT_SEED, JSON.stringify({
  robotDid: ROBOT_DID,
  make: 'Acme Robotics',
  model: 'AR-7',
  serial: 'SN-000123',
  rootKind: 'TPM',
  rootPublicMultibase: rootMultikey,
  attestation,
  validFrom: NOW,
}));
const identitySubject = core.roboticsVerifyIdentity(identity, ROBOT_PUB);
ok('identity mints and verifies (real hardware-root attestation)',
  JSON.parse(identitySubject).make === 'Acme Robotics');

// ---- model provenance -----------------------------------------------------
const CONFIG = { temperature: 0.0, max_torque: 12.5 };
const provenance = core.roboticsBuildProvenance(ROBOT_SEED, JSON.stringify({
  issuerDid: ROBOT_DID,
  robotDid: ROBOT_DID,
  modelName: 'Gemini Robotics ER 2',
  weightsHash: await digest('gemini-robotics-er-2-weights'),
  safetyPolicy: await digest('factory-floor-safety-policy-v3'),
  config: CONFIG,
  version: '2.0',
  validFrom: NOW,
}));

// ---- physical capability scope --------------------------------------------
const scopeCred = core.roboticsBuildScope(ROBOT_SEED, JSON.stringify({
  issuerDid: ROBOT_DID,
  subjectDid: ROBOT_DID,
  maxForceN: 80.0,
  maxSpeedMps: 1.5,
  maxSpeedNearHumansMps: 0.5,
  allowedZones: ['cell-3'],
  validFrom: NOW,
}));
const scope = JSON.parse(scopeCred).credentialSubject.physicalScope;

// ---- safety record over a tamper-evident ledger ---------------------------
let safetyHead = core.roboticsGenesisPrevHash();
const safetyEntries = [];
for (const [eventType, severity, ts] of [
  ['near_miss', 'low', '2026-01-01T00:00:01Z'],
  ['manual_override', 'info', '2026-01-01T00:00:02Z'],
]) {
  const appended = JSON.parse(core.roboticsSafetyAppend(JSON.stringify({
    prevHash: safetyHead, eventType, severity, timestamp: ts,
  })));
  safetyEntries.push(appended.entry);
  safetyHead = appended.head;
}
const summary = core.roboticsSummarizeSafety(JSON.stringify(safetyEntries), safetyHead);
const safetyRecord = core.roboticsBuildSafetyRecord(ASSESSOR_SEED, JSON.stringify({
  issuerDid: ASSESSOR_DID,
  robotDid: ROBOT_DID,
  summary: JSON.parse(summary),
  validFrom: NOW,
}));

// ---- heartbeat carrying a motion digest (ISO/TS 15066 monitoring) ----------
const motionDigest = core.roboticsMotionDigest(JSON.stringify({
  scope,
  samples: [
    { forceN: 12.0, speedMps: 0.4, nearHumans: true, zone: 'cell-3' },
    { forceN: 25.0, speedMps: 1.1, nearHumans: false, zone: 'cell-3' },
  ],
}));
const heartbeat = core.roboticsBuildHeartbeat(ROBOT_SEED, JSON.stringify({
  robotDid: ROBOT_DID,
  sessionId: 'shift-A',
  intervalIndex: 0,
  intervalSeconds: 30,
  motionDigest: JSON.parse(motionDigest),
  validFrom: NOW,
}));

// ---- perception provenance (UL 3300 sensing integrity) --------------------
const frameMb = mb64(Buffer.from('\x89frame-bytes-from-the-front-camera', 'binary'));
const frameHash = core.roboticsHashFrame(Buffer.from(frameMb.slice(1), 'base64url').toString('base64'));
const perceptionRecord = JSON.parse(core.roboticsPerceptionRecord(JSON.stringify({
  prevHash: core.roboticsGenesisPrevHash(),
  frameMb,
  sensorId: 'cam-front',
  modality: 'camera',
  timestamp: '2026-01-01T00:00:03Z',
})));
const perception = core.roboticsBuildPerception(ROBOT_SEED, JSON.stringify({
  robotDid: ROBOT_DID,
  sensorId: 'cam-front',
  modality: 'camera',
  frameHash,
  logHead: perceptionRecord.head,
  validFrom: NOW,
}));

// ---- check every profile, and sign an attestation per profile -------------
const base = [identity, provenance, scopeCred, safetyRecord].map(JSON.parse);
const full = [...base, JSON.parse(heartbeat), JSON.parse(perception)];

ok('full evidence pack carries six credentials', full.length === 6);

// CONFORMS answers "does the evidence cover the clauses this profile maps?",
// which is a different and weaker claim than "does the robot comply with the
// regulation". The citation summary prints beside the verdict so a profile
// whose clause numbers came from secondary sources, or which only names
// topics, says so on the same line as the result.
const citationSummary = (report) =>
  ['descriptive', 'unverified-secondary', 'verified-primary']
    .filter((status) => report.citations?.[status])
    .map((status) => `${report.citations[status]} ${status}`)
    .join(', ');

let allConform = true, citationsCarried = true;
for (const pid of ALL_PROFILE_IDS) {
  const report = JSON.parse(core.roboticsCheckConformance(JSON.stringify(full), pid));
  if (!report.conforms) allConform = false;
  const counted = Object.values(report.citations ?? {}).reduce((a, b) => a + b, 0);
  if (counted !== report.totalCount) citationsCarried = false;
  console.log(`    ${pid.padEnd(24)} ${report.conforms ? 'CONFORMS' : 'GAPS'} ` +
    `(${report.satisfiedCount}/${report.totalCount})  ${report.regime}`);
  console.log(`      citations: ${citationSummary(report)}`);
}
ok('all five profiles conform on the full pack', allConform);
ok('every report totals its clause-citation provenance', citationsCarried);

// UL 3300 is paywalled with no clause numbering available, so a conforming
// UL 3300 report must still say none of its "clauses" can be looked up.
const ul = JSON.parse(core.roboticsCheckConformance(JSON.stringify(full), 'ul-3300'));
ok('a conforming ul-3300 report still reports descriptive-only citations',
  ul.conforms === true && ul.citations.descriptive === ul.totalCount &&
  ul.citations['verified-primary'] === 0);

// The base four credentials leave exactly the two documented gaps.
const baseGaps = ALL_PROFILE_IDS.filter((pid) =>
  !JSON.parse(core.roboticsCheckConformance(JSON.stringify(base), pid)).conforms);
ok('base set leaves exactly the iso-ts-15066 and ul-3300 gaps',
  baseGaps.length === 2 && baseGaps.includes('iso-ts-15066') && baseGaps.includes('ul-3300'));

let attestationsOk = true, wrongKeyRejected = true;
for (const pid of ALL_PROFILE_IDS) {
  const report = core.roboticsCheckConformance(JSON.stringify(full), pid);
  const att = core.roboticsBuildConformanceAttestation(ASSESSOR_SEED, JSON.stringify({
    issuerDid: ASSESSOR_DID, robotDid: ROBOT_DID, report: JSON.parse(report), validFrom: NOW,
  }));
  const subject = JSON.parse(core.roboticsVerifyConformanceAttestation(att, ASSESSOR_PUB));
  if (subject.profileId !== pid || subject.conforms !== true) attestationsOk = false;
  try {
    const bad = core.roboticsVerifyConformanceAttestation(att, OTHER_PUB);
    if (bad && bad !== 'null') wrongKeyRejected = false;
  } catch { /* throwing is also a rejection */ }
}
ok('every signed conformance attestation verifies', attestationsOk);
ok('a wrong key is rejected', wrongKeyRejected);

// ---- 2. VLA accountability loop -------------------------------------------
console.log('\nVLA accountability loop:');

const provSubject = core.roboticsVerifyProvenance(provenance, ROBOT_PUB, JSON.stringify(CONFIG));
ok('provenance verifies on load (no provenance, no autonomy)',
  JSON.parse(provSubject).vla.modelName === 'Gemini Robotics ER 2');

// The planner's proposed episode: two safe actions, one over-speed near a
// human, one outside the allowed zone.
const PLANNED = [
  ['pick up the cup', { forceN: 20.0, speedMps: 0.3, nearHumans: true, zone: 'cell-3' }, true],
  ['hand cup to operator', { forceN: 10.0, speedMps: 0.2, nearHumans: true, zone: 'cell-3' }, true],
  ['sprint to the dock', { speedMps: 2.5, nearHumans: true, zone: 'cell-3' }, false],
  ['fetch from loading bay', { forceN: 15.0, speedMps: 0.5, zone: 'loading-bay' }, false],
];

let gateCorrect = true;
let prevHash = core.roboticsGenesisPrevHash();
const entries = [];
PLANNED.forEach(([task, action, wantAllowed], i) => {
  const result = JSON.parse(core.roboticsCheckAction(JSON.stringify(scope), JSON.stringify(action)));
  if (result.ok !== wantAllowed) gateCorrect = false;
  // seq is a u64 on the Rust side, which wasm-bindgen maps to BigInt.
  const entry = JSON.parse(core.roboticsBlackboxAppend(
    BLACKBOX_KEY, BigInt(i),
    result.ok ? 'actuation_allowed' : 'actuation_denied',
    JSON.stringify({ task, reasons: result.reasons }),
    `2026-01-01T00:00:0${i + 1}Z`,
    prevHash,
  ));
  entries.push(entry);
  prevHash = entry.entryHash;
  const why = result.reasons.length ? `  (${result.reasons.join('; ')})` : '';
  console.log(`    [${result.ok ? 'ALLOW' : 'DENY '}] ${task}${why}`);
});
ok('gate allows the safe actions and denies over-speed and out-of-zone', gateCorrect);

const chain = JSON.parse(core.roboticsVerifyChain(JSON.stringify(entries), undefined));
ok('black-box chain verifies', chain.ok === true);

// Rewriting history (the denied sprint becomes "allowed") breaks the chain.
const tampered = entries.map((e) => ({ ...e }));
tampered[2].event = 'actuation_allowed';
const detected = JSON.parse(core.roboticsVerifyChain(JSON.stringify(tampered), undefined));
ok('tampering is detected', detected.ok === false && String(detected.reason).includes('tampered'));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
