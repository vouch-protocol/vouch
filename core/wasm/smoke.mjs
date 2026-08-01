// Smoke test for core-wasm: exercises the deterministic JS API and confirms it
// verifies the shared interop vectors (cross-implementation). Uses fixed seeds
// from the vectors, so it needs no RNG (keygen RNG is browser-native; under
// Node ESM getrandom needs a crypto polyfill, see README).
import init, * as core from './pkg/vouch_core_wasm.js';
import { readFileSync } from 'fs';
import { webcrypto } from 'node:crypto';
// Node ESM RNG polyfill for getrandom (browsers expose this natively).
if (!globalThis.crypto) globalThis.crypto = webcrypto;

await init({ module_or_path: readFileSync(new URL('./pkg/vouch_core_wasm_bg.wasm', import.meta.url)) });

let pass = 0, fail = 0;
const ok = (name, cond) => { console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`); cond ? pass++ : fail++; };

const rd = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const eddsa = rd('../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json');
const hybrid = rd('../../test-vectors/hybrid-eddsa-mldsa44/vector.json');
const status = rd('../../test-vectors/bitstring-status-list/vector.json');

// JCS
ok('canonicalize sorts keys', core.canonicalize('{"b":1,"a":2}') === '{"a":2,"b":1}');

// Ed25519 sign/verify (seed from vector, no RNG)
const seed = eddsa.ed25519.seed_b64, pub = eddsa.ed25519.public_key_b64;
const msg = Buffer.from('hello').toString('base64');
const sig = core.ed25519Sign(seed, msg);
ok('ed25519 sign/verify', core.ed25519Verify(pub, msg, sig) === true);
ok('multikey + did:key', core.didKeyFromEd25519(pub).startsWith('did:key:z6Mk'));

// Cross-impl: verify shared signed credential + reproduce proofValue
ok('verifies shared signed credential', core.verifyProof(JSON.stringify(eddsa.signed_credential), pub) === true);
const proof = JSON.parse(core.buildProof(JSON.stringify(eddsa.unsigned_credential), seed, eddsa.verificationMethod, eddsa.created));
ok('reproduces shared proofValue', proof.proofValue === eddsa.proofValue);

// Temporal verify
const vr = JSON.parse(core.verify(JSON.stringify(eddsa.signed_credential), pub, '2026-04-26T10:02:00Z', 30));
ok('verify within window', vr.valid === true);

// Dual proof (ML-DSA keys from the hybrid vector, no RNG)
const signedDual = core.signDual(JSON.stringify(eddsa.unsigned_credential), seed,
  hybrid.mldsa44.secret_key_b64, hybrid.mldsa44.public_key_b64,
  eddsa.verificationMethod, eddsa.verificationMethod.replace('#key-1', '#key-2'), eddsa.created);
ok('dual proof is an array', Array.isArray(JSON.parse(signedDual).proof));
ok('verifies dual proof', core.verifyDual(signedDual, pub, hybrid.mldsa44.public_key_b64) === true);

// Composite verify of the shared hybrid credential end-to-end
ok('verifies shared composite credential',
  core.verifyComposite(JSON.stringify(hybrid.signed_credential), hybrid.ed25519.public_key_b64, hybrid.mldsa44.public_key_b64) === true);

// Revocation
ok('status revoked sample', core.verifyStatus(JSON.stringify(status.sample_credential_status_revoked), JSON.stringify(status.status_list_credential)) === true);
ok('status active sample', core.verifyStatus(JSON.stringify(status.sample_credential_status_active), JSON.stringify(status.status_list_credential)) === false);

// Delegation: build links and validate the time-bound chain rule
const dIntent = JSON.stringify({ action: 'read', target: 't', resource: 'https://api/x' });
const dl1 = core.buildDelegationLink('did:web:a', 'did:web:b', dIntent, '2026-04-26T09:00:00Z', '2026-04-26T12:00:00Z', null);
const dl2 = core.buildDelegationLink('did:web:b', 'did:web:c', dIntent, '2026-04-26T10:00:00Z', '2026-04-26T11:00:00Z', null);
const dChain = '[' + dl1 + ',' + dl2 + ']';
ok('delegation chain time-bound valid', core.verifyChainTimeBound(dChain, '2026-04-26T10:30:00Z', 30) === true);
ok('delegation chain outside window rejected', core.verifyChainTimeBound(dChain, '2026-04-26T13:00:00Z', 30) === false);

// FROST(Ed25519) threshold signing: 2-of-3 ceremony. aggregate() self-verifies
// inside the core before it returns, so a successful, non-throwing call is
// itself the proof that the resulting signature is valid.
const generated = JSON.parse(core.thresholdGenerateKey(2, 3));
ok('threshold_generate_key produces 3 shares', generated.shares.length === 3);

const [share0, share1] = generated.shares;
const round1A = JSON.parse(core.thresholdCommit(JSON.stringify(share0)));
const round1B = JSON.parse(core.thresholdCommit(JSON.stringify(share1)));
const commitmentsJson = JSON.stringify({
  [share0.identifier]: round1A.commitments,
  [share1.identifier]: round1B.commitments,
});
const thresholdMessage = Buffer.from('charge api.bank invoices/42').toString('base64');
const sigShare0 = core.thresholdSignShare(thresholdMessage, JSON.stringify(share0), round1A.nonces, commitmentsJson);
const sigShare1 = core.thresholdSignShare(thresholdMessage, JSON.stringify(share1), round1B.nonces, commitmentsJson);
const sharesJson = JSON.stringify({ [share0.identifier]: sigShare0, [share1.identifier]: sigShare1 });
const signatureB64 = core.thresholdAggregate(
  thresholdMessage, commitmentsJson, sharesJson, JSON.stringify(generated.group_public_key));
ok('threshold_aggregate produces a self-verified 64-byte signature', Buffer.from(signatureB64, 'base64').length === 64);

// Authority Freshness: reproduce the shared vector's proof in the browser core,
// verify the shared credential, and reach the same freshness verdicts.
const authority = rd('../../test-vectors/authority-state/vector.json');
const aSubject = authority.unsigned_credential.credentialSubject;
const aSigned = JSON.parse(core.signAuthorityState(
  authority.unsigned_credential.issuer,
  authority.unsigned_credential.id,
  aSubject.authorityEpoch,
  aSubject.status,
  authority.unsigned_credential.validFrom,
  authority.unsigned_credential.validUntil,
  aSubject.id,
  authority.ed25519.seed_b64,
  authority.verificationMethod,
  authority.created,
));
ok('authority state reproduces the shared proofValue', aSigned.proof.proofValue === authority.proofValue);
ok('authority state verifies the shared credential', JSON.parse(core.verifyAuthorityState(
  JSON.stringify(authority.signed_credential), authority.ed25519.public_key_b64,
  '2026-07-26T10:02:00Z', 30)).valid === true);
ok('authority epoch reads back', core.readAuthorityEpoch(JSON.stringify(authority.signed_credential)) === aSubject.authorityEpoch);
ok('authority status reads back', core.readAuthorityStatus(JSON.stringify(authority.signed_credential)) === aSubject.status);

let freshnessFailures = 0;
for (const c of authority.freshness.cases) {
  const v = JSON.parse(core.evaluateAuthorityFreshness(
    c.tier, c.voucher_epoch, c.last_seen_epoch, c.current_status, c.live_cosign_ok));
  if (v.allow !== c.expected_allow) freshnessFailures++;
  if (c.expected_reason !== undefined && v.reason !== c.expected_reason) freshnessFailures++;
}
ok(`authority freshness matches all ${authority.freshness.cases.length} shared cases`, freshnessFailures === 0);

// Reasoned Action Proofs + event-triggered intent recheck: verify a Python-signed
// seal in WASM, recompute the JCS digest byte-for-byte, and return the SAME
// accept/reject verdict for every case in the shared intent-recheck vector.
const intent = rd('../../test-vectors/intent-recheck/vector.json');
const intentPubB64 = Buffer.from(intent.public_key_hex, 'hex').toString('base64');
ok(
  'intent-recheck justification digest matches reference',
  core.reasoningJustificationDigest(JSON.stringify(intent.reference_justification)) ===
    intent.expected_justification_digest,
);
for (const c of intent.cases) {
  const cj = JSON.stringify(c.credential);
  ok(`intent-recheck signature verifies: ${c.name}`, core.verifyProof(cj, intentPubB64) === true);
  const reason = core.reasoningVerifyIntentFreshness(cj, c.tier, c.last_pulse) ?? null;
  ok(`intent-recheck verdict matches: ${c.name}`, reason === c.expected_reason);
}
// Execution-time reseal produces an accepted fresh seal in a later interval.
const irSeed = Buffer.from(new Uint8Array(32).fill(7)).toString('base64');
const irIntent = JSON.stringify({ action: 'transfer_funds', target: 'account:9911', resource: 'https://bank.example/v1/xfer' });
const irHash = core.reasoningArtifactDigest(JSON.stringify({ text: 'please move $500 to savings' }));
const irAnchors = JSON.stringify([{ type: 'user_message', claim: 'user asked', ref: 'urn:msg:42', evidenceHash: irHash }]);
const resealed = core.reasoningResealIntent(irSeed, 'did:web:agent.example', 'did:web:agent.example#key-1', irIntent, irAnchors, 3, '2026-08-02T10:05:00Z', 'urn:uuid:aaaa', true);
ok('intent-recheck reseal signature verifies', core.verifyProof(resealed, intentPubB64) === true);
ok('intent-recheck reseal is accepted as fresh', (core.reasoningVerifyIntentFreshness(resealed, 3, '2026-08-02T10:05:00Z') ?? null) === null);

console.log(`\nTOTAL: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
