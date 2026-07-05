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

console.log(`\nTOTAL: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
