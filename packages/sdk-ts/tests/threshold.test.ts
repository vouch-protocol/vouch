/**
 * Tests for FROST(Ed25519) threshold signing in the TypeScript SDK. Mirrors
 * the Python tests/test_threshold.py. Requires the optional peer dependency
 * @vouch-protocol-official/core-wasm; skipped entirely when it is not
 * installed (built locally via `core/wasm/build-npm.sh` and linked with
 * `npm install ../../core/wasm/pkg` for a local test run), the same graceful
 * skip the Python SDK uses when its native library is unavailable.
 */

import { createRequire } from 'node:module';

import {
  Signer,
  ThresholdError,
  ThresholdSigner,
  Verifier,
  groupPublicKeyMultikey,
  thresholdAggregate,
  thresholdCommit,
  thresholdGenerateKey,
  thresholdSignShare,
} from '../src';
import * as threshold from '../src/threshold';

let coreWasmAvailable = true;
try {
  createRequire(import.meta.url).resolve('@vouch-protocol-official/core-wasm');
} catch {
  coreWasmAvailable = false;
}

describe.skipIf(!coreWasmAvailable)('threshold: FROST(Ed25519) ceremony', () => {
  test('2-of-3 signs and verifies as plain Ed25519 (self-verified inside the core)', async () => {
    // aggregate() self-verifies inside the core before returning, so a
    // resolved, non-throwing call is itself the proof that the resulting
    // signature is a valid, standard Ed25519 signature over the message.
    const generated = await threshold.generateKey(2, 3);
    expect(generated.shares).toHaveLength(3);

    const [share0, share1] = generated.shares;
    const round1A = await threshold.commit(share0);
    const round1B = await threshold.commit(share1);
    const commitments: Record<string, string> = {
      [share0.identifier]: round1A.commitments,
      [share1.identifier]: round1B.commitments,
    };

    const message = new TextEncoder().encode('charge api.bank invoices/42');
    const sigShare0 = await threshold.signShare(message, share0, round1A.nonces, commitments);
    const sigShare1 = await threshold.signShare(message, share1, round1B.nonces, commitments);
    const shares: Record<string, string> = { [share0.identifier]: sigShare0, [share1.identifier]: sigShare1 };

    const signature = await threshold.aggregate(message, commitments, shares, generated.groupPublicKey);
    expect(signature).toHaveLength(64);
  });

  test('generateKey rejects a below-minimum threshold', async () => {
    await expect(threshold.generateKey(1, 3)).rejects.toBeInstanceOf(Error);
  });

  test('groupPublicKeyMultikey encodes a standard Ed25519 multikey', async () => {
    const generated = await threshold.generateKey(2, 3);
    const mk = groupPublicKeyMultikey(generated.groupPublicKey);
    expect(mk.startsWith('z6Mk')).toBe(true);
  });

  test('ThresholdSigner runs the full ceremony and plugs into Signer.fromBackend', async () => {
    const generated = await thresholdGenerateKey(2, 3);
    const signer = await ThresholdSigner.create(generated.shares.slice(0, 2), generated.groupPublicKey);

    const vouchSigner = Signer.fromBackend(
      'did:web:agent.example',
      groupPublicKeyMultikey(generated.groupPublicKey),
      signer.sign
    );
    const credential = await vouchSigner.sign({ action: 'read', target: 't', resource: 'https://x/y' });
    const result = await Verifier.verify(credential, groupPublicKeyMultikey(generated.groupPublicKey));
    expect(result.isValid).toBe(true);
  });

  test('ThresholdSigner requires at least 2 shares', async () => {
    const generated = await thresholdGenerateKey(2, 3);
    await expect(ThresholdSigner.create(generated.shares.slice(0, 1), generated.groupPublicKey))
      .rejects.toBeInstanceOf(ThresholdError);
  });

  test('different subsets of the same group verify against the same public key', async () => {
    const generated = await thresholdGenerateKey(3, 5);
    const message = new TextEncoder().encode('same message, different signer subset');

    async function signWith(indices: number[]): Promise<Uint8Array> {
      const chosen = indices.map((i) => generated.shares[i]);
      const noncesById: Record<string, string> = {};
      const commitments: Record<string, string> = {};
      for (const share of chosen) {
        const round1 = await thresholdCommit(share);
        commitments[share.identifier] = round1.commitments;
        noncesById[share.identifier] = round1.nonces;
      }
      const sharesOut: Record<string, string> = {};
      for (const share of chosen) {
        sharesOut[share.identifier] = await thresholdSignShare(
          message, share, noncesById[share.identifier], commitments);
      }
      return thresholdAggregate(message, commitments, sharesOut, generated.groupPublicKey);
    }

    const sigA = await signWith([0, 1, 2]);
    const sigB = await signWith([2, 3, 4]);
    expect(sigA).toHaveLength(64);
    expect(sigB).toHaveLength(64);
  });
});
