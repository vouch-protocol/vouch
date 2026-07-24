/**
 * Cross-language interop for the disconnected-edge (DTN) robotics primitives.
 *
 * Loads the shared vector at test-vectors/robotics/dtn_vector.json (Python-signed,
 * PAD-106 to PAD-124) and proves the TypeScript SDK verifies every credential and
 * reproduces the sparse-Merkle revocation root byte-for-byte — the same vector the
 * Rust core interop test uses.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import { describe, it, expect } from 'vitest';

import * as dtn from '../src/robotics/dtn';

type Obj = Record<string, unknown>;
type Vec3 = [number, number, number];

const VECTOR = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../../../test-vectors/robotics/dtn_vector.json'), 'utf-8')
) as Obj;

function pubKey(): crypto.KeyObject {
  const x = VECTOR.issuerPublicKeyRawB64Url as string;
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x } as crypto.JsonWebKey, format: 'jwk' });
}

const v3 = (v: unknown): Vec3 => v as Vec3;

describe('disconnected-edge interop', () => {
  it('verifies every Python-signed DTN credential', () => {
    const pk = pubKey();
    for (const entry of VECTOR.credentials as Obj[]) {
      const cred = entry.credential as Obj;
      const v = entry.verify as Obj;
      const kind = v.kind as string;
      let ok = false;
      switch (kind) {
        case 'freshness_token':
          ok = !!dtn.verifyFreshnessToken(cred, pk, { verifierEpoch: v.verifierEpoch as number, tier: v.tier as string });
          break;
        case 'presence':
          ok = !!dtn.verifyPresenceAttestation(cred, pk, { verifierPosition: v3(v.verifierPosition), expectedNonce: v.expectedNonce as string });
          break;
        case 'geoscope': {
          const sub = dtn.verifyGeoscopedGrant(cred, pk);
          ok = !!sub && dtn.geoscopePermits(sub, v3(v.position));
          break;
        }
        case 'conditional_revocation':
          ok = !!dtn.verifyConditionalRevocation(cred, pk);
          break;
        case 'range_observation':
          ok = !!dtn.verifyRangeObservation(cred, pk);
          break;
        case 'beam_presence':
          ok = !!dtn.verifyBeamPresence(cred, pk, { peerDirection: v3(v.peerDirection), expectedNonce: v.expectedNonce as string });
          break;
        case 'distress':
          ok = !!dtn.verifyDistressAttestation(cred, pk);
          break;
        case 'trust_state_update':
          ok = !!dtn.verifyTrustStateUpdate(cred, pk);
          break;
        case 'time_quality': {
          const sub = dtn.verifyTimeQualityAttestation(cred, pk);
          ok = !!sub && dtn.timeQualityPermits(sub, v.tier as string);
          break;
        }
        case 'integrity_risk':
          ok = !!dtn.verifyIntegrityRiskAttestation(cred, pk);
          break;
        case 'perception_claim':
          ok = !!dtn.verifyPerceptionClaim(cred, pk);
          break;
        case 'bundle':
          ok = !!dtn.verifyBundleTrust(cred, pk, v.payloadHash as string);
          break;
        default:
          throw new Error(`unknown verify kind: ${kind}`);
      }
      expect(ok, `verify ${entry.name as string}`).toBe(true);
    }
  });

  it('reproduces the sparse-Merkle root and verifies proofs', () => {
    const pk = pubKey();
    const acc = VECTOR.accumulator as Obj;
    const tree = new dtn.SparseMerkleTree();
    for (const cid of acc.revokedIds as string[]) tree.revoke(cid);
    expect(tree.rootMultibase()).toBe(acc.rootMultibase as string);

    const signed = acc.signedRoot as Obj;
    expect(dtn.verifyNonRevocation(acc.nonRevokedId as string, acc.nonRevokedProof as Obj, signed, pk)).toBe(true);
    expect(dtn.verifyNonRevocation(acc.revokedId as string, acc.revokedProof as Obj, signed, pk)).toBe(false);
  });
});
