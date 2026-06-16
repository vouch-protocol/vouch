/**
 * Model-and-config provenance tests (TypeScript). Mirrors the Python
 * tests/test_robot_provenance_capability.py provenance cases.
 *
 * The first test is the cross-language interop proof: TypeScript reproduces the
 * exact config hash the Python module pins in the shared interop vector.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  configHash,
  buildProvenanceAttestation,
  verifyProvenanceAttestation,
  MODEL_PROVENANCE_TYPE,
} from '../src';

const VECTOR = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../../../test-vectors/robotics/vector.json'),
    'utf8'
  )
);

function publicKeyFromJwk(jwk: unknown): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
}

describe('model provenance', () => {
  it('reproduces the Python config hash (byte-identical)', () => {
    expect(configHash(VECTOR.config)).toBe(VECTOR.expected_config_hash);
  });

  it('builds and verifies a provenance attestation, including the config hash', async () => {
    const keys = await generateIdentity('robot.example.com');
    const signer = new Signer({
      privateKey: keys.privateKeyJwk,
      did: 'did:web:robot.example.com',
    });
    const att = await buildProvenanceAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      modelName: 'vla-7b',
      weightsHash: 'uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      safetyPolicy: 'policy-1',
      config: VECTOR.config,
      version: '1.0',
    });
    expect(att.type as string[]).toContain(MODEL_PROVENANCE_TYPE);

    const robotPub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
    expect(verifyProvenanceAttestation(att, robotPub, VECTOR.config).ok).toBe(true);
    // A different config no longer matches the recorded configHash.
    expect(verifyProvenanceAttestation(att, robotPub, { temperature: 1.0 }).ok).toBe(false);
  });

  it('re-signs on OTA update via supersedes', async () => {
    const keys = await generateIdentity('robot.example.com');
    const signer = new Signer({
      privateKey: keys.privateKeyJwk,
      did: 'did:web:robot.example.com',
    });
    const v1 = await buildProvenanceAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      modelName: 'vla-7b',
      weightsHash: 'uAAAA',
      safetyPolicy: 'policy-1',
    });
    const v2 = await buildProvenanceAttestation(signer, {
      robotDid: 'did:web:robot.example.com',
      modelName: 'vla-7b',
      weightsHash: 'uBBBB',
      safetyPolicy: 'policy-2',
      supersedes: 'urn:prev',
    });
    const robotPub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
    expect(verifyProvenanceAttestation(v1, robotPub).ok).toBe(true);
    expect(verifyProvenanceAttestation(v2, robotPub).ok).toBe(true);
    expect((v2.credentialSubject as Record<string, unknown>).supersedes).toBe('urn:prev');
  });
});
