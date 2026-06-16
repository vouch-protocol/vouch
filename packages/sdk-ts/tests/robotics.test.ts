/**
 * Robot identity tests (TypeScript). Mirrors tests/test_robot_identity.py.
 *
 * The first test is the cross-language interop proof: the TypeScript verifier
 * accepts the credential minted by the Python module and pinned in the shared
 * interop vector. Both implementations produce and check byte-identical
 * canonical forms.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  SoftwareRootOfTrust,
  mintRobotIdentity,
  verifyRobotIdentity,
  ROBOT_IDENTITY_TYPE,
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

async function newRobot(did = 'did:web:robot.example.com') {
  const keys = await generateIdentity('robot.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const robotPub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, robotPub };
}

describe('robot identity', () => {
  it('verifies the Python-generated interop vector (cross-language)', () => {
    const robotPub = publicKeyFromJwk(VECTOR.robot_public_key_jwk);
    const res = verifyRobotIdentity(VECTOR.robot_identity_credential, robotPub);
    expect(res.ok).toBe(true);
    expect(res.subject?.make).toBe('Acme Robotics');
    expect(res.subject?.serial).toBe('SN-000123');
  });

  it('mints and verifies a credential round-trip', async () => {
    const { signer, robotPub } = await newRobot();
    const root = new SoftwareRootOfTrust(new Uint8Array(32).fill(7), 'TPM');
    const cred = await mintRobotIdentity(signer, root, {
      make: 'Acme',
      model: 'AR-7',
      serial: 'SN-1',
      owner: 'did:web:owner.example.com',
    });
    expect(cred.type as string[]).toContain(ROBOT_IDENTITY_TYPE);
    expect(verifyRobotIdentity(cred, robotPub).ok).toBe(true);
  });

  it('rejects a forged hardware root', async () => {
    const { signer, robotPub } = await newRobot();
    const root = new SoftwareRootOfTrust(new Uint8Array(32).fill(7), 'TPM');
    const cred = (await mintRobotIdentity(signer, root, {
      make: 'A',
      model: 'B',
      serial: 'C',
    })) as Record<string, any>;

    // Point the hardware-root key at an attacker's; the attestation, signed by
    // the real root over the binding, no longer verifies.
    const attacker = new SoftwareRootOfTrust(new Uint8Array(32).fill(9), 'TPM');
    cred.credentialSubject.hardwareRoot.publicKeyMultibase = attacker.publicKeyMultibase();
    // Re-sign the credential proof so only the hardware attestation is wrong.
    delete cred.proof;
    const resigned = await signer.attachProof(cred);

    expect(verifyRobotIdentity(resigned, robotPub).ok).toBe(false);
  });
});
