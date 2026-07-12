/**
 * Robot post-quantum signing tests (TypeScript). Mirrors the Python
 * vouch/robotics/pq.py module: hybrid Ed25519 + ML-DSA-44 signing, dual verify
 * auto-detected from the proof cryptosuite, and the software re-sign migration.
 *
 * The cross-language interop cases verify the Python-signed hybrid robot
 * identity credential pinned in the shared interop vector: the TypeScript
 * verifier accepts what the Python module produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  signPq,
  isPq,
  verifyPq,
  verifyRobotCredential,
  migrateToPq,
  HYBRID_CRYPTOSUITE,
} from '../src';

const VECTOR = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../../../test-vectors/robotics/vector.json'),
    'utf8'
  )
);

const ROBOT = 'did:web:robot.example.com';

function publicKeyFromJwk(jwk: unknown): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
}

/**
 * A fresh Signer plus its Ed25519 public key (JWK) and ML-DSA-44 public
 * multikey, for local round-trip signing and verification.
 */
async function newRobotSigner() {
  const keys = await generateIdentity('robot.example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did: ROBOT });
  const edJwk = JSON.parse(keys.publicKeyJwk);
  const mldsa44Multikey = signer.publicKeyMLDSA44Multikey();
  return { signer, edJwk, edPub: publicKeyFromJwk(edJwk), mldsa44Multikey };
}

/** A minimal robot identity credential body (no proof). */
function robotCredentialBody(): Record<string, unknown> {
  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://vouch-protocol.com/contexts/v1',
    ],
    type: ['VerifiableCredential', 'RobotIdentityCredential'],
    issuer: ROBOT,
    validFrom: '2026-01-01T00:00:00Z',
    credentialSubject: {
      id: ROBOT,
      make: 'Acme Robotics',
      model: 'AR-7',
      serial: 'SN-000123',
    },
  };
}

describe('post-quantum robot credential (cross-language interop)', () => {
  it('verifies the Python-generated hybrid robot identity credential', () => {
    const ok = verifyRobotCredential(
      VECTOR.pq_robot_identity_credential,
      VECTOR.robot_public_key_jwk,
      { mldsa44PublicKey: VECTOR.robot_mldsa44_public_multikey }
    );
    expect(ok).toBe(true);
  });

  it('detects the hybrid credential as post-quantum', () => {
    expect(isPq(VECTOR.pq_robot_identity_credential)).toBe(true);
  });

  it('verifies the pinned hybrid credential directly with verifyPq', () => {
    const ok = verifyPq(
      VECTOR.pq_robot_identity_credential,
      VECTOR.robot_public_key_jwk,
      VECTOR.robot_mldsa44_public_multikey
    );
    expect(ok).toBe(true);
  });
});

describe('hybrid signing round-trip', () => {
  it('signs a robot credential hybrid and verifies it', async () => {
    const { signer, edJwk, mldsa44Multikey } = await newRobotSigner();
    const signed = await signPq(robotCredentialBody(), signer);

    expect((signed.proof as Record<string, unknown>).cryptosuite).toBe(
      HYBRID_CRYPTOSUITE
    );
    expect(isPq(signed)).toBe(true);

    const ok = verifyRobotCredential(signed, edJwk, {
      mldsa44PublicKey: mldsa44Multikey,
    });
    expect(ok).toBe(true);
  });

  it('strips any existing proof before signing hybrid', async () => {
    const { signer, edJwk, mldsa44Multikey } = await newRobotSigner();
    // Sign classical first, then re-sign hybrid over the same body.
    const classical = await signer.attachProof(robotCredentialBody());
    const signed = await signPq(classical, signer);
    expect(isPq(signed)).toBe(true);
    const ok = verifyRobotCredential(signed, edJwk, {
      mldsa44PublicKey: mldsa44Multikey,
    });
    expect(ok).toBe(true);
  });
});

describe('hybrid verification rejects invalid inputs', () => {
  it('rejects a tampered hybrid credential', async () => {
    const { signer, edJwk, mldsa44Multikey } = await newRobotSigner();
    const signed = await signPq(robotCredentialBody(), signer);
    // Tamper with the subject after signing.
    (signed.credentialSubject as Record<string, unknown>).serial = 'SN-999999';
    const ok = verifyRobotCredential(signed, edJwk, {
      mldsa44PublicKey: mldsa44Multikey,
    });
    expect(ok).toBe(false);
  });

  it('rejects a hybrid credential verified with the wrong ML-DSA-44 key', async () => {
    const { signer, edJwk } = await newRobotSigner();
    const other = await newRobotSigner();
    const signed = await signPq(robotCredentialBody(), signer);
    const ok = verifyRobotCredential(signed, edJwk, {
      mldsa44PublicKey: other.mldsa44Multikey,
    });
    expect(ok).toBe(false);
  });

  it('returns false for a hybrid credential without an ML-DSA-44 key', async () => {
    const { signer, edJwk } = await newRobotSigner();
    const signed = await signPq(robotCredentialBody(), signer);
    expect(verifyRobotCredential(signed, edJwk)).toBe(false);
  });
});

describe('backward-compatible dual verify', () => {
  it('verifies a classical credential without an ML-DSA-44 key', async () => {
    const { signer, edPub } = await newRobotSigner();
    const classical = await signer.attachProof(robotCredentialBody());
    expect(isPq(classical)).toBe(false);
    expect(verifyRobotCredential(classical, edPub)).toBe(true);
  });
});

describe('migration to post-quantum', () => {
  it('re-signs a classical credential under the hybrid cryptosuite', async () => {
    const { signer, edJwk, mldsa44Multikey } = await newRobotSigner();
    const classical = await signer.attachProof(robotCredentialBody());
    expect(isPq(classical)).toBe(false);

    const migrated = await migrateToPq(classical, signer);
    expect(isPq(migrated)).toBe(true);
    const ok = verifyRobotCredential(migrated, edJwk, {
      mldsa44PublicKey: mldsa44Multikey,
    });
    expect(ok).toBe(true);
  });
});
