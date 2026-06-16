/**
 * Scannable robot passport tests (TypeScript). Mirrors the Python
 * tests/test_robot_handshake_blackbox_passport.py passport cases: build, encode
 * to a vouch-passport: URI, decode and verify offline, surface live standing,
 * and reject an expired passport.
 */

import * as crypto from 'crypto';

import {
  Signer,
  generateIdentity,
  buildPassport,
  encodePassport,
  decodePassport,
  verifyPassport,
  PASSPORT_URI_SCHEME,
  STATUS_SUSPENDED,
} from '../src';

async function authority(domain = 'owner.example.com') {
  const keys = await generateIdentity(domain);
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did: `did:web:${domain}` });
  const pub = crypto.createPublicKey({ key: JSON.parse(keys.publicKeyJwk) as crypto.JsonWebKey, format: 'jwk' });
  return { signer, pub };
}

describe('scannable robot passport', () => {
  it('encodes to a vouch-passport URI and decodes back unchanged', async () => {
    const { signer } = await authority();
    const passport = await buildPassport(signer, {
      robotDid: 'did:web:robot.example.com',
      make: 'Acme',
      model: 'AR-7',
      owner: 'did:web:owner.example.com',
      authorizedActions: ['lift', 'move'],
      certification: 'CE-2026',
    });
    const uri = encodePassport(passport);
    expect(uri.startsWith(PASSPORT_URI_SCHEME + 'u')).toBe(true);
    expect(decodePassport(uri)).toEqual(passport);
  });

  it('verifies a passport offline from its URI and surfaces standing', async () => {
    const { signer, pub } = await authority();
    const passport = await buildPassport(signer, {
      robotDid: 'did:web:robot.example.com',
      make: 'Acme',
      model: 'AR-7',
      owner: 'did:web:owner.example.com',
      authorizedActions: ['lift'],
      status: STATUS_SUSPENDED,
    });
    const uri = encodePassport(passport);

    const fromCred = verifyPassport(passport, pub);
    const fromUri = verifyPassport(uri, pub);
    expect(fromCred.ok).toBe(true);
    expect(fromUri.ok).toBe(true);
    // A suspended passport still verifies, but the scanner sees the status.
    expect(fromUri.summary!.status).toBe(STATUS_SUSPENDED);
    expect(fromUri.summary!.owner).toBe('did:web:owner.example.com');
  });

  it('rejects an expired passport and a non-passport URI', async () => {
    const { signer, pub } = await authority();
    const passport = await buildPassport(signer, {
      robotDid: 'did:web:robot.example.com',
      make: 'Acme',
      model: 'AR-7',
      owner: 'did:web:owner.example.com',
      authorizedActions: ['lift'],
      validSeconds: 60,
    });
    // A scan far in the future sees it expired.
    expect(verifyPassport(passport, pub, { now: new Date('2099-01-01T00:00:00Z') }).ok).toBe(false);
    expect(verifyPassport('not-a-passport-uri', pub).ok).toBe(false);
  });
});
