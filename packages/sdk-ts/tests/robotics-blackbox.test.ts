/**
 * Robot black-box + kill-switch tests (TypeScript). Mirrors the Python
 * tests/test_robot_handshake_blackbox_passport.py black-box cases: encrypted,
 * hash-linked entries that verify and decrypt, tamper detection without the key,
 * and a kill-switch credential with an attested-authority allowlist.
 */

import * as crypto from 'crypto';

import {
  Signer,
  generateIdentity,
  BlackBoxLog,
  BlackBoxError,
  openEntry,
  verifyBlackboxChain,
  buildKillswitchCredential,
  verifyKillswitchCredential,
} from '../src';

describe('robot black box', () => {
  it('logs encrypted, hash-linked entries that verify and decrypt', () => {
    const key = crypto.randomBytes(32);
    const log = new BlackBoxLog(key);
    const e1 = log.append('boot', { ok: true });
    const e2 = log.append('move', { x: 1, y: 2 });

    expect(verifyBlackboxChain(log.entries()).ok).toBe(true);
    expect(openEntry(e1, key)).toEqual({ ok: true });
    expect(log.openEntry(e2)).toEqual({ x: 1, y: 2 });
  });

  it('detects tampering without the key', () => {
    const key = crypto.randomBytes(32);
    const log = new BlackBoxLog(key);
    log.append('a', { v: 1 });
    log.append('b', { v: 2 });
    const entries = log.entries();
    entries[1].event = 'tampered';
    expect(verifyBlackboxChain(entries).ok).toBe(false);
  });

  it('refuses to open with the wrong key', () => {
    const log = new BlackBoxLog(crypto.randomBytes(32));
    const e = log.append('x', { secret: 1 });
    expect(() => openEntry(e, crypto.randomBytes(32))).toThrow(BlackBoxError);
  });

  it('rejects a non-32-byte key', () => {
    expect(() => new BlackBoxLog(crypto.randomBytes(16))).toThrow(BlackBoxError);
  });

  it('issues and verifies a kill-switch credential with an authority allowlist', async () => {
    const keys = await generateIdentity('authority.example.com');
    const signer = new Signer({ privateKey: keys.privateKeyJwk, did: 'did:web:authority.example.com' });
    const pub = crypto.createPublicKey({ key: JSON.parse(keys.publicKeyJwk) as crypto.JsonWebKey, format: 'jwk' });

    const cred = await buildKillswitchCredential(signer, {
      target: 'did:web:robot.example.com',
      reason: 'fault detected',
    });
    expect(verifyKillswitchCredential(cred, pub).ok).toBe(true);
    expect(
      verifyKillswitchCredential(cred, pub, {
        trustedAuthorities: new Set(['did:web:authority.example.com']),
      }).ok
    ).toBe(true);
    // An issuer outside the allowlist cannot trigger the stop.
    expect(
      verifyKillswitchCredential(cred, pub, {
        trustedAuthorities: new Set(['did:web:other.example.com']),
      }).ok
    ).toBe(false);
  });
});
