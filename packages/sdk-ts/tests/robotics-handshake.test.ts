/**
 * Robot-to-robot handshake tests (TypeScript). Mirrors the Python
 * tests/test_robot_handshake_blackbox_passport.py handshake cases: a full
 * HELLO/ACCEPT/CONFIRM exchange with scope intersection, plus trust-policy and
 * nonce-mismatch rejection.
 */

import * as crypto from 'crypto';

import {
  Signer,
  generateIdentity,
  TrustPolicy,
  buildHello,
  buildAccept,
  verifyAccept,
  buildConfirm,
  verifyConfirm,
} from '../src';

async function robot(domain: string) {
  const keys = await generateIdentity(domain);
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did: `did:web:${domain}` });
  const pub = crypto.createPublicKey({ key: JSON.parse(keys.publicKeyJwk) as crypto.JsonWebKey, format: 'jwk' });
  return { signer, pub, did: `did:web:${domain}` };
}

describe('robot-to-robot handshake', () => {
  it('completes a bounded-trust handshake with scope intersection', async () => {
    const a = await robot('a.example.com');
    const b = await robot('b.example.com');
    const policyB = new TrustPolicy({ trustedDomains: ['a.example.com'] });

    const hello = await buildHello(a.signer, {
      proposedScope: ['lift', 'move', 'weld'],
      peerDid: b.did,
    });
    const accept = await buildAccept(b.signer, {
      hello,
      helloPublicKey: a.pub,
      policy: policyB,
      offeredScope: ['move', 'weld', 'paint'],
    });

    const { ok, session } = verifyAccept(accept, b.pub, { expectedNonce: hello.nonce as string });
    expect(ok).toBe(true);
    expect(session!.scope).toEqual(['move', 'weld']); // intersection, sorted

    const confirm = await buildConfirm(a.signer, { session: session! });
    expect(
      verifyConfirm(confirm, a.pub, { sessionId: session!.sessionId, expectedNonce: hello.nonce as string })
    ).toBe(true);
  });

  it('rejects an initiator outside the trust policy', async () => {
    const a = await robot('evil.example.com');
    const b = await robot('b.example.com');
    const policyB = new TrustPolicy({ trustedDomains: ['good.example.com'] });
    const hello = await buildHello(a.signer, { proposedScope: ['move'] });
    await expect(
      buildAccept(b.signer, { hello, helloPublicKey: a.pub, policy: policyB, offeredScope: ['move'] })
    ).rejects.toThrow();
  });

  it('rejects a nonce mismatch on accept', async () => {
    const a = await robot('a.example.com');
    const b = await robot('b.example.com');
    const policyB = new TrustPolicy({ acceptUnknown: true });
    const hello = await buildHello(a.signer, { proposedScope: ['move'] });
    const accept = await buildAccept(b.signer, {
      hello,
      helloPublicKey: a.pub,
      policy: policyB,
      offeredScope: ['move'],
    });
    expect(verifyAccept(accept, b.pub, { expectedNonce: 'wrong-nonce' }).ok).toBe(false);
  });
});
