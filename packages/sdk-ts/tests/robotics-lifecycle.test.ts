/**
 * Robot lifecycle tests (TypeScript). Mirrors the Python lifecycle.py module:
 * ownership transfer (chain of custody), key rotation (key history), and
 * decommission (retirement).
 *
 * The cross-language interop cases verify the Python-signed lifecycle
 * credentials pinned in the shared interop vector: the TypeScript verifier
 * accepts what the Python module produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  buildOwnershipTransfer,
  verifyOwnershipTransfer,
  verifyCustodyChain,
  buildKeyRotation,
  verifyKeyRotation,
  verifyKeyHistory,
  buildDecommission,
  verifyDecommission,
  OWNERSHIP_TRANSFER_TYPE,
  KEY_ROTATION_TYPE,
  DECOMMISSION_TYPE,
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

async function newSigner(did: string) {
  const keys = await generateIdentity('example.com');
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  const multikey = await signer.getPublicKeyMultikey();
  return { signer, pub, multikey };
}

const ROBOT = 'did:web:robot.example.com';

describe('ownership transfer (cross-language interop)', () => {
  it('verifies the Python-generated ownership transfer credential', () => {
    const ownerKey = publicKeyFromJwk(VECTOR.ownership_transfer_owner_key);
    const res = verifyOwnershipTransfer(VECTOR.ownership_transfer_credential, ownerKey);
    expect(res.ok).toBe(true);
    expect(res.subject?.fromOwner).toBe('did:web:owner-a.example.com');
    expect(res.subject?.toOwner).toBe('did:web:owner-b.example.com');
  });
});

describe('key rotation (cross-language interop)', () => {
  it('verifies the Python-generated key rotation credential', () => {
    const robotPub = publicKeyFromJwk(VECTOR.robot_public_key_jwk);
    const res = verifyKeyRotation(VECTOR.key_rotation_credential, robotPub);
    expect(res.ok).toBe(true);
    expect(res.subject?.newKey).toBe(
      'z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2'
    );
  });
});

describe('decommission (cross-language interop)', () => {
  it('verifies the Python-generated decommission credential', () => {
    const authorityKey = publicKeyFromJwk(VECTOR.decommission_authority_key);
    const res = verifyDecommission(VECTOR.decommission_credential, authorityKey);
    expect(res.ok).toBe(true);
    expect(res.subject?.reason).toBe('end of service life');
    expect(res.subject?.finalDisposition).toBe('recycled');
  });
});

describe('ownership transfer round-trip', () => {
  it('builds and verifies a transfer', async () => {
    const ownerA = await newSigner('did:web:owner-a.example.com');
    const cred = await buildOwnershipTransfer(ownerA.signer, {
      robotDid: ROBOT,
      toOwner: 'did:web:owner-b.example.com',
    });
    expect(cred.type as string[]).toContain(OWNERSHIP_TRANSFER_TYPE);
    const subject = cred.credentialSubject as Record<string, unknown>;
    expect(subject.fromOwner).toBe('did:web:owner-a.example.com');
    expect(subject.toOwner).toBe('did:web:owner-b.example.com');
    const res = verifyOwnershipTransfer(cred, ownerA.pub);
    expect(res.ok).toBe(true);
  });

  it('rejects a transfer whose issuer is not the fromOwner', async () => {
    // The signer's DID is owner-a, but fromOwner claims owner-x. Only the
    // current owner may transfer the robot, so verification must fail.
    const ownerA = await newSigner('did:web:owner-a.example.com');
    const cred = await buildOwnershipTransfer(ownerA.signer, {
      robotDid: ROBOT,
      toOwner: 'did:web:owner-b.example.com',
      fromOwner: 'did:web:owner-x.example.com',
    });
    const res = verifyOwnershipTransfer(cred, ownerA.pub);
    expect(res.ok).toBe(false);
  });
});

describe('custody chain', () => {
  it('accepts an ordered chain of custody', async () => {
    const ownerA = await newSigner('did:web:owner-a.example.com');
    const ownerB = await newSigner('did:web:owner-b.example.com');
    const t1 = await buildOwnershipTransfer(ownerA.signer, {
      robotDid: ROBOT,
      toOwner: 'did:web:owner-b.example.com',
    });
    const t2 = await buildOwnershipTransfer(ownerB.signer, {
      robotDid: ROBOT,
      toOwner: 'did:web:owner-c.example.com',
      prevTransferId: 'transfer-1',
    });
    const publicKeys: Record<string, crypto.KeyObject> = {
      'did:web:owner-a.example.com': ownerA.pub,
      'did:web:owner-b.example.com': ownerB.pub,
    };
    const res = verifyCustodyChain([t1, t2], publicKeys, {
      originOwner: 'did:web:owner-a.example.com',
    });
    expect(res.ok).toBe(true);
    expect(res.currentOwner).toBe('did:web:owner-c.example.com');
  });

  it('rejects a broken chain where a link does not connect', async () => {
    const ownerA = await newSigner('did:web:owner-a.example.com');
    const ownerB = await newSigner('did:web:owner-b.example.com');
    // First link hands off to owner-b, but the second link's fromOwner is the
    // signer owner-b transferring as if it received from owner-z. The chain
    // still connects b -> ... but origin expectation breaks when we assert the
    // first fromOwner is owner-a and the second fromOwner mismatches.
    const t1 = await buildOwnershipTransfer(ownerA.signer, {
      robotDid: ROBOT,
      toOwner: 'did:web:owner-x.example.com', // not owner-b
    });
    const t2 = await buildOwnershipTransfer(ownerB.signer, {
      robotDid: ROBOT,
      toOwner: 'did:web:owner-c.example.com',
    });
    const publicKeys: Record<string, crypto.KeyObject> = {
      'did:web:owner-a.example.com': ownerA.pub,
      'did:web:owner-b.example.com': ownerB.pub,
    };
    // t1.toOwner is owner-x, but t2.fromOwner is owner-b: the links do not join.
    const res = verifyCustodyChain([t1, t2], publicKeys, {
      originOwner: 'did:web:owner-a.example.com',
    });
    expect(res.ok).toBe(false);
  });
});

describe('key rotation round-trip and history', () => {
  it('builds and verifies a key rotation signed by the old key', async () => {
    const old = await newSigner(ROBOT);
    const next = await newSigner(ROBOT);
    const cred = await buildKeyRotation(old.signer, {
      robotDid: ROBOT,
      newKeyMultibase: next.multikey,
      reason: 'routine',
    });
    expect(cred.type as string[]).toContain(KEY_ROTATION_TYPE);
    expect(cred.issuer).toBe(ROBOT);
    const subject = cred.credentialSubject as Record<string, unknown>;
    expect(subject.previousKey).toBe(old.multikey);
    expect(subject.newKey).toBe(next.multikey);
    const res = verifyKeyRotation(cred, old.pub);
    expect(res.ok).toBe(true);
  });

  it('verifies a key history chain from the origin key', async () => {
    const k0 = await newSigner(ROBOT);
    const k1 = await newSigner(ROBOT);
    const k2 = await newSigner(ROBOT);
    const r1 = await buildKeyRotation(k0.signer, {
      robotDid: ROBOT,
      newKeyMultibase: k1.multikey,
    });
    const r2 = await buildKeyRotation(k1.signer, {
      robotDid: ROBOT,
      newKeyMultibase: k2.multikey,
    });
    const publicKeys: Record<string, crypto.KeyObject> = {
      [k0.multikey]: k0.pub,
      [k1.multikey]: k1.pub,
    };
    const res = verifyKeyHistory([r1, r2], k0.multikey, publicKeys);
    expect(res.ok).toBe(true);
    expect(res.currentKey).toBe(k2.multikey);
  });

  it('rejects a key history with a broken previousKey link', async () => {
    const k0 = await newSigner(ROBOT);
    const k1 = await newSigner(ROBOT);
    const k2 = await newSigner(ROBOT);
    // r1 rotates k0 -> k1, but the next rotation is signed by k2 (previousKey
    // is k2's multikey, which does not match the current key k1).
    const r1 = await buildKeyRotation(k0.signer, {
      robotDid: ROBOT,
      newKeyMultibase: k1.multikey,
    });
    const r2 = await buildKeyRotation(k2.signer, {
      robotDid: ROBOT,
      newKeyMultibase: k0.multikey,
    });
    const publicKeys: Record<string, crypto.KeyObject> = {
      [k0.multikey]: k0.pub,
      [k1.multikey]: k1.pub,
      [k2.multikey]: k2.pub,
    };
    const res = verifyKeyHistory([r1, r2], k0.multikey, publicKeys);
    expect(res.ok).toBe(false);
  });
});

describe('decommission round-trip and trusted authorities', () => {
  it('builds and verifies a decommission', async () => {
    const authority = await newSigner('did:web:authority.example.com');
    const cred = await buildDecommission(authority.signer, {
      robotDid: ROBOT,
      reason: 'end of service life',
      finalDisposition: 'recycled',
    });
    expect(cred.type as string[]).toContain(DECOMMISSION_TYPE);
    const res = verifyDecommission(cred, authority.pub);
    expect(res.ok).toBe(true);
    expect(res.subject?.decommissionedBy).toBe('did:web:authority.example.com');
  });

  it('accepts a decommission from a trusted authority', async () => {
    const authority = await newSigner('did:web:authority.example.com');
    const cred = await buildDecommission(authority.signer, {
      robotDid: ROBOT,
      reason: 'end of service life',
    });
    const res = verifyDecommission(cred, authority.pub, {
      trustedAuthorities: new Set(['did:web:authority.example.com']),
    });
    expect(res.ok).toBe(true);
  });

  it('rejects a decommission from an issuer outside the trusted set', async () => {
    const rogue = await newSigner('did:web:rogue.example.com');
    const cred = await buildDecommission(rogue.signer, {
      robotDid: ROBOT,
      reason: 'unauthorized retirement',
    });
    const res = verifyDecommission(cred, rogue.pub, {
      trustedAuthorities: new Set(['did:web:authority.example.com']),
    });
    expect(res.ok).toBe(false);
  });
});
