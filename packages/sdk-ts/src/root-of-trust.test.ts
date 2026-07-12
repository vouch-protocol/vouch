/**
 * Root of Trust for Machine Identity: interop and reproduction tests.
 *
 * Gates the TypeScript port against the Python-generated interop vector at
 * `test-vectors/root-of-trust/vector.json`. Proves the TS SDK can (a) verify a
 * chain of Python-signed credentials, (b) reproduce those credentials
 * byte-for-byte from the same fixed inputs, and (c) reject a tampered chain.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
import { describe, expect, it } from 'vitest';

import { encodeEd25519Public } from './multikey';
import {
  ACTION_ISSUE_AGENT_IDENTITY,
  buildAgentIdentity,
  buildRecognizedIssuer,
  buildRootOfTrust,
  verifyIdentityChain,
} from './root-of-trust';
import { Signer } from './signer';

// Node needs DER-wrapped keys; a raw Ed25519 seed gets this fixed PKCS8 prefix.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Build a did:key Signer from a fixed 32-byte Ed25519 seed. */
function signerFromSeed(seed: Uint8Array): Signer {
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
  const pubJwk = crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x: string };
  const xRaw = new Uint8Array(Buffer.from(pubJwk.x, 'base64url'));
  const did = 'did:key:' + encodeEd25519Public(xRaw);
  const jwk = JSON.stringify({
    kty: 'OKP',
    crv: 'Ed25519',
    x: pubJwk.x,
    d: Buffer.from(seed).toString('base64url'),
  });
  return new Signer({ privateKey: jwk, did });
}

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

const vectorPath = fileURLToPath(
  new URL('../../../test-vectors/root-of-trust/vector.json', import.meta.url)
);
const vector = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

// Fixed inputs that reproduce the committed vector.
const FIXED_TIME = new Date('2026-01-01T00:00:00Z');
const VALID_SECONDS = 100 * 365 * 24 * 3600;
const ATTRIBUTES = { owner: 'Acme', model: 'gpt-x', capabilityClass: 'shopping' };

describe('Root of Trust: verify a Python-signed chain (interop)', () => {
  it('verifies the agent identity anchored to the pinned root', async () => {
    const result = await verifyIdentityChain(vector.agentIdentity, vector.recognizedIssuer, {
      trustedRoot: vector.trustedRoot,
      rootCredential: vector.rootOfTrust,
    });

    expect(result.ok).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.agentDid).toBe(vector.expected.agentDid);
    expect(result.issuerDid).toBe(vector.expected.issuerDid);
    expect(result.rootDid).toBe(vector.trustedRoot);
    expect(result.attributes).toEqual(ATTRIBUTES);
  });
});

describe('Root of Trust: reproduce the vector byte-for-byte', () => {
  const rootSigner = signerFromSeed(seed(0x01));
  const issuerSigner = signerFromSeed(seed(0x02));
  const agentSigner = signerFromSeed(seed(0x03));

  it('derives the same did:key identifiers as the vector', () => {
    expect(rootSigner.getDid()).toBe(vector.trustedRoot);
    expect(issuerSigner.getDid()).toBe(vector.recognizedIssuer.credentialSubject.id);
    expect(agentSigner.getDid()).toBe(vector.expected.agentDid);
  });

  it('reproduces the Root of Trust credential proofValue', async () => {
    const cred = await buildRootOfTrust(rootSigner, {
      name: 'Vouch Machine Identity Root',
      validSeconds: VALID_SECONDS,
      validFrom: FIXED_TIME,
      created: FIXED_TIME,
      credentialId: 'urn:uuid:11111111-1111-1111-1111-111111111111',
    });
    expect(cred).toEqual(vector.rootOfTrust);
    expect((cred.proof as { proofValue: string }).proofValue).toBe(
      vector.rootOfTrust.proof.proofValue
    );
  });

  it('reproduces the Recognized Issuer credential proofValue', async () => {
    const cred = await buildRecognizedIssuer(rootSigner, {
      issuerDid: issuerSigner.getDid(),
      recognizedActions: [ACTION_ISSUE_AGENT_IDENTITY],
      validSeconds: VALID_SECONDS,
      validFrom: FIXED_TIME,
      created: FIXED_TIME,
      credentialId: 'urn:uuid:22222222-2222-2222-2222-222222222222',
    });
    expect(cred).toEqual(vector.recognizedIssuer);
    expect((cred.proof as { proofValue: string }).proofValue).toBe(
      vector.recognizedIssuer.proof.proofValue
    );
  });

  it('reproduces the Agent Identity credential proofValue', async () => {
    const cred = await buildAgentIdentity(issuerSigner, {
      subjectDid: agentSigner.getDid(),
      attributes: ATTRIBUTES,
      validSeconds: VALID_SECONDS,
      validFrom: FIXED_TIME,
      created: FIXED_TIME,
      credentialId: 'urn:uuid:33333333-3333-3333-3333-333333333333',
    });
    expect(cred).toEqual(vector.agentIdentity);
    expect((cred.proof as { proofValue: string }).proofValue).toBe(
      vector.agentIdentity.proof.proofValue
    );
  });
});

describe('Root of Trust: adversarial rejection', () => {
  it('rejects the chain when the identity proofValue is tampered', async () => {
    const tampered = {
      ...vector.agentIdentity,
      proof: {
        ...vector.agentIdentity.proof,
        // Flip one character in the base58 proofValue.
        proofValue: flipOneChar(vector.agentIdentity.proof.proofValue),
      },
    };

    const result = await verifyIdentityChain(tampered, vector.recognizedIssuer, {
      trustedRoot: vector.trustedRoot,
      rootCredential: vector.rootOfTrust,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('identity_proof_invalid');
  });
});

/** Flip a single character of a proofValue to a different valid base58 char. */
function flipOneChar(proofValue: string): string {
  const i = proofValue.length - 1;
  const ch = proofValue[i];
  const replacement = ch === 'A' ? 'B' : 'A';
  return proofValue.slice(0, i) + replacement + proofValue.slice(i + 1);
}
