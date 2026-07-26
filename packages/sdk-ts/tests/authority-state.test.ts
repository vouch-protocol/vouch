/**
 * Cross-implementation interop tests for Authority Freshness.
 *
 * Reads the shared vector at test-vectors/authority-state/vector.json and
 * asserts the TypeScript SDK is byte-identical with the Rust core, the Go
 * sidecar, and Python:
 *   - signAuthorityState / buildProof reproduce `proofValue` exactly from the
 *     seed, the unsigned credential, the verification method, and `created`;
 *   - verifyAuthorityState accepts the signed credential and rejects a tampered
 *     one;
 *   - evaluate_authority_freshness produces the same (allow, reason) for every
 *     freshness case.
 *
 * The Python and Rust suites have parallel tests over the same vector.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import { describe, expect, it, test } from 'vitest';

import {
  AUTHORITY_STATE_TYPE,
  CONSEQUENCE_CRITICAL,
  CONSEQUENCE_SENSITIVE,
  buildAuthorityState,
  evaluateAuthorityFreshness,
  readAuthorityEpoch,
  readAuthorityStatus,
  signAuthorityState,
  verifyAuthorityState,
} from '../src/authority-state';
import { buildProof } from '../src/data-integrity';

interface FreshnessCase {
  name: string;
  tier: string;
  voucher_epoch: number | null;
  last_seen_epoch: number | null;
  current_status: string | null;
  live_cosign_ok: boolean | null;
  expected_allow: boolean;
  expected_reason?: string;
}

interface AuthorityStateVector {
  ed25519: { seed_b64: string; public_key_b64: string };
  verificationMethod: string;
  created: string;
  unsigned_credential: Record<string, unknown>;
  signed_credential: Record<string, unknown>;
  proofValue: string;
  freshness: { cases: FreshnessCase[] };
}

const VECTOR_PATH = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  'test-vectors',
  'authority-state',
  'vector.json'
);

function loadVector(): AuthorityStateVector {
  return JSON.parse(fs.readFileSync(VECTOR_PATH, 'utf-8')) as AuthorityStateVector;
}

/** Build a Node Ed25519 private KeyObject from the raw 32-byte seed. */
function privateKeyFromSeed(seedB64: string, publicB64: string): crypto.KeyObject {
  const d = Buffer.from(seedB64, 'base64').toString('base64url');
  const x = Buffer.from(publicB64, 'base64').toString('base64url');
  return crypto.createPrivateKey({
    key: { kty: 'OKP', crv: 'Ed25519', d, x } as crypto.JsonWebKey,
    format: 'jwk',
  });
}

function subjectOf(cred: Record<string, unknown>): Record<string, unknown> {
  return cred.credentialSubject as Record<string, unknown>;
}

const vector = loadVector();

describe('AuthorityState interop vector', () => {
  const privateKey = privateKeyFromSeed(
    vector.ed25519.seed_b64,
    vector.ed25519.public_key_b64
  );
  const rawPublicKey = new Uint8Array(
    Buffer.from(vector.ed25519.public_key_b64, 'base64')
  );
  const created = new Date(vector.created);
  const subject = subjectOf(vector.unsigned_credential);

  const buildOpts = {
    issuerDid: vector.unsigned_credential.issuer as string,
    credentialId: vector.unsigned_credential.id as string,
    authorityEpoch: subject.authorityEpoch as number,
    status: subject.status as string,
    validFrom: vector.unsigned_credential.validFrom as string,
    validUntil: vector.unsigned_credential.validUntil as string,
    subjectDid: subject.id as string,
  };

  it('reproduces the unsigned credential byte-shape', () => {
    expect(buildAuthorityState(buildOpts)).toEqual(vector.unsigned_credential);
  });

  it('reproduces proofValue via buildProof over the unsigned credential', () => {
    const proof = buildProof(vector.unsigned_credential, {
      privateKey,
      verificationMethod: vector.verificationMethod,
      created,
    });
    expect(proof.proofValue).toBe(vector.proofValue);
  });

  it('reproduces proofValue via signAuthorityState', () => {
    const signed = signAuthorityState(buildOpts, {
      privateKey,
      verificationMethod: vector.verificationMethod,
      created,
    });
    expect((signed.proof as { proofValue: string }).proofValue).toBe(
      vector.proofValue
    );
    // and the whole signed credential matches the vector byte-for-byte.
    expect(signed).toEqual(vector.signed_credential);
  });

  it('verifies the signed credential', () => {
    const result = verifyAuthorityState(
      vector.signed_credential,
      rawPublicKey,
      '2026-07-26T10:02:00Z',
      30
    );
    expect(result.proofValid).toBe(true);
    expect(result.timeValid).toBe(true);
  });

  it('rejects a tampered epoch', () => {
    const tampered = JSON.parse(
      JSON.stringify(vector.signed_credential)
    ) as Record<string, unknown>;
    subjectOf(tampered).authorityEpoch = 999;
    const result = verifyAuthorityState(
      tampered,
      rawPublicKey,
      '2026-07-26T10:02:00Z',
      30
    );
    expect(result.proofValid).toBe(false);
  });

  it('reads epoch and status without verifying', () => {
    expect(readAuthorityEpoch(vector.signed_credential)).toBe(
      subject.authorityEpoch
    );
    expect(readAuthorityStatus(vector.signed_credential)).toBe(subject.status);
  });

  for (const c of vector.freshness.cases) {
    test(`freshness: ${c.name}`, () => {
      const verdict = evaluateAuthorityFreshness(
        c.tier,
        c.voucher_epoch,
        c.last_seen_epoch,
        c.current_status,
        c.live_cosign_ok
      );
      expect(verdict.allow).toBe(c.expected_allow);
      if (c.expected_reason !== undefined) {
        expect(verdict.reason).toBe(c.expected_reason);
      }
    });
  }
});

describe('AuthorityState unit behavior', () => {
  it('builds the expected shape', () => {
    const cred = buildAuthorityState({
      issuerDid: 'did:web:treasury.example.com',
      credentialId: 'urn:uuid:00000000-0000-4000-8000-000000000000',
      authorityEpoch: 7,
      validFrom: '2026-07-26T10:00:00Z',
      validUntil: '2026-07-26T10:05:00Z',
    });
    expect(cred.type).toEqual(['VerifiableCredential', AUTHORITY_STATE_TYPE]);
    expect(cred.credentialSubject.authorityEpoch).toBe(7);
    expect(cred.credentialSubject.status).toBe('active');
    // subjectDid defaults to issuerDid.
    expect(cred.credentialSubject.id).toBe('did:web:treasury.example.com');
  });

  it('rejects a bad status', () => {
    expect(() =>
      buildAuthorityState({
        issuerDid: 'did:web:treasury.example.com',
        credentialId: 'urn:uuid:00000000-0000-4000-8000-000000000000',
        authorityEpoch: 1,
        status: 'bogus',
        validFrom: '2026-07-26T10:00:00Z',
        validUntil: '2026-07-26T10:05:00Z',
      })
    ).toThrow();
  });

  it('sensitive tier rejects a stale epoch', () => {
    const v = evaluateAuthorityFreshness(CONSEQUENCE_SENSITIVE, 5, 7, null, null);
    expect(v.allow).toBe(false);
    expect(v.reason).toBe('authority_epoch_stale:seen=7,voucher=5');
  });

  it('sensitive tier allows a current epoch', () => {
    const v = evaluateAuthorityFreshness(CONSEQUENCE_SENSITIVE, 9, 9, null, null);
    expect(v.allow).toBe(true);
  });

  it('critical tier needs a live co-sign', () => {
    const denied = evaluateAuthorityFreshness(
      CONSEQUENCE_CRITICAL,
      9,
      9,
      null,
      null
    );
    expect(denied.allow).toBe(false);
    expect(denied.reason).toBe('live_cosign_required:tier=critical');

    const allowed = evaluateAuthorityFreshness(
      CONSEQUENCE_CRITICAL,
      9,
      9,
      null,
      true
    );
    expect(allowed.allow).toBe(true);
  });

  it('coerces an unknown tier to critical', () => {
    const v = evaluateAuthorityFreshness('made-up', 9, 9, null, null);
    expect(v.tier).toBe('critical');
    expect(v.allow).toBe(false);
  });
});
