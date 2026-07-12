/**
 * Bystander-consent evidence tests (TypeScript). Mirrors the Python consent.py
 * module: a bystander signs a consent token bound to one capture and one robot,
 * and the robot signs evidence recording the basis on which a capture was
 * permitted, committing to those tokens by their proof value.
 *
 * The cross-language interop case reproduces the capture hash pinned in the
 * shared interop vector and verifies the Python-signed consent token and
 * evidence under their keys: the TypeScript module reproduces byte for byte what
 * the Python module produced.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  CONSENT_BASES,
  CONSENT_EVIDENCE_TYPE,
  CONSENT_TOKEN_TYPE,
  hashCapture,
  buildConsentToken,
  verifyConsentToken,
  buildConsentEvidence,
  verifyConsentEvidence,
  RoboticsError,
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

async function newParty(domain: string) {
  const keys = await generateIdentity(domain);
  const did = `did:web:${domain}`;
  const signer = new Signer({ privateKey: keys.privateKeyJwk, did });
  const pub = publicKeyFromJwk(JSON.parse(keys.publicKeyJwk));
  return { signer, pub, did };
}

const T0 = new Date('2026-01-01T00:00:00Z');
const IN_WINDOW = new Date('2026-01-01T00:05:00Z');
const AFTER = new Date('2026-01-01T02:00:00Z');

describe('bystander consent (cross-language interop)', () => {
  it('reproduces the pinned capture hash', () => {
    const hash = hashCapture(Buffer.from('bystander-frame-0'));
    expect(hash).toBe(VECTOR.expected_consent_capture_hash);
  });

  it('verifies the Python-signed consent token under the bystander key', () => {
    const bystanderKey = publicKeyFromJwk(VECTOR.consent_bystander_key);
    const evidence = VECTOR.consent_evidence_credential;
    const robotDid = evidence.credentialSubject.id;
    const res = verifyConsentToken(VECTOR.consent_token_credential, bystanderKey, {
      captureHash: VECTOR.expected_consent_capture_hash,
      robotDid,
    });
    expect(res.ok).toBe(true);
  });

  it('verifies the Python-signed consent evidence under the robot key', () => {
    const robotKey = publicKeyFromJwk(VECTOR.robot_public_key_jwk);
    const bystanderKey = publicKeyFromJwk(VECTOR.consent_bystander_key);
    const token = VECTOR.consent_token_credential;
    const res = verifyConsentEvidence(VECTOR.consent_evidence_credential, robotKey, {
      consentTokens: [token],
      bystanderKeys: { [token.issuer]: bystanderKey },
    });
    expect(res.ok).toBe(true);
    expect(res.subject?.basis).toBe('explicit-consent');
  });
});

describe('consent token round-trip', () => {
  it('exposes the interoperable consent bases', () => {
    expect(CONSENT_BASES.has('explicit-consent')).toBe(true);
    expect(CONSENT_BASES.has('posted-notice')).toBe(true);
    expect(CONSENT_BASES.has('legitimate-interest')).toBe(true);
    expect(CONSENT_BASES.has('redacted')).toBe(true);
  });

  async function token(
    bystander: { signer: Signer; did: string },
    robotDid: string,
    captureHash: string
  ) {
    return buildConsentToken(bystander.signer, {
      bystanderDid: bystander.did,
      captureHash,
      robotDid,
      validSeconds: 3600,
      grantedAt: T0,
    });
  }

  it('verifies for its capture', async () => {
    const bystander = await newParty('person-1.example.com');
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    const tok = await token(bystander, robot.did, captureHash);
    expect(tok.type as string[]).toContain(CONSENT_TOKEN_TYPE);
    const res = verifyConsentToken(tok, bystander.pub, {
      captureHash,
      robotDid: robot.did,
      now: IN_WINDOW,
    });
    expect(res.ok).toBe(true);
    expect(res.subject?.robotDid).toBe(robot.did);
  });

  it('is rejected for another capture', async () => {
    const bystander = await newParty('person-1.example.com');
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    const tok = await token(bystander, robot.did, captureHash);
    const res = verifyConsentToken(tok, bystander.pub, {
      captureHash: hashCapture(Buffer.from('different-frame')),
      robotDid: robot.did,
      now: IN_WINDOW,
    });
    expect(res.ok).toBe(false);
  });

  it('is rejected for another robot', async () => {
    const bystander = await newParty('person-1.example.com');
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    const tok = await token(bystander, robot.did, captureHash);
    const res = verifyConsentToken(tok, bystander.pub, {
      captureHash,
      robotDid: 'did:web:robot-z.example.com',
      now: IN_WINDOW,
    });
    expect(res.ok).toBe(false);
  });

  it('is rejected out of window', async () => {
    const bystander = await newParty('person-1.example.com');
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    const tok = await token(bystander, robot.did, captureHash);
    const res = verifyConsentToken(tok, bystander.pub, {
      captureHash,
      robotDid: robot.did,
      now: AFTER,
    });
    expect(res.ok).toBe(false);
  });
});

describe('consent evidence round-trip', () => {
  it('verifies explicit-consent evidence with its token', async () => {
    const bystander = await newParty('person-1.example.com');
    const robot = await newParty('robot-a.example.com');
    const capture = Buffer.from('frame-0');
    const captureHash = hashCapture(capture);
    const tok = await buildConsentToken(bystander.signer, {
      bystanderDid: bystander.did,
      captureHash,
      robotDid: robot.did,
      validSeconds: 3600,
      grantedAt: T0,
    });
    const ev = await buildConsentEvidence(robot.signer, {
      robotDid: robot.did,
      captureHash,
      basis: 'explicit-consent',
      consentTokens: [tok],
      validFrom: T0,
    });
    expect(ev.type as string[]).toContain(CONSENT_EVIDENCE_TYPE);
    const res = verifyConsentEvidence(ev, robot.pub, {
      capture,
      consentTokens: [tok],
      bystanderKeys: { [bystander.did]: bystander.pub },
      now: IN_WINDOW,
    });
    expect(res.ok).toBe(true);
    expect(res.subject?.basis).toBe('explicit-consent');
  });

  it('rejects explicit-consent without a token at build time', async () => {
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    await expect(
      buildConsentEvidence(robot.signer, {
        robotDid: robot.did,
        captureHash,
        basis: 'explicit-consent',
        validFrom: T0,
      })
    ).rejects.toThrow(RoboticsError);
  });

  it('accepts a redacted basis with no token', async () => {
    const robot = await newParty('robot-a.example.com');
    const capture = Buffer.from('frame-0');
    const captureHash = hashCapture(capture);
    const ev = await buildConsentEvidence(robot.signer, {
      robotDid: robot.did,
      captureHash,
      basis: 'redacted',
      redactionHash: hashCapture(Buffer.from('blurred-frame')),
      validFrom: T0,
    });
    const res = verifyConsentEvidence(ev, robot.pub, { capture });
    expect(res.ok).toBe(true);
    expect(res.subject?.basis).toBe('redacted');
  });

  it('rejects a wrong capture', async () => {
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    const ev = await buildConsentEvidence(robot.signer, {
      robotDid: robot.did,
      captureHash,
      basis: 'posted-notice',
      validFrom: T0,
    });
    const res = verifyConsentEvidence(ev, robot.pub, {
      capture: Buffer.from('a-different-capture'),
    });
    expect(res.ok).toBe(false);
  });

  it('rejects an unknown basis at build time', async () => {
    const robot = await newParty('robot-a.example.com');
    const captureHash = hashCapture(Buffer.from('frame-0'));
    await expect(
      buildConsentEvidence(robot.signer, {
        robotDid: robot.did,
        captureHash,
        basis: 'whatever',
        validFrom: T0,
      })
    ).rejects.toThrow(RoboticsError);
  });

  it('rejects a token bound to another capture', async () => {
    const bystander = await newParty('person-1.example.com');
    const robot = await newParty('robot-a.example.com');
    const capture = Buffer.from('frame-0');
    const captureHash = hashCapture(capture);
    const stray = await buildConsentToken(bystander.signer, {
      bystanderDid: bystander.did,
      captureHash: hashCapture(Buffer.from('other-capture')),
      robotDid: robot.did,
      validSeconds: 3600,
      grantedAt: T0,
    });
    const ev = await buildConsentEvidence(robot.signer, {
      robotDid: robot.did,
      captureHash,
      basis: 'explicit-consent',
      consentTokens: [stray],
      validFrom: T0,
    });
    const res = verifyConsentEvidence(ev, robot.pub, {
      capture,
      consentTokens: [stray],
      bystanderKeys: { [bystander.did]: bystander.pub },
      now: IN_WINDOW,
    });
    expect(res.ok).toBe(false);
  });
});
