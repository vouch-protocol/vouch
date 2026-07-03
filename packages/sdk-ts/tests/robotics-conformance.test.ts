/**
 * Robot regulatory conformance tests (TypeScript). Mirrors the Python
 * conformance.py module: declarative profiles, a deterministic checker, the
 * report digest, and a signed point-in-time attestation over the full report.
 *
 * The cross-language interop cases pin the report and its digest computed from a
 * fixed credential set against a named profile, so the TypeScript checker
 * reproduces the Python bytes exactly.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  generateIdentity,
  checkConformance,
  reportDigest,
  buildConformanceAttestation,
  verifyConformanceAttestation,
  CONFORMANCE_ATTESTATION_TYPE,
  type ConformanceReport,
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
  return { signer, pub };
}

const ROBOT = 'did:web:robot.example.com';

describe('conformance checker (cross-language interop)', () => {
  it('reproduces the pinned report from the fixed credential set', () => {
    const report = checkConformance(
      VECTOR.conformance_credentials,
      VECTOR.conformance_profile_id
    );
    expect(report).toEqual(VECTOR.expected_conformance_report);
  });

  it('reproduces the pinned report digest', () => {
    const report = checkConformance(
      VECTOR.conformance_credentials,
      VECTOR.conformance_profile_id
    );
    expect(reportDigest(report)).toBe(VECTOR.expected_conformance_report_digest);
  });
});

describe('conformance checker (structure)', () => {
  it('marks a requirement unsatisfied when a required field is missing', () => {
    // Drop the logHead field from the safety-record credential. The EU AI Act
    // record-keeping requirement (eu-aia-record-keeping) depends on it, so that
    // requirement must fail and the report must no longer conform.
    const creds = JSON.parse(JSON.stringify(VECTOR.conformance_credentials));
    const safety = creds.find((c: Record<string, unknown>) =>
      (c.type as string[]).includes('RobotSafetyRecordCredential')
    );
    delete (safety.credentialSubject as Record<string, unknown>).logHead;

    const report = checkConformance(creds, VECTOR.conformance_profile_id);
    expect(report.conforms).toBe(false);
    expect(report.satisfiedCount).toBe(3);
    expect(report.totalCount).toBe(4);
    const recordKeeping = report.requirements.find(
      (r) => r.id === 'eu-aia-record-keeping'
    );
    expect(recordKeeping?.satisfied).toBe(false);
  });

  it('treats an empty array or object as unsatisfied', () => {
    const report = checkConformance(
      [
        {
          type: ['VerifiableCredential', 'PhysicalCapabilityScope'],
          credentialSubject: {
            id: ROBOT,
            physicalScope: { allowedZones: [] },
          },
        },
      ],
      'iso-ts-15066'
    );
    const workspace = report.requirements.find(
      (r) => r.id === 'iso15066-collaborative-workspace'
    );
    expect(workspace?.satisfied).toBe(false);
  });

  it('throws on an unknown profile id', () => {
    expect(() => checkConformance([], 'no-such-profile')).toThrow();
  });
});

describe('conformance attestation round-trip', () => {
  it('builds and verifies an attestation binding the report by digest', async () => {
    const authority = await newSigner('did:web:authority.example.com');
    const report = checkConformance(
      VECTOR.conformance_credentials,
      VECTOR.conformance_profile_id
    );
    const cred = await buildConformanceAttestation(authority.signer, {
      robotDid: ROBOT,
      report,
    });
    expect(cred.type as string[]).toContain(CONFORMANCE_ATTESTATION_TYPE);
    const subject = cred.credentialSubject as Record<string, unknown>;
    expect(subject.id).toBe(ROBOT);
    expect(subject.profileId).toBe('eu-ai-act-high-risk');
    expect(subject.conforms).toBe(true);
    expect(subject.reportDigest).toBe(VECTOR.expected_conformance_report_digest);

    const res = verifyConformanceAttestation(cred, authority.pub);
    expect(res.ok).toBe(true);
    expect(res.subject?.satisfiedCount).toBe(4);
  });

  it('sets validUntil when validSeconds is given', async () => {
    const authority = await newSigner('did:web:authority.example.com');
    const report = checkConformance(
      VECTOR.conformance_credentials,
      VECTOR.conformance_profile_id
    );
    const cred = await buildConformanceAttestation(authority.signer, {
      robotDid: ROBOT,
      report,
      validSeconds: 3600,
    });
    expect(typeof cred.validUntil).toBe('string');
  });

  it('rejects verification under the wrong key', async () => {
    const authority = await newSigner('did:web:authority.example.com');
    const other = await newSigner('did:web:other.example.com');
    const report = checkConformance(
      VECTOR.conformance_credentials,
      VECTOR.conformance_profile_id
    );
    const cred = await buildConformanceAttestation(authority.signer, {
      robotDid: ROBOT,
      report,
    });
    const res = verifyConformanceAttestation(cred, other.pub);
    expect(res.ok).toBe(false);
  });

  it('rejects an attestation whose embedded report was tampered with', async () => {
    const authority = await newSigner('did:web:authority.example.com');
    const report = checkConformance(
      VECTOR.conformance_credentials,
      VECTOR.conformance_profile_id
    );
    const cred = await buildConformanceAttestation(authority.signer, {
      robotDid: ROBOT,
      report,
    });
    // Flip the embedded report's conforms flag after signing. The digest no
    // longer matches the embedded report, so verification must fail.
    const subject = cred.credentialSubject as Record<string, unknown>;
    const embedded = subject.report as ConformanceReport;
    embedded.conforms = false;
    const res = verifyConformanceAttestation(cred, authority.pub);
    expect(res.ok).toBe(false);
  });
});
