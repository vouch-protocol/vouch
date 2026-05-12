/**
 * Tests for the BitstringStatusList implementation (Specification §11.2).
 *
 * Mirrors `tests/test_status_list.py` and `go-sidecar/signer/status_list_test.go`.
 * Cross-language interop is verified against the canonical vector at
 * `test-vectors/bitstring-status-list/vector.json`.
 */

import * as fs from 'fs';
import * as path from 'path';

import { describe, expect, it } from 'vitest';

import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_ENTRY_TYPE,
  BITSTRING_STATUS_LIST_SUBJECT_TYPE,
  DEFAULT_BITSTRING_LENGTH,
  MULTIBASE_BASE64URL_PREFIX,
  STATUS_PURPOSE_REVOCATION,
  STATUS_PURPOSE_SUSPENSION,
  StatusList,
  StatusListError,
  buildStatusListCredential,
  buildStatusListEntry,
  buildVouchCredential,
  verifyStatus,
} from '../src';

const STATUS_URL = 'https://issuer.example/status/1';
const ISSUER_DID = 'did:web:issuer.example';

const VECTOR_PATH = path.resolve(
  __dirname,
  '../../../test-vectors/bitstring-status-list/vector.json'
);

interface CanonicalVector {
  status_list_id: string;
  issuer_did: string;
  bitstring_length_bits: number;
  status_purpose: string;
  revoked_indices: number[];
  active_indices_sample: number[];
  expected_encoded_list: string;
  status_list_credential: Record<string, unknown>;
  sample_credential_status_revoked: Record<string, unknown>;
  sample_credential_status_active: Record<string, unknown>;
}

function loadVector(): CanonicalVector {
  return JSON.parse(fs.readFileSync(VECTOR_PATH, 'utf8')) as CanonicalVector;
}

// ---------------------------------------------------------------------------
// Construction & validation
// ---------------------------------------------------------------------------

describe('StatusList construction', () => {
  it('uses default length and purpose', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    expect(sl.length).toBe(DEFAULT_BITSTRING_LENGTH);
    expect(sl.statusPurpose).toBe(STATUS_PURPOSE_REVOCATION);
  });

  it('rejects bitstring shorter than protocol minimum', () => {
    expect(() => new StatusList({ statusListId: STATUS_URL, length: 1024 })).toThrow(
      StatusListError
    );
  });

  it('rejects non-multiple-of-8 length', () => {
    expect(
      () =>
        new StatusList({
          statusListId: STATUS_URL,
          length: DEFAULT_BITSTRING_LENGTH + 1,
        })
    ).toThrow(StatusListError);
  });

  it('rejects invalid status purpose', () => {
    expect(
      () =>
        new StatusList({
          statusListId: STATUS_URL,
          // @ts-expect-error: intentional bad value
          statusPurpose: 'bogus',
        })
    ).toThrow(StatusListError);
  });

  it('rejects empty id', () => {
    expect(() => new StatusList({ statusListId: '' })).toThrow(StatusListError);
  });

  it('default state has all bits clear', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    for (const idx of [0, 1, 7, 8, 100, 65535, DEFAULT_BITSTRING_LENGTH - 1]) {
      expect(sl.getStatus(idx)).toBe(false);
    }
  });
});

describe('Bit operations', () => {
  it('sets and gets a bit', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    sl.setStatus(42, true);
    expect(sl.getStatus(42)).toBe(true);
    expect(sl.getStatus(41)).toBe(false);
    expect(sl.getStatus(43)).toBe(false);
  });

  it('clears a bit after setting', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    sl.setStatus(42, true);
    sl.setStatus(42, false);
    expect(sl.getStatus(42)).toBe(false);
  });

  it('handles first and last bit', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    sl.revoke(0);
    sl.revoke(DEFAULT_BITSTRING_LENGTH - 1);
    expect(sl.isSet(0)).toBe(true);
    expect(sl.isSet(DEFAULT_BITSTRING_LENGTH - 1)).toBe(true);
    expect(sl.isSet(1)).toBe(false);
  });

  it('throws on out-of-range index', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    expect(() => sl.setStatus(-1)).toThrow(StatusListError);
    expect(() => sl.setStatus(DEFAULT_BITSTRING_LENGTH)).toThrow(StatusListError);
  });

  it('revoke / reinstate helpers work for suspension purpose', () => {
    const sl = new StatusList({
      statusListId: STATUS_URL,
      statusPurpose: STATUS_PURPOSE_SUSPENSION,
    });
    sl.revoke(7);
    expect(sl.isSet(7)).toBe(true);
    sl.reinstate(7);
    expect(sl.isSet(7)).toBe(false);
  });
});

describe('Allocation', () => {
  it('returns sequential indices', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    expect(sl.allocateIndex()).toBe(0);
    expect(sl.allocateIndex()).toBe(1);
    expect(sl.allocateIndex()).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

describe('Encoding', () => {
  it('uses multibase base64url prefix', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    expect(sl.encode().startsWith(MULTIBASE_BASE64URL_PREFIX)).toBe(true);
  });

  it('round-trip preserves all bits', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    const indices = [0, 1, 7, 8, 9, 16, 1023, 65535, DEFAULT_BITSTRING_LENGTH - 1];
    for (const idx of indices) {
      sl.revoke(idx);
    }
    const encoded = sl.encode();
    const decoded = StatusList.decode(encoded, STATUS_URL);
    for (const idx of indices) {
      expect(decoded.getStatus(idx)).toBe(true);
    }
    expect(decoded.getStatus(2)).toBe(false);
    expect(decoded.getStatus(50)).toBe(false);
  });

  it('rejects wrong multibase prefix', () => {
    expect(() => StatusList.decode('zSomethingBase58', STATUS_URL)).toThrow(StatusListError);
  });

  it('rejects corrupt payload', () => {
    expect(() =>
      StatusList.decode(`${MULTIBASE_BASE64URL_PREFIX}$$$invalid$$$`, STATUS_URL)
    ).toThrow(StatusListError);
  });
});

// ---------------------------------------------------------------------------
// Credential and entry builders
// ---------------------------------------------------------------------------

describe('buildStatusListCredential', () => {
  it('produces a standards-shaped credential', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    sl.revoke(7);
    const vc = buildStatusListCredential({
      issuerDid: ISSUER_DID,
      statusList: sl,
    });

    expect(vc['@context']).toEqual(['https://www.w3.org/ns/credentials/v2']);
    expect(vc.id).toBe(STATUS_URL);
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE);
    expect(vc.issuer).toBe(ISSUER_DID);
    expect(vc.credentialSubject.id).toBe(`${STATUS_URL}#list`);
    expect(vc.credentialSubject.type).toBe(BITSTRING_STATUS_LIST_SUBJECT_TYPE);
    expect(vc.credentialSubject.statusPurpose).toBe(STATUS_PURPOSE_REVOCATION);
    expect(vc.credentialSubject.encodedList.startsWith(MULTIBASE_BASE64URL_PREFIX)).toBe(true);
  });
});

describe('buildStatusListEntry', () => {
  it('produces the standards-shaped entry', () => {
    const entry = buildStatusListEntry({
      statusListCredential: STATUS_URL,
      statusListIndex: 42,
    });
    expect(entry).toEqual({
      id: `${STATUS_URL}#42`,
      type: BITSTRING_STATUS_LIST_ENTRY_TYPE,
      statusPurpose: STATUS_PURPOSE_REVOCATION,
      statusListIndex: '42',
      statusListCredential: STATUS_URL,
    });
  });

  it('rejects negative index', () => {
    expect(() =>
      buildStatusListEntry({
        statusListCredential: STATUS_URL,
        statusListIndex: -1,
      })
    ).toThrow(StatusListError);
  });
});

// ---------------------------------------------------------------------------
// verifyStatus
// ---------------------------------------------------------------------------

describe('verifyStatus', () => {
  function buildPair(revoked: number[] = []) {
    const sl = new StatusList({ statusListId: STATUS_URL });
    for (const idx of revoked) {
      sl.revoke(idx);
    }
    return {
      sl,
      vc: buildStatusListCredential({ issuerDid: ISSUER_DID, statusList: sl }),
    };
  }

  it('returns false when bit is unset', () => {
    const { vc } = buildPair();
    const entry = buildStatusListEntry({
      statusListCredential: STATUS_URL,
      statusListIndex: 10,
    });
    expect(verifyStatus({ credentialStatus: entry, statusListCredential: vc })).toBe(false);
  });

  it('returns true when bit is set', () => {
    const { vc } = buildPair([10]);
    const entry = buildStatusListEntry({
      statusListCredential: STATUS_URL,
      statusListIndex: 10,
    });
    expect(verifyStatus({ credentialStatus: entry, statusListCredential: vc })).toBe(true);
  });

  it('throws on id mismatch', () => {
    const { vc } = buildPair();
    const entry = buildStatusListEntry({
      statusListCredential: 'https://other.example/status/9',
      statusListIndex: 0,
    });
    expect(() => verifyStatus({ credentialStatus: entry, statusListCredential: vc })).toThrow(
      StatusListError
    );
  });

  it('throws on purpose mismatch', () => {
    const sl = new StatusList({
      statusListId: STATUS_URL,
      statusPurpose: STATUS_PURPOSE_SUSPENSION,
    });
    const vc = buildStatusListCredential({ issuerDid: ISSUER_DID, statusList: sl });
    const entry = buildStatusListEntry({
      statusListCredential: STATUS_URL,
      statusListIndex: 0,
      statusPurpose: STATUS_PURPOSE_REVOCATION,
    });
    expect(() => verifyStatus({ credentialStatus: entry, statusListCredential: vc })).toThrow(
      StatusListError
    );
  });
});

// ---------------------------------------------------------------------------
// buildVouchCredential integration
// ---------------------------------------------------------------------------

describe('buildVouchCredential integration', () => {
  it('embeds credentialStatus when provided', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    const idx = sl.allocateIndex();
    const entry = buildStatusListEntry({
      statusListCredential: STATUS_URL,
      statusListIndex: idx,
    });

    const vc = buildVouchCredential({
      issuerDid: 'did:web:agent.example.com',
      intent: {
        action: 'POST',
        target: 'https://api.example.com/orders',
        resource: 'order:42',
      },
      credentialStatus: entry as unknown as Record<string, unknown>,
    });

    expect(vc.credentialStatus).toEqual(entry);
  });

  it('omits credentialStatus when not provided', () => {
    const vc = buildVouchCredential({
      issuerDid: 'did:web:agent.example.com',
      intent: {
        action: 'POST',
        target: 'https://api.example.com/orders',
        resource: 'order:42',
      },
    });
    expect(vc.credentialStatus).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Cross-language interop against the canonical test vector
// ---------------------------------------------------------------------------

describe('State dict persistence', () => {
  it('round-trips bits and cursor', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    const a = sl.allocateIndex();
    const b = sl.allocateIndex();
    const c = sl.allocateIndex();
    sl.revoke(b);

    const state = sl.toStateDict();
    const restored = StatusList.fromStateDict(state);

    expect(restored.statusListId).toBe(STATUS_URL);
    expect(restored.length).toBe(sl.length);
    expect(restored.getStatus(a)).toBe(false);
    expect(restored.getStatus(b)).toBe(true);
    expect(restored.getStatus(c)).toBe(false);
    expect(restored.allocateIndex()).toBe(c + 1);
  });

  it('state dict is JSON serializable', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    sl.revoke(100);
    const state = sl.toStateDict();
    const json = JSON.stringify(state);
    expect(JSON.parse(json)).toEqual(state);
  });

  it('rejects state dict missing required keys', () => {
    expect(() =>
      // @ts-expect-error: intentionally incomplete
      StatusList.fromStateDict({ statusListId: STATUS_URL })
    ).toThrow(StatusListError);
  });

  it('rejects out-of-range nextIndex', () => {
    const sl = new StatusList({ statusListId: STATUS_URL });
    const state = sl.toStateDict();
    state.nextIndex = -1;
    expect(() => StatusList.fromStateDict(state)).toThrow(StatusListError);
  });
});

describe('Cross-language interop', () => {
  it('encodes the canonical revoked-indices set to byte-identical output', () => {
    const v = loadVector();
    const sl = new StatusList({ statusListId: v.status_list_id });
    for (const idx of v.revoked_indices) {
      sl.revoke(idx);
    }
    expect(sl.encode()).toBe(v.expected_encoded_list);
  });

  it('decodes the canonical encodedList and reports correct bits', () => {
    const v = loadVector();
    const sl = StatusList.decode(
      v.expected_encoded_list,
      v.status_list_id,
      v.status_purpose as 'revocation'
    );
    for (const idx of v.revoked_indices) {
      expect(sl.getStatus(idx)).toBe(true);
    }
    for (const idx of v.active_indices_sample) {
      expect(sl.getStatus(idx)).toBe(false);
    }
  });

  it('verifyStatus matches the canonical credentials', () => {
    const v = loadVector();
    const revokedResult = verifyStatus({
      credentialStatus: v.sample_credential_status_revoked,
      statusListCredential: v.status_list_credential,
    });
    const activeResult = verifyStatus({
      credentialStatus: v.sample_credential_status_active,
      statusListCredential: v.status_list_credential,
    });
    expect(revokedResult).toBe(true);
    expect(activeResult).toBe(false);
  });
});
