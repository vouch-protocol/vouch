/**
 * BitstringStatusList implementation for Vouch Protocol.
 *
 * Mirrors `vouch/status_list.py`. Implements credential-level revocation
 * and suspension status per VC-BITSTRING-STATUS-LIST
 * (https://www.w3.org/TR/vc-bitstring-status-list/), referenced in
 * Specification §11.2.
 *
 * Cross-implementation interop is verified against the canonical test
 * vector at `test-vectors/bitstring-status-list/vector.json`.
 */

import * as zlib from 'zlib';

import { VC_CONTEXT_V2, VC_TYPE } from './vc';

// BitstringStatusList §4.2: minimum bitstring length is 131,072 bits (16 KiB).
export const DEFAULT_BITSTRING_LENGTH = 131_072;

// Upper bound on a decoded status list to prevent a gzip decompression bomb.
// 16 MiB is far beyond any realistic status list (~134M entries).
export const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

// BitstringStatusList §4.1
export const STATUS_PURPOSE_REVOCATION = 'revocation';
export const STATUS_PURPOSE_SUSPENSION = 'suspension';
export const STATUS_PURPOSE_MESSAGE = 'message';

export const VALID_STATUS_PURPOSES = [
  STATUS_PURPOSE_REVOCATION,
  STATUS_PURPOSE_SUSPENSION,
  STATUS_PURPOSE_MESSAGE,
] as const;

export type StatusPurpose = (typeof VALID_STATUS_PURPOSES)[number];

export const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE = 'BitstringStatusListCredential';
export const BITSTRING_STATUS_LIST_SUBJECT_TYPE = 'BitstringStatusList';
export const BITSTRING_STATUS_LIST_ENTRY_TYPE = 'BitstringStatusListEntry';

// Multibase prefix for base64url-no-pad per the multibase spec.
export const MULTIBASE_BASE64URL_PREFIX = 'u';

export class StatusListError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StatusListError';
  }
}

export interface StatusListOptions {
  statusListId: string;
  statusPurpose?: StatusPurpose;
  length?: number;
}

/**
 * In-memory bitstring for credential status tracking. Bit ordering follows
 * BitstringStatusList §4.2: bit at index `i` is stored at byte `i >> 3`,
 * with bit position `7 - (i % 8)` (most significant bit first within each byte).
 */
export class StatusList {
  readonly statusListId: string;
  readonly statusPurpose: StatusPurpose;
  readonly length: number;
  private bits: Uint8Array;
  private nextIndex: number;

  constructor(opts: StatusListOptions) {
    const purpose = opts.statusPurpose ?? STATUS_PURPOSE_REVOCATION;
    const length = opts.length ?? DEFAULT_BITSTRING_LENGTH;

    if (!opts.statusListId) {
      throw new StatusListError('statusListId is required');
    }
    if (!VALID_STATUS_PURPOSES.includes(purpose)) {
      throw new StatusListError(
        `statusPurpose must be one of ${VALID_STATUS_PURPOSES.join(', ')}, got ${purpose}`
      );
    }
    if (length < DEFAULT_BITSTRING_LENGTH) {
      throw new StatusListError(
        `bitstring length must be at least ${DEFAULT_BITSTRING_LENGTH} ` +
          `per BitstringStatusList §4.2, got ${length}`
      );
    }
    if (length % 8 !== 0) {
      throw new StatusListError(
        `bitstring length must be a multiple of 8, got ${length}`
      );
    }

    this.statusListId = opts.statusListId;
    this.statusPurpose = purpose;
    this.length = length;
    this.bits = new Uint8Array(length / 8);
    this.nextIndex = 0;
  }

  /**
   * Return the next unused index and advance the cursor.
   */
  allocateIndex(): number {
    if (this.nextIndex >= this.length) {
      throw new StatusListError(
        `status list exhausted: all ${this.length} indices allocated`
      );
    }
    const idx = this.nextIndex;
    this.nextIndex += 1;
    return idx;
  }

  setStatus(index: number, value = true): void {
    this.checkIndex(index);
    const byteIdx = index >> 3;
    const bitPos = 7 - (index % 8);
    if (value) {
      this.bits[byteIdx] |= 1 << bitPos;
    } else {
      this.bits[byteIdx] &= (~(1 << bitPos)) & 0xff;
    }
  }

  getStatus(index: number): boolean {
    this.checkIndex(index);
    const byteIdx = index >> 3;
    const bitPos = 7 - (index % 8);
    return (this.bits[byteIdx] & (1 << bitPos)) !== 0;
  }

  revoke(index: number): void {
    this.setStatus(index, true);
  }

  reinstate(index: number): void {
    this.setStatus(index, false);
  }

  isSet(index: number): boolean {
    return this.getStatus(index);
  }

  /**
   * Internal accessor used by the bytes-equality interop test. Returns a
   * defensive copy of the raw bitstring (uncompressed).
   */
  rawBytes(): Uint8Array {
    return new Uint8Array(this.bits);
  }

  /**
   * Return the multibase (base64url, no pad) string of the gzip-compressed
   * bitstring per BitstringStatusList §4.2.
   *
   * The gzip mtime and OS bytes are normalized to fixed values (mtime=0,
   * OS=255) so the encoded output is deterministic across runs and
   * platforms, matching the Python and Go reference implementations.
   */
  encode(): string {
    const compressed = zlib.gzipSync(Buffer.from(this.bits), { level: 9 });
    normalizeGzipHeader(compressed);
    const b64 = base64UrlEncodeNoPad(compressed);
    return MULTIBASE_BASE64URL_PREFIX + b64;
  }

  /**
   * Reconstruct a StatusList from its multibase encoding.
   *
   * Caller is responsible for verifying the Data Integrity proof on the
   * enclosing BitstringStatusListCredential BEFORE calling this method.
   */
  static decode(
    encoded: string,
    statusListId: string,
    statusPurpose: StatusPurpose = STATUS_PURPOSE_REVOCATION
  ): StatusList {
    if (!encoded.startsWith(MULTIBASE_BASE64URL_PREFIX)) {
      throw new StatusListError(
        `encoded list must use multibase prefix '${MULTIBASE_BASE64URL_PREFIX}' (base64url), ` +
          `got '${encoded.slice(0, 1)}'`
      );
    }

    let raw: Buffer;
    try {
      const compressed = base64UrlDecodeNoPad(encoded.slice(1));
      // Cap decompressed size to prevent a gzip bomb (node throws if exceeded).
      raw = zlib.gunzipSync(compressed, {
        maxOutputLength: MAX_STATUS_LIST_BYTES,
      });
    } catch (err) {
      throw new StatusListError(
        `failed to decode bitstring: ${(err as Error).message}`
      );
    }

    const length = raw.length * 8;
    if (length < DEFAULT_BITSTRING_LENGTH) {
      throw new StatusListError(
        `decoded bitstring length ${length} is below the protocol minimum ` +
          `(${DEFAULT_BITSTRING_LENGTH})`
      );
    }

    const lst = new StatusList({
      statusListId,
      statusPurpose,
      length,
    });
    lst.bits = new Uint8Array(raw);
    return lst;
  }

  private checkIndex(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.length) {
      throw new StatusListError(
        `index ${index} out of range [0, ${this.length})`
      );
    }
  }

  // -----------------------------------------------------------------------
  // Persistence
  // -----------------------------------------------------------------------

  /**
   * Serialize the StatusList to a state object suitable for persistence.
   *
   * The state object carries everything needed to reconstruct the list,
   * including `nextIndex` (which is NOT recoverable from the encoded
   * bitstring alone). Issuers SHOULD persist this state after every
   * revocation or allocation and reload it on startup to avoid
   * re-allocating already-used indices.
   */
  toStateDict(): StatusListStateDict {
    return {
      version: 1,
      statusListId: this.statusListId,
      statusPurpose: this.statusPurpose,
      length: this.length,
      nextIndex: this.nextIndex,
      encodedList: this.encode(),
    };
  }

  /**
   * Reconstruct a StatusList from a state object produced by `toStateDict`.
   */
  static fromStateDict(state: StatusListStateDict): StatusList {
    const required = [
      'statusListId',
      'statusPurpose',
      'length',
      'nextIndex',
      'encodedList',
    ] as const;
    for (const key of required) {
      if (!(key in state)) {
        throw new StatusListError(`state dict missing required key: ${key}`);
      }
    }

    const lst = StatusList.decode(
      state.encodedList,
      state.statusListId,
      state.statusPurpose
    );
    if (lst.length !== state.length) {
      throw new StatusListError(
        `length mismatch: state declares ${state.length}, decoded bitstring has ${lst.length}`
      );
    }
    const nextIndex = Number(state.nextIndex);
    if (!Number.isInteger(nextIndex) || nextIndex < 0 || nextIndex > lst.length) {
      throw new StatusListError(
        `nextIndex ${nextIndex} out of range [0, ${lst.length}]`
      );
    }
    lst.nextIndex = nextIndex;
    return lst;
  }
}

export interface StatusListStateDict {
  version: 1;
  statusListId: string;
  statusPurpose: StatusPurpose;
  length: number;
  nextIndex: number;
  encodedList: string;
}

export interface BuildStatusListCredentialOptions {
  issuerDid: string;
  statusList: StatusList;
  credentialId?: string;
  validSeconds?: number;
  validFrom?: Date;
}

export interface BitstringStatusListCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: {
    id: string;
    type: string;
    statusPurpose: StatusPurpose;
    encodedList: string;
  };
  proof?: unknown;
}

/**
 * Construct an unsigned BitstringStatusListCredential VC per W3C
 * BitstringStatusList §4. Caller attaches a Data Integrity proof before
 * publishing at the URL referenced by issued credentials.
 */
export function buildStatusListCredential(
  opts: BuildStatusListCredentialOptions
): BitstringStatusListCredential {
  const issuedAt = opts.validFrom ?? new Date();
  const validSeconds = opts.validSeconds ?? 30 * 24 * 60 * 60;
  const expiresAt = new Date(issuedAt.getTime() + validSeconds * 1000);
  const listId = opts.credentialId ?? opts.statusList.statusListId;

  return {
    '@context': [VC_CONTEXT_V2],
    id: listId,
    type: [VC_TYPE, BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
    issuer: opts.issuerDid,
    validFrom: iso(issuedAt),
    validUntil: iso(expiresAt),
    credentialSubject: {
      id: `${listId}#list`,
      type: BITSTRING_STATUS_LIST_SUBJECT_TYPE,
      statusPurpose: opts.statusList.statusPurpose,
      encodedList: opts.statusList.encode(),
    },
  };
}

export interface BuildStatusListEntryOptions {
  statusListCredential: string;
  statusListIndex: number;
  statusPurpose?: StatusPurpose;
  entryId?: string;
}

export interface BitstringStatusListEntry {
  id: string;
  type: string;
  statusPurpose: StatusPurpose;
  statusListIndex: string;
  statusListCredential: string;
}

/**
 * Construct a `credentialStatus` entry for a Vouch Credential, referencing
 * a specific bit index in a published BitstringStatusListCredential.
 */
export function buildStatusListEntry(
  opts: BuildStatusListEntryOptions
): BitstringStatusListEntry {
  const purpose = opts.statusPurpose ?? STATUS_PURPOSE_REVOCATION;
  if (!VALID_STATUS_PURPOSES.includes(purpose)) {
    throw new StatusListError(
      `statusPurpose must be one of ${VALID_STATUS_PURPOSES.join(', ')}, got ${purpose}`
    );
  }
  if (!Number.isInteger(opts.statusListIndex) || opts.statusListIndex < 0) {
    throw new StatusListError('statusListIndex must be a non-negative integer');
  }
  if (!opts.statusListCredential) {
    throw new StatusListError('statusListCredential URL is required');
  }

  return {
    id: opts.entryId ?? `${opts.statusListCredential}#${opts.statusListIndex}`,
    type: BITSTRING_STATUS_LIST_ENTRY_TYPE,
    statusPurpose: purpose,
    statusListIndex: String(opts.statusListIndex),
    statusListCredential: opts.statusListCredential,
  };
}

export interface VerifyStatusOptions {
  credentialStatus: BitstringStatusListEntry | Record<string, unknown>;
  statusListCredential: BitstringStatusListCredential | Record<string, unknown>;
}

/**
 * Verify a credential's status by looking up its bit in a fetched status
 * list credential.
 *
 * Returns true if the bit is set (e.g., revoked, suspended, or message-bit-on),
 * false if the bit is in its default state. The caller MUST verify the Data
 * Integrity proof on `statusListCredential` BEFORE calling this function.
 */
export function verifyStatus(opts: VerifyStatusOptions): boolean {
  const cs = opts.credentialStatus as Record<string, unknown>;
  const sl = opts.statusListCredential as Record<string, unknown>;

  if (!cs || typeof cs !== 'object') {
    throw new StatusListError('credentialStatus must be an object');
  }
  if (!sl || typeof sl !== 'object') {
    throw new StatusListError('statusListCredential must be an object');
  }

  if (cs.type !== BITSTRING_STATUS_LIST_ENTRY_TYPE) {
    throw new StatusListError(
      `credentialStatus.type must be ${BITSTRING_STATUS_LIST_ENTRY_TYPE}, got ${String(
        cs.type
      )}`
    );
  }

  const referenced = cs.statusListCredential;
  if (typeof referenced !== 'string' || !referenced) {
    throw new StatusListError('credentialStatus.statusListCredential is required');
  }

  const actualId = sl.id;
  if (actualId !== referenced) {
    throw new StatusListError(
      `status list credential id mismatch: credential references ${referenced}, ` +
        `fetched credential has id ${String(actualId)}`
    );
  }

  const typeField = (sl.type as unknown[]) ?? [];
  if (!Array.isArray(typeField) || !typeField.includes(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE)) {
    throw new StatusListError(
      `fetched credential is not a ${BITSTRING_STATUS_LIST_CREDENTIAL_TYPE}`
    );
  }

  const subject = (sl.credentialSubject as Record<string, unknown>) ?? {};
  if (subject.type !== BITSTRING_STATUS_LIST_SUBJECT_TYPE) {
    throw new StatusListError(
      `credentialSubject.type must be ${BITSTRING_STATUS_LIST_SUBJECT_TYPE}`
    );
  }

  const declaredPurpose = cs.statusPurpose;
  const actualPurpose = subject.statusPurpose;
  if (declaredPurpose !== actualPurpose) {
    throw new StatusListError(
      `statusPurpose mismatch: credential entry declares ${String(
        declaredPurpose
      )}, status list declares ${String(actualPurpose)}`
    );
  }

  const encoded = subject.encodedList;
  if (typeof encoded !== 'string' || !encoded) {
    throw new StatusListError('credentialSubject.encodedList is required');
  }

  const rawIndex = cs.statusListIndex;
  if (rawIndex === undefined || rawIndex === null) {
    throw new StatusListError('credentialStatus.statusListIndex is required');
  }
  const index = Number(rawIndex);
  if (!Number.isInteger(index) || index < 0) {
    throw new StatusListError(
      `statusListIndex must be a non-negative integer, got ${String(rawIndex)}`
    );
  }

  const statusList = StatusList.decode(
    encoded,
    actualId as string,
    actualPurpose as StatusPurpose
  );
  return statusList.getStatus(index);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Normalize the gzip header for deterministic output across platforms.
 *
 * Bytes 0-3 are magic + CM + FLG (preserved).
 * Bytes 4-7 are MTIME, forced to 0 (Node already defaults to 0; defensive).
 * Byte 8 is XFL (compression flags), preserved as Node produces it.
 * Byte 9 is OS, forced to 0xff (unknown) to match Python's `gzip.compress`
 *  and Go's `compress/gzip` defaults. Node sets this to a platform-specific
 *  value (e.g., 0x03 for Unix) which prevents byte-identical cross-platform
 *  output without normalization.
 */
function normalizeGzipHeader(buf: Buffer): void {
  if (buf.length < 10) {
    return;
  }
  buf[4] = 0;
  buf[5] = 0;
  buf[6] = 0;
  buf[7] = 0;
  buf[9] = 0xff;
}

function base64UrlEncodeNoPad(buf: Buffer): string {
  return buf.toString('base64url');
}

function base64UrlDecodeNoPad(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
