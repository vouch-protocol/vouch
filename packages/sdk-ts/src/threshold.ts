/**
 * FROST(Ed25519, SHA-512) threshold signing (RFC 9591).
 *
 * A key is split among `maxSigners` participants so that any `minSigners` of
 * them can produce a signature together, WITHOUT the full private key ever
 * being reconstructed at any point, not even during signing. This is distinct
 * from `./recovery` (Shamir secret sharing), where the secret IS reconstructed
 * at recovery time; FROST is for live, repeated signing across a threshold of
 * custodians, and the key never exists whole anywhere.
 *
 * The critical property that makes this a drop-in fit for Vouch: the
 * aggregated signature is a STANDARD Ed25519 signature, so it verifies with
 * the existing credential verifier and needs no new proof type. Combine it
 * with `Signer.fromBackend` to get a Signer whose sign callback runs a
 * threshold-signing ceremony instead of holding a raw key:
 *
 * ```ts
 * const generated = await generateKey(2, 3);
 * const thresholdSigner = await ThresholdSigner.create(
 *   generated.shares.slice(0, 2), generated.groupPublicKey);
 * const signer = Signer.fromBackend(
 *   'did:web:agent.example',
 *   groupPublicKeyMultikey(generated.groupPublicKey),
 *   thresholdSigner.sign,
 * );
 * const credential = await signer.sign('read', 't', 'https://x/y');
 * ```
 *
 * The cryptography is not implemented here: this module is a thin binding
 * over the same audited Rust core (`frost-ed25519`, the Zcash Foundation
 * crate, RFC 9591) that backs the Python, Go, JVM, .NET, C++, and Swift SDKs,
 * compiled to WebAssembly, so every language produces byte-identical results
 * from one implementation.
 *
 * `@vouch-protocol-official/core-wasm` is an OPTIONAL peer dependency,
 * loaded lazily on first use, matching how `@noble/post-quantum` is handled
 * for the hybrid post-quantum profile. Importing this SDK never requires it
 * to be installed; only calling into this module does.
 *
 * There is deliberately no "reconstruct" function here. Nothing in this
 * module takes key shares and returns a seed or a private scalar.
 */

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

import { encodeEd25519Public } from './multikey';

export class ThresholdError extends Error {}

/** One participant's share of a threshold key. Secret; keep it only on the participant it was issued to. */
export interface KeyShare {
  identifier: string; // base64
  keyPackage: string; // base64, SECRET
}

/** The threshold group's public identity. */
export interface GroupPublicKey {
  verifyingKey: string; // base64, 32 bytes: a standard Ed25519 public key
  publicKeyPackage: string; // base64, needed to aggregate
}

export interface GenerateKeyResult {
  shares: KeyShare[];
  groupPublicKey: GroupPublicKey;
}

/** Round 1 output for one signer: secret nonces and a public commitment. */
export interface Round1 {
  nonces: string; // base64, SECRET, single-use
  commitments: string; // base64, public
}

/** The group public key as a Multikey (z-prefixed) string, for `Signer.fromBackend` or any other Vouch API that takes a public key. */
export function groupPublicKeyMultikey(groupPublicKey: GroupPublicKey): string {
  const raw = Buffer.from(groupPublicKey.verifyingKey, 'base64');
  return encodeEd25519Public(new Uint8Array(raw));
}

interface CoreWasmModule {
  thresholdGenerateKey(minSigners: number, maxSigners: number): string;
  thresholdCommit(keyShareJson: string): string;
  thresholdSignShare(messageB64: string, keyShareJson: string, noncesB64: string, commitmentsJson: string): string;
  thresholdAggregate(
    messageB64: string, commitmentsJson: string, sharesJson: string, groupPublicKeyJson: string
  ): string;
}

let _core: CoreWasmModule | undefined;
let _loading: Promise<CoreWasmModule> | undefined;

/**
 * Lazily resolve and initialize the optional `@vouch-protocol-official/core-wasm`
 * peer dependency. WASM instantiation is asynchronous, so this is the only
 * async step; every function below only needs it once. Throws a clear,
 * actionable error if the optional dependency is not installed.
 */
async function ensureCoreWasm(): Promise<CoreWasmModule> {
  if (_core) return _core;
  if (_loading) return _loading;
  _loading = (async () => {
    let mod: any;
    try {
      const req = createRequire(import.meta.url);
      const wasmPath = req.resolve('@vouch-protocol-official/core-wasm/vouch_core_wasm_bg.wasm');
      mod = await import('@vouch-protocol-official/core-wasm');
      await mod.default({ module_or_path: readFileSync(wasmPath) });
    } catch (err) {
      throw new ThresholdError(
        'FROST threshold signing requires the optional peer dependency ' +
        '"@vouch-protocol-official/core-wasm". Install it with ' +
        '`npm install @vouch-protocol-official/core-wasm` to use threshold signing. ' +
        'Original error: ' + (err instanceof Error ? err.message : String(err))
      );
    }
    _core = mod as CoreWasmModule;
    return _core;
  })();
  return _loading;
}

/** Synchronous access to the already-loaded core, for use inside {@link ThresholdSigner.sign}. */
function coreWasmSync(): CoreWasmModule {
  if (!_core) {
    throw new ThresholdError(
      'core-wasm has not finished loading; await generateKey(), commit(), or ' +
      'ThresholdSigner.create() at least once before calling sign() synchronously.'
    );
  }
  return _core;
}

function keyShareToJson(share: KeyShare): string {
  return JSON.stringify({ identifier: share.identifier, key_package: share.keyPackage });
}

function keyShareFromJson(v: any): KeyShare {
  return { identifier: v.identifier, keyPackage: v.key_package };
}

function groupPublicKeyToJson(gpk: GroupPublicKey): string {
  return JSON.stringify({ verifying_key: gpk.verifyingKey, public_key_package: gpk.publicKeyPackage });
}

function groupPublicKeyFromJson(v: any): GroupPublicKey {
  return { verifyingKey: v.verifying_key, publicKeyPackage: v.public_key_package };
}

function runGenerateKey(core: CoreWasmModule, minSigners: number, maxSigners: number): GenerateKeyResult {
  const data = JSON.parse(core.thresholdGenerateKey(minSigners, maxSigners));
  return {
    shares: data.shares.map(keyShareFromJson),
    groupPublicKey: groupPublicKeyFromJson(data.group_public_key),
  };
}

function runCommit(core: CoreWasmModule, keyShare: KeyShare): Round1 {
  const data = JSON.parse(core.thresholdCommit(keyShareToJson(keyShare)));
  return { nonces: data.nonces, commitments: data.commitments };
}

function runSignShare(
  core: CoreWasmModule,
  message: Uint8Array,
  keyShare: KeyShare,
  nonces: string,
  commitmentsByParticipant: Record<string, string>
): string {
  return core.thresholdSignShare(
    Buffer.from(message).toString('base64'),
    keyShareToJson(keyShare),
    nonces,
    JSON.stringify(commitmentsByParticipant)
  );
}

function runAggregate(
  core: CoreWasmModule,
  message: Uint8Array,
  commitmentsByParticipant: Record<string, string>,
  sharesByParticipant: Record<string, string>,
  groupPublicKey: GroupPublicKey
): Uint8Array {
  const sigB64 = core.thresholdAggregate(
    Buffer.from(message).toString('base64'),
    JSON.stringify(commitmentsByParticipant),
    JSON.stringify(sharesByParticipant),
    groupPublicKeyToJson(groupPublicKey)
  );
  return new Uint8Array(Buffer.from(sigB64, 'base64'));
}

/**
 * Mint a fresh threshold-native Ed25519 identity: `maxSigners` key shares,
 * any `minSigners` of which can sign together, and the group's public key.
 * This mints a NEW identity; it does not convert an existing single-key
 * Ed25519 identity (see this module's docstring for why).
 */
export async function generateKey(minSigners: number, maxSigners: number): Promise<GenerateKeyResult> {
  const core = await ensureCoreWasm();
  return runGenerateKey(core, minSigners, maxSigners);
}

/**
 * Round 1: a signer generates its single-use nonces and public commitment.
 * `nonces` MUST be used for exactly one {@link signShare} call and then
 * discarded; reusing them leaks the signer's key share.
 */
export async function commit(keyShare: KeyShare): Promise<Round1> {
  const core = await ensureCoreWasm();
  return runCommit(core, keyShare);
}

/**
 * Round 2: given the message and every participating signer's commitment,
 * this signer produces its signature share using its own key share and its
 * own (single-use) nonces from {@link commit}. `commitmentsByParticipant`
 * maps each participant's base64 identifier to its base64 commitment,
 * including this signer's own.
 */
export async function signShare(
  message: Uint8Array,
  keyShare: KeyShare,
  nonces: string,
  commitmentsByParticipant: Record<string, string>
): Promise<string> {
  const core = await ensureCoreWasm();
  return runSignShare(core, message, keyShare, nonces, commitmentsByParticipant);
}

/**
 * Combine `minSigners` (or more) signature shares into the final, standard
 * Ed25519 signature. Verify the result the same way as any other Vouch
 * credential, against `groupPublicKeyMultikey(groupPublicKey)`.
 */
export async function aggregate(
  message: Uint8Array,
  commitmentsByParticipant: Record<string, string>,
  sharesByParticipant: Record<string, string>,
  groupPublicKey: GroupPublicKey
): Promise<Uint8Array> {
  const core = await ensureCoreWasm();
  return runAggregate(core, message, commitmentsByParticipant, sharesByParticipant, groupPublicKey);
}

/**
 * Convenience: run a full commit/sign/aggregate ceremony in one call.
 *
 * Holds `minSigners` (or more) key shares locally and produces a signature
 * over any message with a single {@link sign} call, running round 1, round 2,
 * and aggregation across the shares it holds. This fits a coordinator
 * process that has access to enough shares to sign (for example, a service
 * with several custodian shares mounted, or a test harness); a true
 * multi-device ceremony instead calls {@link commit} / {@link signShare} /
 * {@link aggregate} directly across devices, passing commitments and shares
 * over the network.
 *
 * Pass {@link sign} to `Signer.fromBackend` to get a Signer backed by
 * threshold signing.
 */
export class ThresholdSigner {
  private readonly shares: KeyShare[];
  private readonly groupPublicKey: GroupPublicKey;

  private constructor(shares: KeyShare[], groupPublicKey: GroupPublicKey) {
    this.shares = shares;
    this.groupPublicKey = groupPublicKey;
  }

  /** Creates a ThresholdSigner, ensuring the WASM core is loaded so {@link sign} can run synchronously. */
  static async create(shares: KeyShare[], groupPublicKey: GroupPublicKey): Promise<ThresholdSigner> {
    if (shares.length < 2) {
      throw new ThresholdError('ThresholdSigner needs at least 2 key shares');
    }
    await ensureCoreWasm();
    return new ThresholdSigner(shares, groupPublicKey);
  }

  /**
   * Signs digest via a full commit/sign-share/aggregate ceremony across the
   * held shares. Synchronous (matching `Signer.fromBackend`'s sign callback
   * shape) because {@link create} already ensured the WASM core is loaded.
   */
  sign = (digest: Uint8Array): Uint8Array => {
    const core = coreWasmSync();
    const noncesById: Record<string, string> = {};
    const commitments: Record<string, string> = {};
    for (const share of this.shares) {
      const round1 = runCommit(core, share);
      commitments[share.identifier] = round1.commitments;
      noncesById[share.identifier] = round1.nonces;
    }

    const sharesOut: Record<string, string> = {};
    for (const share of this.shares) {
      sharesOut[share.identifier] = runSignShare(core, digest, share, noncesById[share.identifier], commitments);
    }

    return runAggregate(core, digest, commitments, sharesOut, this.groupPublicKey);
  };
}
