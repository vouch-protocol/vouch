/**
 * Revocation for robot credentials (TypeScript).
 *
 * Mirrors `vouch/robotics/revocation.py`. Robot identity, provenance, and
 * capability credentials need the same two-level revocation the rest of Vouch
 * already provides, applied to physical machines:
 *
 *   - Whole-DID kill (key compromise): a robot whose identity key is leaked or
 *     whose hardware is captured is revoked at the DID level through the same
 *     revocation path Vouch already uses for agents. A robot DID is an ordinary
 *     DID, so the existing distribution mechanism applies unchanged. The Python
 *     SDK re-exports a `RevocationRegistry` here for discoverability; the
 *     TypeScript SDK does not ship a registry class, so whole-DID kill reuses the
 *     existing revocation path rather than a robotics-specific wrapper.
 *
 *   - Surgical per-credential revocation: a single capability grant, a
 *     superseded provenance attestation, or one identity credential is retired
 *     without killing the robot's whole identity, by carrying a
 *     BitstringStatusList entry. This module adds the ergonomics for putting that
 *     entry on any robot credential and checking it, over the existing
 *     `status-list` primitives.
 *
 * The fleet-scale operation of these (SLA'd propagation, dashboards, cross-fleet
 * aggregation) is a service concern layered on top; the formats and the verifier
 * here are the open, free protocol surface.
 */

import type { Signer } from '../signer';
import {
  STATUS_PURPOSE_REVOCATION,
  buildStatusListEntry,
  verifyStatus,
  type StatusPurpose,
} from '../status-list';

import { RoboticsError } from './identity';

// Re-export the status-list primitives a robot fleet uses for surgical
// per-credential revocation, matching the Python module's surface.
export {
  StatusListError,
  buildStatusListCredential,
  buildStatusListEntry,
} from '../status-list';

export interface AttachCredentialStatusOptions {
  statusListCredential: string;
  statusListIndex: number;
  statusPurpose?: StatusPurpose;
  entryId?: string;
}

/**
 * Add a BitstringStatusList `credentialStatus` entry to a robot credential and
 * (re)sign it, so the credential can later be revoked or suspended surgically.
 *
 * The entry references a bit index in a published status list credential. The
 * credential is signed after the entry is added, so the proof covers the status
 * binding. Any pre-existing proof is replaced. If the credential already carries
 * a credentialStatus, the new entry is appended (the field becomes a list),
 * matching the Verifiable Credentials data model. Returns the signed credential.
 */
export async function attachCredentialStatus(
  credential: Record<string, unknown>,
  signer: Signer,
  opts: AttachCredentialStatusOptions
): Promise<Record<string, unknown>> {
  const entry = buildStatusListEntry({
    statusListCredential: opts.statusListCredential,
    statusListIndex: opts.statusListIndex,
    statusPurpose: opts.statusPurpose ?? STATUS_PURPOSE_REVOCATION,
    entryId: opts.entryId,
  });

  const existing = credential.credentialStatus;
  if (existing === undefined || existing === null) {
    credential.credentialStatus = entry;
  } else if (Array.isArray(existing)) {
    existing.push(entry);
  } else {
    credential.credentialStatus = [existing, entry];
  }

  // Re-sign: the proof must cover the credentialStatus we just added.
  delete credential.proof;
  return signer.attachProof(credential);
}

function statusEntries(credential: Record<string, unknown>): Array<Record<string, unknown>> {
  const raw = credential.credentialStatus;
  if (raw === undefined || raw === null) {
    return [];
  }
  if (Array.isArray(raw)) {
    return raw.filter((e) => e !== null && typeof e === 'object') as Array<Record<string, unknown>>;
  }
  if (typeof raw === 'object') {
    return [raw as Record<string, unknown>];
  }
  throw new RoboticsError('credentialStatus must be an object or a list of objects');
}

export interface CheckCredentialStatusOptions {
  statusPurpose?: StatusPurpose;
}

/**
 * Return true if the robot credential's status bit for `statusPurpose` is set
 * (for example, the credential has been revoked) in the supplied status list.
 *
 * The caller MUST verify the Data Integrity proof on `statusListCredential`
 * before calling this, exactly as for the agent-side `verifyStatus`. Returns
 * false when the credential carries no matching status entry.
 */
export function checkCredentialStatus(
  credential: Record<string, unknown>,
  statusListCredential: Record<string, unknown>,
  opts: CheckCredentialStatusOptions = {}
): boolean {
  const statusPurpose = opts.statusPurpose ?? STATUS_PURPOSE_REVOCATION;
  const referencedId = statusListCredential.id;
  for (const entry of statusEntries(credential)) {
    if (entry.statusPurpose !== statusPurpose) {
      continue;
    }
    if (entry.statusListCredential !== referencedId) {
      continue;
    }
    return verifyStatus({
      credentialStatus: entry,
      statusListCredential,
    });
  }
  return false;
}
