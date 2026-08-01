//! Reasoned Action Proofs and event-triggered intent recheck.
//!
//! A standard credential answers *who* acted and *under what authority*. It says
//! nothing about *why*. This module adds the missing "why" layer: before acting,
//! an agent states a structured **justification** (an intent plus a set of
//! **evidence anchors**, each a claim tied to a real artifact by that artifact's
//! hash). The justification is committed by digest, optionally deposited with a
//! neutral **escrow** that timestamps it, and the executed action credential
//! carries the commitment. Three properties then hold: no fabrication (each
//! reason names an artifact a verifier re-resolves and hashes), no post-hoc
//! rewrite (the credential carries the digest), and, with escrow, committed
//! before execution (the deposit time is not after execution).
//!
//! This is the canonical port of the Python reference `vouch/reasoning.py`. The
//! digest algorithm and every stable reason string match byte for byte, so a
//! seal built in one language verifies in another. Everything here is an ordinary
//! `eddsa-jcs-2022` Verifiable Credential.
//!
//! ## Intent recheck (event-triggered)
//!
//! A heartbeat proves the agent is alive across an interval; it does not prove the
//! agent's intent is current at the moment of a sensitive action. A justification
//! sealed early in an interval still passes for an action executed much later in
//! the same interval, so a sophisticated actor can time a sensitive action to land
//! after a pulse boundary while reusing an intent sealed before it. The intent
//! recheck binds seal freshness to the action: for a sensitive consequence tier
//! the seal must post-date the last pulse boundary and be within a configurable
//! max age, not merely predate execution. See [`verify_intent_freshness`] and
//! [`reseal_intent`].

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};
use crate::jcs;
use crate::time::iso_to_epoch_seconds;

pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const VOUCH_CONTEXT_V1: &str = "https://vouch-protocol.com/contexts/v1";

pub const REASONED_ACTION_TYPE: &str = "ReasonedActionCredential";
pub const ESCROW_RECEIPT_TYPE: &str = "JustificationEscrowReceipt";

pub const JUSTIFICATION_ALGORITHM: &str = "sha-256-jcs";

// Structured verification reasons (stable strings, mirrored by every SDK).
pub const REASON_INVALID_PROOF: &str = "invalid_proof";
pub const REASON_NOT_REASONED_ACTION: &str = "not_reasoned_action";
pub const REASON_MISSING_COMMITMENT: &str = "missing_commitment";
pub const REASON_MISSING_ESCROW: &str = "missing_escrow";
pub const REASON_ESCROW_INVALID: &str = "escrow_receipt_invalid";
pub const REASON_ESCROW_DIGEST_MISMATCH: &str = "escrow_digest_mismatch";
pub const REASON_ESCROW_AFTER_EXECUTION: &str = "escrow_after_execution";
pub const REASON_JUSTIFICATION_DIGEST_MISMATCH: &str = "justification_digest_mismatch";
pub const REASON_EVIDENCE_UNRESOLVED: &str = "evidence_unresolved";
pub const REASON_EVIDENCE_HASH_MISMATCH: &str = "evidence_hash_mismatch";
pub const REASON_UNANCHORED_CLAIM: &str = "unanchored_claim";

// Intent-recheck reasons (stable prefixes; carry a structured suffix).
pub const REASON_INTENT_SEAL_STALE: &str = "intent_seal_stale";
pub const REASON_INTENT_SEAL_EXPIRED: &str = "intent_seal_expired";
pub const REASON_INTENT_SEAL_MISSING: &str = "intent_seal_missing";

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Multibase base64url-no-pad of raw bytes, matching the Python `_mb64` helper
/// (`"u"` prefix + RFC 4648 base64url without padding).
fn mb64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    format!("u{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Canonical bytes of an evidence artifact, for content addressing. A JSON string
/// is hashed as its UTF-8 bytes; a JSON object is JCS-canonicalized. This matches
/// the `str`/`dict` cases of the Python `_artifact_bytes`. Raw byte artifacts use
/// [`artifact_digest_bytes`].
fn artifact_bytes(artifact: &Value) -> Result<Vec<u8>> {
    match artifact {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        Value::Object(_) => Ok(jcs::canonicalize(artifact)),
        _ => Err(CoreError::Json(
            "evidence artifact must be a JSON object or string".into(),
        )),
    }
}

/// Multibase SHA-256 of an evidence artifact (JSON object or string).
pub fn artifact_digest(artifact: &Value) -> Result<String> {
    Ok(mb64(&Sha256::digest(&artifact_bytes(artifact)?)))
}

/// Multibase SHA-256 of a raw-byte evidence artifact.
pub fn artifact_digest_bytes(artifact: &[u8]) -> String {
    mb64(&Sha256::digest(artifact))
}

fn type_list(credential: &Value) -> Vec<String> {
    match credential.get("type") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Attach an `eddsa-jcs-2022` proof to `credential` in place, signing with the
/// raw Ed25519 seed and stamping `created`.
fn attach_proof(
    credential: &mut Value,
    seed: &[u8],
    verification_method: &str,
    created: &str,
) -> Result<()> {
    let opts = BuildProofOptions::new(verification_method, created);
    let proof = data_integrity::build_proof(credential, seed, &opts)?;
    credential
        .as_object_mut()
        .ok_or_else(|| CoreError::Json("credential must be a JSON object".into()))?
        .insert("proof".into(), proof);
    Ok(())
}

// ---------------------------------------------------------------------------
// Justification: the structured "why", anchored to real evidence
// ---------------------------------------------------------------------------

/// Build one evidence anchor: a claim tied to a verifiable artifact. Supply
/// `evidence` (its hash is computed) OR a precomputed `evidence_hash`.
pub fn evidence_anchor(
    claim: &str,
    reference: &str,
    evidence: Option<&Value>,
    evidence_hash: Option<&str>,
    anchor_type: &str,
) -> Result<Value> {
    if claim.is_empty() || reference.is_empty() {
        return Err(CoreError::Json(
            "an evidence anchor needs a claim and a ref".into(),
        ));
    }
    let hash = match evidence_hash {
        Some(h) => h.to_string(),
        None => match evidence {
            Some(e) => artifact_digest(e)?,
            None => {
                return Err(CoreError::Json(
                    "supply evidence or evidence_hash for the anchor".into(),
                ))
            }
        },
    };
    let mut anchor = Map::new();
    anchor.insert("type".into(), Value::String(anchor_type.to_string()));
    anchor.insert("claim".into(), Value::String(claim.to_string()));
    anchor.insert("ref".into(), Value::String(reference.to_string()));
    anchor.insert("evidenceHash".into(), Value::String(hash));
    Ok(Value::Object(anchor))
}

/// Assemble a justification: the intent plus its evidence anchors. `intent` must
/// carry at least `action` and `target`; at least one anchor is required.
pub fn build_justification(
    intent: &Value,
    anchors: &[Value],
    commitment_level: Option<i64>,
) -> Result<Value> {
    if !intent.is_object()
        || intent.get("action").and_then(|v| v.as_str()).is_none()
        || intent.get("target").and_then(|v| v.as_str()).is_none()
    {
        return Err(CoreError::Json(
            "intent must be an object with at least action and target".into(),
        ));
    }
    if anchors.is_empty() {
        return Err(CoreError::Json(
            "a justification needs at least one evidence anchor".into(),
        ));
    }
    let mut just = Map::new();
    just.insert("intent".into(), intent.clone());
    just.insert("evidenceAnchors".into(), Value::Array(anchors.to_vec()));
    if let Some(level) = commitment_level {
        just.insert("commitmentLevel".into(), Value::from(level));
    }
    Ok(Value::Object(just))
}

/// Multibase SHA-256 over the JCS-canonical justification.
pub fn justification_digest(justification: &Value) -> Result<String> {
    if !justification.is_object() {
        return Err(CoreError::Json(
            "justification must be a JSON object".into(),
        ));
    }
    Ok(mb64(&Sha256::digest(&jcs::canonicalize(justification))))
}

// ---------------------------------------------------------------------------
// Escrow: a neutral timestamp that fixes the commitment before execution
// ---------------------------------------------------------------------------

/// Issue a signed `JustificationEscrowReceipt` fixing a commitment in time. The
/// escrow sees only the digest, never the plaintext justification.
#[allow(clippy::too_many_arguments)]
pub fn build_escrow_receipt(
    escrow_seed: &[u8],
    escrow_did: &str,
    escrow_verification_method: &str,
    agent_did: &str,
    committed_digest: &str,
    deposited_at: &str,
    credential_id: &str,
) -> Result<Value> {
    let mut subject = Map::new();
    subject.insert("agent".into(), Value::String(agent_did.to_string()));
    subject.insert(
        "committedDigest".into(),
        Value::String(committed_digest.to_string()),
    );
    subject.insert(
        "depositedAt".into(),
        Value::String(deposited_at.to_string()),
    );

    let mut receipt = Map::new();
    receipt.insert(
        "@context".into(),
        Value::Array(vec![
            Value::String(VC_CONTEXT_V2.into()),
            Value::String(VOUCH_CONTEXT_V1.into()),
        ]),
    );
    receipt.insert(
        "type".into(),
        Value::Array(vec![
            Value::String("VerifiableCredential".into()),
            Value::String(ESCROW_RECEIPT_TYPE.into()),
        ]),
    );
    receipt.insert("id".into(), Value::String(credential_id.to_string()));
    receipt.insert("issuer".into(), Value::String(escrow_did.to_string()));
    receipt.insert("validFrom".into(), Value::String(deposited_at.to_string()));
    receipt.insert("credentialSubject".into(), Value::Object(subject));

    let mut receipt = Value::Object(receipt);
    attach_proof(
        &mut receipt,
        escrow_seed,
        escrow_verification_method,
        deposited_at,
    )?;
    Ok(receipt)
}

/// Verify an escrow receipt's proof and structure against the escrow's raw
/// Ed25519 public key. Returns `(ok, subject)`.
pub fn verify_escrow_receipt(receipt: &Value, escrow_public_key: &[u8]) -> (bool, Option<Value>) {
    if !type_list(receipt).iter().any(|t| t == ESCROW_RECEIPT_TYPE) {
        return (false, None);
    }
    match data_integrity::verify_proof(receipt, escrow_public_key) {
        Ok(true) => {}
        _ => return (false, None),
    }
    let subject = match receipt.get("credentialSubject").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return (false, None),
    };
    let has_digest = subject
        .get("committedDigest")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    let has_deposited = subject
        .get("depositedAt")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    if !has_digest || !has_deposited {
        return (false, None);
    }
    (true, Some(Value::Object(subject.clone())))
}

// ---------------------------------------------------------------------------
// Reasoned action credential: the executed action, carrying its commitment
// ---------------------------------------------------------------------------

/// Options for [`sign_reasoned_action`].
#[derive(Debug, Clone, Default)]
pub struct SignReasonedActionOptions {
    /// If false, publish only the digest (private reasoning); reveal anchors out
    /// of band at audit time. Defaults to true.
    pub include_reasoning: bool,
    /// Attach an escrow receipt proving the commitment was fixed before this
    /// action.
    pub escrow_receipt: Option<Value>,
    /// The moment the intent was sealed. Read by the intent recheck. When escrow
    /// is used this SHOULD equal the receipt's `depositedAt`; without escrow the
    /// signer stamps it. Absent by default (backward compatible).
    pub sealed_at: Option<String>,
}

impl SignReasonedActionOptions {
    pub fn new() -> Self {
        Self {
            include_reasoning: true,
            escrow_receipt: None,
            sealed_at: None,
        }
    }
}

/// Issue a `ReasonedActionCredential`: the action bound to its justification.
/// `valid_from` is the execution time and also the proof `created`.
#[allow(clippy::too_many_arguments)]
pub fn sign_reasoned_action(
    seed: &[u8],
    issuer_did: &str,
    verification_method: &str,
    intent: &Value,
    justification: &Value,
    valid_from: &str,
    credential_id: &str,
    opts: &SignReasonedActionOptions,
) -> Result<Value> {
    if !intent.is_object()
        || intent.get("action").and_then(|v| v.as_str()).is_none()
        || intent.get("target").and_then(|v| v.as_str()).is_none()
    {
        return Err(CoreError::Json(
            "intent must be an object with at least action and target".into(),
        ));
    }
    let digest = justification_digest(justification)?;

    let mut commitment = Map::new();
    commitment.insert(
        "algorithm".into(),
        Value::String(JUSTIFICATION_ALGORITHM.into()),
    );
    commitment.insert("digest".into(), Value::String(digest));

    let mut jblock = Map::new();
    jblock.insert("commitment".into(), Value::Object(commitment));
    if let Some(sealed) = &opts.sealed_at {
        jblock.insert("sealedAt".into(), Value::String(sealed.clone()));
    }
    if let Some(level) = justification.get("commitmentLevel") {
        jblock.insert("commitmentLevel".into(), level.clone());
    }
    if let Some(receipt) = &opts.escrow_receipt {
        jblock.insert("escrowReceipt".into(), receipt.clone());
    }
    if opts.include_reasoning {
        let anchors = justification
            .get("evidenceAnchors")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        jblock.insert("evidenceAnchors".into(), anchors);
    }

    let mut subject = Map::new();
    subject.insert("intent".into(), intent.clone());
    subject.insert("justification".into(), Value::Object(jblock));

    let mut credential = Map::new();
    credential.insert(
        "@context".into(),
        Value::Array(vec![
            Value::String(VC_CONTEXT_V2.into()),
            Value::String(VOUCH_CONTEXT_V1.into()),
        ]),
    );
    credential.insert(
        "type".into(),
        Value::Array(vec![
            Value::String("VerifiableCredential".into()),
            Value::String(REASONED_ACTION_TYPE.into()),
        ]),
    );
    credential.insert("id".into(), Value::String(credential_id.to_string()));
    credential.insert("issuer".into(), Value::String(issuer_did.to_string()));
    credential.insert("validFrom".into(), Value::String(valid_from.to_string()));
    credential.insert("credentialSubject".into(), Value::Object(subject));

    let mut credential = Value::Object(credential);
    attach_proof(&mut credential, seed, verification_method, valid_from)?;
    Ok(credential)
}

/// Verify a reasoned-action credential. Returns `None` on success or a structured
/// reason string on failure. Checks the agent's proof, the commitment, and, when
/// an escrow receipt is attached, the receipt's proof, digest agreement, and
/// commit-before-execute. Does not resolve evidence anchors (see
/// [`verify_justification`]).
pub fn check_reasoned_action(
    credential: &Value,
    public_key: &[u8],
    escrow_public_key: Option<&[u8]>,
    require_escrow: bool,
) -> Option<String> {
    if !type_list(credential)
        .iter()
        .any(|t| t == REASONED_ACTION_TYPE)
    {
        return Some(REASON_NOT_REASONED_ACTION.into());
    }
    match data_integrity::verify_proof(credential, public_key) {
        Ok(true) => {}
        _ => return Some(REASON_INVALID_PROOF.into()),
    }

    let jblock = credential
        .get("credentialSubject")
        .and_then(|s| s.get("justification"));
    let commitment_digest = jblock
        .and_then(|j| j.get("commitment"))
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str());
    let commitment_digest = match commitment_digest {
        Some(d) if !d.is_empty() => d,
        _ => return Some(REASON_MISSING_COMMITMENT.into()),
    };

    let receipt = jblock.and_then(|j| j.get("escrowReceipt"));
    let receipt = match receipt {
        None | Some(Value::Null) => {
            return if require_escrow {
                Some(REASON_MISSING_ESCROW.into())
            } else {
                None
            };
        }
        Some(r) => r,
    };

    let escrow_key = match escrow_public_key {
        Some(k) => k,
        None => return Some(REASON_ESCROW_INVALID.into()),
    };
    let (ok, rsubject) = verify_escrow_receipt(receipt, escrow_key);
    if !ok {
        return Some(REASON_ESCROW_INVALID.into());
    }
    let rsubject = rsubject.unwrap();
    if rsubject.get("committedDigest").and_then(|v| v.as_str()) != Some(commitment_digest) {
        return Some(REASON_ESCROW_DIGEST_MISMATCH.into());
    }

    let deposited = rsubject
        .get("depositedAt")
        .and_then(|v| v.as_str())
        .and_then(|s| iso_to_epoch_seconds(s).ok());
    let executed = credential
        .get("validFrom")
        .and_then(|v| v.as_str())
        .and_then(|s| iso_to_epoch_seconds(s).ok());
    match (deposited, executed) {
        (Some(d), Some(e)) if d > e => Some(REASON_ESCROW_AFTER_EXECUTION.into()),
        (Some(_), Some(_)) => None,
        _ => Some(REASON_ESCROW_INVALID.into()),
    }
}

/// Convenience wrapper over [`check_reasoned_action`] returning
/// `(ok, credentialSubject)`.
pub fn verify_reasoned_action(
    credential: &Value,
    public_key: &[u8],
    escrow_public_key: Option<&[u8]>,
    require_escrow: bool,
) -> (bool, Option<Value>) {
    if check_reasoned_action(credential, public_key, escrow_public_key, require_escrow).is_some() {
        return (false, None);
    }
    (true, credential.get("credentialSubject").cloned())
}

/// Check a revealed justification against a verified credential's commitment: the
/// justification must recompute to the committed digest, and every anchor must
/// resolve (via `resolver`) to an artifact whose hash matches. Returns
/// `(true, None)` on success, else `(false, Some(reason))`.
pub fn verify_justification<F>(
    presented_justification: &Value,
    credential_subject: &Value,
    resolver: F,
) -> (bool, Option<String>)
where
    F: Fn(&str) -> Option<Value>,
{
    let committed = credential_subject
        .get("justification")
        .and_then(|j| j.get("commitment"))
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str());
    let committed = match committed {
        Some(d) if !d.is_empty() => d,
        _ => return (false, Some(REASON_MISSING_COMMITMENT.into())),
    };

    match justification_digest(presented_justification) {
        Ok(d) if d == committed => {}
        _ => return (false, Some(REASON_JUSTIFICATION_DIGEST_MISMATCH.into())),
    }

    let anchors = presented_justification
        .get("evidenceAnchors")
        .and_then(|a| a.as_array());
    let anchors = match anchors {
        Some(a) if !a.is_empty() => a,
        _ => return (false, Some(REASON_UNANCHORED_CLAIM.into())),
    };
    for anchor in anchors {
        let reference = anchor.get("ref").and_then(|v| v.as_str());
        let artifact = reference.and_then(&resolver);
        let artifact = match artifact {
            Some(a) => a,
            None => return (false, Some(REASON_EVIDENCE_UNRESOLVED.into())),
        };
        let expected = anchor.get("evidenceHash").and_then(|v| v.as_str());
        match artifact_digest(&artifact) {
            Ok(actual) if Some(actual.as_str()) == expected => {}
            _ => return (false, Some(REASON_EVIDENCE_HASH_MISMATCH.into())),
        }
    }
    (true, None)
}

// ---------------------------------------------------------------------------
// Intent recheck: bind seal freshness to the action, not just the interval
// ---------------------------------------------------------------------------

/// Where an action's execution time falls relative to the current pulse window
/// `[last_pulse, last_pulse + interval)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PulseWindow {
    /// Execution is inside the current window (a pulse is not yet due).
    pub in_window: bool,
    /// Execution is in the gap past the window's end (the next pulse is overdue).
    pub in_gap: bool,
    /// Seconds from `last_pulse` to execution (negative if execution precedes it).
    pub seconds_into_window: i64,
}

/// Classify an action's execution time against the pulse schedule. `last_pulse`
/// is the issue time of the most recent heartbeat; `interval_seconds` is the
/// heartbeat period.
pub fn pulse_window(
    last_pulse: &str,
    interval_seconds: i64,
    exec_time: &str,
) -> Result<PulseWindow> {
    let pulse = iso_to_epoch_seconds(last_pulse)?;
    let exec = iso_to_epoch_seconds(exec_time)?;
    let delta = exec - pulse;
    let in_window = delta >= 0 && delta < interval_seconds;
    Ok(PulseWindow {
        in_window,
        in_gap: delta >= interval_seconds,
        seconds_into_window: delta,
    })
}

/// The freshness requirement a consequence tier imposes on an intent seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessRequirement {
    /// The seal must post-date the last pulse boundary (be sealed in the current
    /// window), not merely predate execution.
    pub require_fresh_seal: bool,
    /// The seal must be at most this many seconds older than execution. `i64::MAX`
    /// means no age bound.
    pub max_age_seconds: i64,
}

impl FreshnessRequirement {
    pub const NONE: FreshnessRequirement = FreshnessRequirement {
        require_fresh_seal: false,
        max_age_seconds: i64::MAX,
    };
}

/// Consequence tiers, aligned with PAD-017 commitment levels (0..4) and the
/// trust-entropy stakes bands. Higher tiers demand a fresher seal.
pub const TIER_ROUTINE: i64 = 0;
pub const TIER_LOW: i64 = 1;
pub const TIER_MEDIUM: i64 = 2;
pub const TIER_HIGH: i64 = 3;
pub const TIER_CRITICAL: i64 = 4;

/// Reference intent-freshness policy: routine/low/medium tiers inherit the last
/// pulse's assurance; high and critical tiers require a seal sealed after the
/// last pulse boundary, within a tightening max age. Deployments substitute their
/// own thresholds; these are reference values.
pub fn default_requirement(tier: i64) -> FreshnessRequirement {
    match tier {
        t if t >= TIER_CRITICAL => FreshnessRequirement {
            require_fresh_seal: true,
            max_age_seconds: 60,
        },
        TIER_HIGH => FreshnessRequirement {
            require_fresh_seal: true,
            max_age_seconds: 300,
        },
        _ => FreshnessRequirement::NONE,
    }
}

/// Read the seal timestamp from a reasoned-action credential: the justification's
/// `sealedAt` if present, else the attached escrow receipt's `depositedAt`.
pub fn seal_timestamp(credential: &Value) -> Option<String> {
    let jblock = credential
        .get("credentialSubject")
        .and_then(|s| s.get("justification"))?;
    if let Some(sealed) = jblock.get("sealedAt").and_then(|v| v.as_str()) {
        return Some(sealed.to_string());
    }
    jblock
        .get("escrowReceipt")
        .and_then(|r| r.get("credentialSubject"))
        .and_then(|s| s.get("depositedAt"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// The core intent-recheck rule. Given a seal time, the action's execution time,
/// the last pulse boundary, and a tier's freshness requirement, return `None` if
/// the seal is fresh enough, else a stable reason string.
///
/// - `intent_seal_stale:sealed_at=<t>,last_pulse=<t>` — a pulse boundary elapsed
///   between sealing and execution; the action inherited a prior pulse's
///   assurance. This is the timing-the-gap case.
/// - `intent_seal_expired:sealed_at=<t>,max_age=<n>s` — the seal is within the
///   current window but older than the tier's max age.
pub fn check_seal_freshness(
    sealed_at: &str,
    exec_time: &str,
    last_pulse: &str,
    requirement: FreshnessRequirement,
) -> Result<Option<String>> {
    if !requirement.require_fresh_seal {
        return Ok(None);
    }
    let sealed = iso_to_epoch_seconds(sealed_at)?;
    let exec = iso_to_epoch_seconds(exec_time)?;
    let pulse = iso_to_epoch_seconds(last_pulse)?;
    if sealed < pulse {
        return Ok(Some(format!(
            "{REASON_INTENT_SEAL_STALE}:sealed_at={sealed_at},last_pulse={last_pulse}"
        )));
    }
    if requirement.max_age_seconds != i64::MAX && exec - sealed > requirement.max_age_seconds {
        return Ok(Some(format!(
            "{REASON_INTENT_SEAL_EXPIRED}:sealed_at={sealed_at},max_age={}s",
            requirement.max_age_seconds
        )));
    }
    Ok(None)
}

/// Verify intent freshness for a reasoned-action credential at a given tier.
/// Returns `None` when the tier does not require a fresh seal or the seal is
/// fresh; else a stable reason string. When the tier requires a fresh seal but
/// the credential carries no seal timestamp, returns `intent_seal_missing`.
pub fn verify_intent_freshness(
    credential: &Value,
    tier: i64,
    last_pulse: &str,
    requirement: FreshnessRequirement,
) -> Result<Option<String>> {
    if !requirement.require_fresh_seal {
        return Ok(None);
    }
    let exec_time = credential
        .get("validFrom")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("credential has no validFrom".into()))?;
    let sealed_at = match seal_timestamp(credential) {
        Some(s) => s,
        None => return Ok(Some(format!("{REASON_INTENT_SEAL_MISSING}:tier={tier}"))),
    };
    check_seal_freshness(&sealed_at, exec_time, last_pulse, requirement)
}

/// Execution-time reseal helper: seal the intent right now and issue a fresh
/// `ReasonedActionCredential` whose `sealedAt` and `validFrom` are both `now`, so
/// a sensitive action carries a seal made in the current pulse window. Reuses
/// [`build_justification`] and [`sign_reasoned_action`]; no new cryptography.
#[allow(clippy::too_many_arguments)]
pub fn reseal_intent(
    seed: &[u8],
    issuer_did: &str,
    verification_method: &str,
    intent: &Value,
    anchors: &[Value],
    commitment_level: Option<i64>,
    now: &str,
    credential_id: &str,
    include_reasoning: bool,
) -> Result<Value> {
    let justification = build_justification(intent, anchors, commitment_level)?;
    let opts = SignReasonedActionOptions {
        include_reasoning,
        escrow_receipt: None,
        sealed_at: Some(now.to_string()),
    };
    sign_reasoned_action(
        seed,
        issuer_did,
        verification_method,
        intent,
        &justification,
        now,
        credential_id,
        &opts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519KeyPair;
    use serde_json::json;

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn pubkey() -> [u8; 32] {
        Ed25519KeyPair::from_seed_slice(&seed())
            .unwrap()
            .public_key()
    }

    fn sample_intent() -> Value {
        json!({"action": "transfer_funds", "target": "account:9911", "resource": "https://bank.example/v1/xfer"})
    }

    fn sample_justification() -> Value {
        let anchor = evidence_anchor(
            "user approved the transfer",
            "urn:msg:42",
            Some(&json!({"text": "please move $500 to savings"})),
            None,
            "user_message",
        )
        .unwrap();
        build_justification(&sample_intent(), &[anchor], Some(TIER_HIGH)).unwrap()
    }

    #[test]
    fn justification_digest_is_multibase_b64url() {
        let d = justification_digest(&sample_justification()).unwrap();
        assert!(d.starts_with('u'));
    }

    #[test]
    fn sign_then_verify_reasoned_action() {
        let cred = sign_reasoned_action(
            &seed(),
            "did:web:agent.example",
            "did:web:agent.example#key-1",
            &sample_intent(),
            &sample_justification(),
            "2026-08-02T10:00:00Z",
            "urn:uuid:11111111-1111-1111-1111-111111111111",
            &SignReasonedActionOptions::new(),
        )
        .unwrap();
        assert!(check_reasoned_action(&cred, &pubkey(), None, false).is_none());
        assert_eq!(
            check_reasoned_action(&cred, &pubkey(), None, true),
            Some(REASON_MISSING_ESCROW.into())
        );
    }

    #[test]
    fn tampered_action_fails() {
        let mut cred = sign_reasoned_action(
            &seed(),
            "did:web:agent.example",
            "did:web:agent.example#key-1",
            &sample_intent(),
            &sample_justification(),
            "2026-08-02T10:00:00Z",
            "urn:uuid:11111111-1111-1111-1111-111111111111",
            &SignReasonedActionOptions::new(),
        )
        .unwrap();
        cred["credentialSubject"]["intent"]["action"] = json!("drain_account");
        assert_eq!(
            check_reasoned_action(&cred, &pubkey(), None, false),
            Some(REASON_INVALID_PROOF.into())
        );
    }

    #[test]
    fn pulse_window_classifies_window_and_gap() {
        // interval 60s, last pulse at 10:00:00.
        let w = pulse_window("2026-08-02T10:00:00Z", 60, "2026-08-02T10:00:30Z").unwrap();
        assert!(w.in_window && !w.in_gap);
        let g = pulse_window("2026-08-02T10:00:00Z", 60, "2026-08-02T10:02:00Z").unwrap();
        assert!(g.in_gap && !g.in_window);
    }

    // --- Intent recheck acceptance/rejection matrix ---

    fn reasoned_with_seal(sealed_at: &str, exec: &str, level: i64) -> Value {
        let anchor = evidence_anchor(
            "user approved",
            "urn:msg:42",
            Some(&json!({"text": "go"})),
            None,
            "user_message",
        )
        .unwrap();
        let just = build_justification(&sample_intent(), &[anchor], Some(level)).unwrap();
        let opts = SignReasonedActionOptions {
            include_reasoning: true,
            escrow_receipt: None,
            sealed_at: Some(sealed_at.to_string()),
        };
        sign_reasoned_action(
            &seed(),
            "did:web:agent.example",
            "did:web:agent.example#key-1",
            &sample_intent(),
            &just,
            exec,
            "urn:uuid:22222222-2222-2222-2222-222222222222",
            &opts,
        )
        .unwrap()
    }

    #[test]
    fn fresh_seal_in_window_accepts() {
        // High tier, sealed at 10:00:10, pulse at 10:00:00, exec 10:00:20 (< 300s).
        let cred = reasoned_with_seal("2026-08-02T10:00:10Z", "2026-08-02T10:00:20Z", TIER_HIGH);
        let r = verify_intent_freshness(
            &cred,
            TIER_HIGH,
            "2026-08-02T10:00:00Z",
            default_requirement(TIER_HIGH),
        )
        .unwrap();
        assert_eq!(r, None);
    }

    #[test]
    fn stale_seal_across_boundary_rejects() {
        // Sealed 09:59:50 (before the 10:00:00 pulse), executed at 10:00:20 in the
        // gap after the boundary. The attacker timed the interval.
        let cred = reasoned_with_seal("2026-08-02T09:59:50Z", "2026-08-02T10:00:20Z", TIER_HIGH);
        let r = verify_intent_freshness(
            &cred,
            TIER_HIGH,
            "2026-08-02T10:00:00Z",
            default_requirement(TIER_HIGH),
        )
        .unwrap();
        assert_eq!(
            r,
            Some(
                "intent_seal_stale:sealed_at=2026-08-02T09:59:50Z,last_pulse=2026-08-02T10:00:00Z"
                    .into()
            )
        );
    }

    #[test]
    fn fresh_reseal_in_gap_accepts() {
        // Even executing at 10:05:00, a reseal at 10:05:00 with a pulse boundary
        // advanced to 10:05:00 is fresh.
        let cred = reseal_intent(
            &seed(),
            "did:web:agent.example",
            "did:web:agent.example#key-1",
            &sample_intent(),
            &[evidence_anchor(
                "user approved",
                "urn:msg:42",
                Some(&json!({"text": "go"})),
                None,
                "user_message",
            )
            .unwrap()],
            Some(TIER_HIGH),
            "2026-08-02T10:05:00Z",
            "urn:uuid:33333333-3333-3333-3333-333333333333",
            true,
        )
        .unwrap();
        let r = verify_intent_freshness(
            &cred,
            TIER_HIGH,
            "2026-08-02T10:05:00Z",
            default_requirement(TIER_HIGH),
        )
        .unwrap();
        assert_eq!(r, None);
        assert!(check_reasoned_action(&cred, &pubkey(), None, false).is_none());
    }

    #[test]
    fn non_sensitive_tier_ignores_stale_seal() {
        // Same stale seal, but a routine tier does not require freshness.
        let cred = reasoned_with_seal("2026-08-02T09:59:50Z", "2026-08-02T10:00:20Z", TIER_ROUTINE);
        let r = verify_intent_freshness(
            &cred,
            TIER_ROUTINE,
            "2026-08-02T10:00:00Z",
            default_requirement(TIER_ROUTINE),
        )
        .unwrap();
        assert_eq!(r, None);
    }

    #[test]
    fn sensitive_tier_without_seal_is_missing() {
        // A high-tier action with no seal timestamp at all.
        let cred = sign_reasoned_action(
            &seed(),
            "did:web:agent.example",
            "did:web:agent.example#key-1",
            &sample_intent(),
            &sample_justification(),
            "2026-08-02T10:00:20Z",
            "urn:uuid:44444444-4444-4444-4444-444444444444",
            &SignReasonedActionOptions::new(),
        )
        .unwrap();
        let r = verify_intent_freshness(
            &cred,
            TIER_HIGH,
            "2026-08-02T10:00:00Z",
            default_requirement(TIER_HIGH),
        )
        .unwrap();
        assert_eq!(r, Some("intent_seal_missing:tier=3".into()));
    }

    #[test]
    fn escrow_roundtrip_and_seal_from_deposit() {
        let escrow_seed = [3u8; 32];
        let escrow_pub = Ed25519KeyPair::from_seed_slice(&escrow_seed)
            .unwrap()
            .public_key();
        let digest = justification_digest(&sample_justification()).unwrap();
        let receipt = build_escrow_receipt(
            &escrow_seed,
            "did:web:escrow.example",
            "did:web:escrow.example#key-1",
            "did:web:agent.example",
            &digest,
            "2026-08-02T10:00:05Z",
            "urn:uuid:55555555-5555-5555-5555-555555555555",
        )
        .unwrap();
        let (ok, _) = verify_escrow_receipt(&receipt, &escrow_pub);
        assert!(ok);

        let opts = SignReasonedActionOptions {
            include_reasoning: true,
            escrow_receipt: Some(receipt),
            sealed_at: None,
        };
        let cred = sign_reasoned_action(
            &seed(),
            "did:web:agent.example",
            "did:web:agent.example#key-1",
            &sample_intent(),
            &sample_justification(),
            "2026-08-02T10:00:20Z",
            "urn:uuid:66666666-6666-6666-6666-666666666666",
            &opts,
        )
        .unwrap();
        // Seal timestamp falls back to the escrow depositedAt.
        assert_eq!(
            seal_timestamp(&cred).as_deref(),
            Some("2026-08-02T10:00:05Z")
        );
        assert!(check_reasoned_action(&cred, &pubkey(), Some(&escrow_pub), true).is_none());
    }
}
