//! Authority Freshness: authority state as a first-class input to trust freshness.
//!
//! Time-decay trust answers "how long ago was this trust established". That is
//! not enough for a high-consequence agent whose mandate can be suspended
//! seconds after a valid credential is issued. This module adds the state axis:
//! a signed `AuthorityState` credential carrying a monotonic `authorityEpoch`
//! and a `status`, plus the collapse rule that rejects a voucher minted under a
//! stale epoch for a state-freshness action, even when its time-decay trust
//! still passes.
//!
//! The credential is a plain VC Data Model 2.0 object signed with the shared
//! `eddsa-jcs-2022` path, so it canonicalizes byte-identically across every
//! language binding. This is the canonical implementation; the TypeScript, Go,
//! and Python ports mirror it and share the interop vector in
//! `test-vectors/authority-state/`.

use serde_json::{json, Map, Value};

use crate::credentials::{verify_temporal, VerifyResult, VC_CONTEXT_V2, VC_TYPE, VOUCH_CONTEXT_V1};
use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};

pub const AUTHORITY_STATE_TYPE: &str = "AuthorityState";

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_SUSPENDED: &str = "suspended";
pub const STATUS_INCIDENT: &str = "incident";
pub const STATUS_EXPOSURE_BREACHED: &str = "exposure_breached";
pub const STATUS_REVOKED: &str = "revoked";

pub const VALID_AUTHORITY_STATUSES: [&str; 5] = [
    STATUS_ACTIVE,
    STATUS_SUSPENDED,
    STATUS_INCIDENT,
    STATUS_EXPOSURE_BREACHED,
    STATUS_REVOKED,
];

// Consequence tiers, ordered by how much a stale authority view is tolerated.
// Shared vocabulary with bounded-staleness revocation.
pub const CONSEQUENCE_ROUTINE: &str = "routine";
pub const CONSEQUENCE_SENSITIVE: &str = "sensitive";
pub const CONSEQUENCE_CRITICAL: &str = "critical";

fn is_valid_status(status: &str) -> bool {
    VALID_AUTHORITY_STATUSES.contains(&status)
}

/// Render an epoch for a reason code; "?" when absent, so the string is
/// identical across every language binding.
fn epoch_str(epoch: Option<i64>) -> String {
    match epoch {
        Some(e) => e.to_string(),
        None => "?".to_string(),
    }
}

/// Inputs to build an unsigned AuthorityState credential. Deterministic and
/// clock-free: the caller supplies the id and validity window.
#[derive(Debug, Clone)]
pub struct BuildAuthorityStateOptions {
    pub issuer_did: String,
    pub credential_id: String,
    pub authority_epoch: i64,
    pub status: String,
    pub valid_from: String,
    pub valid_until: String,
    /// The DID the state is about; defaults to `issuer_did` when None.
    pub subject_did: Option<String>,
}

/// Construct an unsigned AuthorityState credential.
pub fn build_authority_state(opts: &BuildAuthorityStateOptions) -> Result<Value> {
    if opts.authority_epoch < 0 {
        return Err(CoreError::Json("authorityEpoch must be non-negative".into()));
    }
    if !is_valid_status(&opts.status) {
        return Err(CoreError::Json(format!(
            "status must be one of {VALID_AUTHORITY_STATUSES:?}"
        )));
    }
    if opts.issuer_did.is_empty() {
        return Err(CoreError::Json("issuer_did is required".into()));
    }

    let subject_did = opts.subject_did.clone().unwrap_or_else(|| opts.issuer_did.clone());

    let mut subject = Map::new();
    subject.insert("id".into(), json!(subject_did));
    subject.insert("authorityEpoch".into(), json!(opts.authority_epoch));
    subject.insert("status".into(), json!(opts.status));

    let mut vc = Map::new();
    vc.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    vc.insert("id".into(), json!(opts.credential_id));
    vc.insert("type".into(), json!([VC_TYPE, AUTHORITY_STATE_TYPE]));
    vc.insert("issuer".into(), json!(opts.issuer_did));
    vc.insert("validFrom".into(), json!(opts.valid_from));
    vc.insert("validUntil".into(), json!(opts.valid_until));
    vc.insert("credentialSubject".into(), Value::Object(subject));
    Ok(Value::Object(vc))
}

/// Build and sign an AuthorityState credential in one step (eddsa-jcs-2022).
pub fn sign_authority_state(
    opts: &BuildAuthorityStateOptions,
    raw_private_seed: &[u8],
    proof_opts: &BuildProofOptions,
) -> Result<Value> {
    let cred = build_authority_state(opts)?;
    data_integrity::sign(&cred, raw_private_seed, proof_opts)
}

/// Verify an AuthorityState credential's Data Integrity proof and validity
/// window. Same shape as `credentials::verify`: proof and time are reported
/// separately so "bad signature" is distinguished from "expired".
pub fn verify(
    credential: &Value,
    raw_public_key: &[u8],
    now_iso: &str,
    clock_skew_seconds: i64,
) -> Result<VerifyResult> {
    let ty = credential.get("type").and_then(|v| v.as_array());
    let is_authority_state = ty
        .map(|arr| arr.iter().any(|t| t.as_str() == Some(AUTHORITY_STATE_TYPE)))
        .unwrap_or(false);
    if !is_authority_state {
        return Err(CoreError::Json("credential is not an AuthorityState".into()));
    }
    let proof_valid = data_integrity::verify_proof(credential, raw_public_key)?;
    let time_valid = verify_temporal(credential, now_iso, clock_skew_seconds)?;
    Ok(VerifyResult {
        proof_valid,
        time_valid,
    })
}

/// Read `credentialSubject.authorityEpoch` without verifying the proof. For
/// deciding which of two credentials is newer; never a substitute for `verify`.
pub fn read_authority_epoch(credential: &Value) -> Result<i64> {
    credential
        .get("credentialSubject")
        .and_then(|s| s.get("authorityEpoch"))
        .and_then(|v| v.as_i64())
        .filter(|e| *e >= 0)
        .ok_or_else(|| CoreError::Json("missing or invalid authorityEpoch".into()))
}

/// Read `credentialSubject.status` without verifying the proof.
pub fn read_authority_status(credential: &Value) -> Result<String> {
    credential
        .get("credentialSubject")
        .and_then(|s| s.get("status"))
        .and_then(|v| v.as_str())
        .filter(|s| is_valid_status(s))
        .map(|s| s.to_string())
        .ok_or_else(|| CoreError::Json("missing or invalid status".into()))
}

/// How a consequence tier treats authority state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessRule {
    pub enforce_epoch: bool,
    pub require_live_cosign: bool,
}

/// The consequence -> policy map. Unknown tiers coerce to the strictest rule.
pub fn freshness_rule(tier: &str) -> FreshnessRule {
    match tier {
        CONSEQUENCE_ROUTINE => FreshnessRule {
            enforce_epoch: false,
            require_live_cosign: false,
        },
        CONSEQUENCE_SENSITIVE => FreshnessRule {
            enforce_epoch: true,
            require_live_cosign: false,
        },
        // critical and any unknown tier
        _ => FreshnessRule {
            enforce_epoch: true,
            require_live_cosign: true,
        },
    }
}

/// The outcome of an Authority Freshness evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFreshnessVerdict {
    pub allow: bool,
    pub tier: String,
    pub reason: String,
}

/// Decide whether an action passes the Authority Freshness gate.
///
/// `voucher_epoch` and `last_seen_epoch` are None when unknown. `current_status`
/// is None when the verifier does not hold a current AuthorityState.
/// `live_cosign_ok` is the verified-fresh state of a live co-sign, for the
/// critical tier only.
pub fn evaluate_authority_freshness(
    tier: &str,
    voucher_epoch: Option<i64>,
    last_seen_epoch: Option<i64>,
    current_status: Option<&str>,
    live_cosign_ok: Option<bool>,
) -> AuthorityFreshnessVerdict {
    let canonical_tier = match tier {
        CONSEQUENCE_ROUTINE | CONSEQUENCE_SENSITIVE | CONSEQUENCE_CRITICAL => tier,
        _ => CONSEQUENCE_CRITICAL,
    };
    let rule = freshness_rule(canonical_tier);
    let mk = |allow: bool, reason: String| AuthorityFreshnessVerdict {
        allow,
        tier: canonical_tier.to_string(),
        reason,
    };

    if !rule.enforce_epoch && !rule.require_live_cosign {
        return mk(true, "routine tier: time-decay only".into());
    }

    if let Some(status) = current_status {
        if status != STATUS_ACTIVE {
            return mk(false, format!("authority_status_not_active:status={status}"));
        }
    }

    if rule.require_live_cosign && live_cosign_ok != Some(true) {
        return mk(false, format!("live_cosign_required:tier={canonical_tier}"));
    }

    if rule.enforce_epoch {
        match (voucher_epoch, last_seen_epoch) {
            (Some(v), Some(seen)) => {
                if v < seen {
                    return mk(
                        false,
                        format!("authority_epoch_stale:seen={seen},voucher={v}"),
                    );
                }
            }
            _ => {
                // An absent epoch renders as "?" so the reason code is identical
                // in every language binding. Pinned by the interop vector.
                return mk(
                    false,
                    format!(
                        "authority_epoch_unknown:voucher={},seen={}",
                        epoch_str(voucher_epoch),
                        epoch_str(last_seen_epoch)
                    ),
                );
            }
        }
    }

    mk(true, format!("{canonical_tier} tier: authority state fresh"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> BuildAuthorityStateOptions {
        BuildAuthorityStateOptions {
            issuer_did: "did:web:treasury.example.com".into(),
            credential_id: "urn:uuid:00000000-0000-4000-8000-000000000000".into(),
            authority_epoch: 7,
            status: STATUS_ACTIVE.into(),
            valid_from: "2026-07-26T10:00:00Z".into(),
            valid_until: "2026-07-26T10:05:00Z".into(),
            subject_did: None,
        }
    }

    #[test]
    fn builds_expected_shape() {
        let vc = build_authority_state(&opts()).unwrap();
        assert_eq!(vc["type"], json!(["VerifiableCredential", "AuthorityState"]));
        assert_eq!(vc["credentialSubject"]["authorityEpoch"], json!(7));
        assert_eq!(vc["credentialSubject"]["status"], json!("active"));
    }

    #[test]
    fn rejects_bad_status() {
        let mut o = opts();
        o.status = "bogus".into();
        assert!(build_authority_state(&o).is_err());
    }

    #[test]
    fn sign_and_verify_within_window() {
        let seed = [7u8; 32];
        let proof_opts =
            BuildProofOptions::new("did:web:treasury.example.com#key-1", "2026-07-26T10:00:00Z");
        let signed = sign_authority_state(&opts(), &seed, &proof_opts).unwrap();
        let pk = crate::keys::Ed25519KeyPair::from_seed(&seed).public_key();
        let r = verify(&signed, &pk, "2026-07-26T10:02:00Z", 30).unwrap();
        assert!(r.is_valid());
        assert_eq!(read_authority_epoch(&signed).unwrap(), 7);
        assert_eq!(read_authority_status(&signed).unwrap(), "active");
    }

    #[test]
    fn routine_ignores_stale_epoch() {
        let v = evaluate_authority_freshness(CONSEQUENCE_ROUTINE, Some(1), Some(9), None, None);
        assert!(v.allow);
    }

    #[test]
    fn sensitive_rejects_stale_epoch() {
        let v = evaluate_authority_freshness(CONSEQUENCE_SENSITIVE, Some(5), Some(7), None, None);
        assert!(!v.allow);
        assert_eq!(v.reason, "authority_epoch_stale:seen=7,voucher=5");
    }

    #[test]
    fn sensitive_rejects_unknown_epoch() {
        // An absent epoch renders as "?" so the reason code is identical in
        // every language binding. Pinned by the shared interop vector.
        let v = evaluate_authority_freshness(CONSEQUENCE_SENSITIVE, None, Some(3), None, None);
        assert!(!v.allow);
        assert_eq!(v.reason, "authority_epoch_unknown:voucher=?,seen=3");
        let v2 = evaluate_authority_freshness(CONSEQUENCE_SENSITIVE, Some(5), None, None, None);
        assert_eq!(v2.reason, "authority_epoch_unknown:voucher=5,seen=?");
    }

    #[test]
    fn sensitive_allows_current_epoch() {
        let v = evaluate_authority_freshness(CONSEQUENCE_SENSITIVE, Some(9), Some(9), None, None);
        assert!(v.allow);
    }

    #[test]
    fn non_active_status_fails_closed() {
        let v = evaluate_authority_freshness(
            CONSEQUENCE_SENSITIVE,
            Some(9),
            Some(9),
            Some(STATUS_SUSPENDED),
            None,
        );
        assert!(!v.allow);
        assert_eq!(v.reason, "authority_status_not_active:status=suspended");
    }

    #[test]
    fn critical_requires_live_cosign() {
        let denied =
            evaluate_authority_freshness(CONSEQUENCE_CRITICAL, Some(9), Some(9), None, None);
        assert!(!denied.allow);
        assert!(denied.reason.starts_with("live_cosign_required"));
        let allowed =
            evaluate_authority_freshness(CONSEQUENCE_CRITICAL, Some(9), Some(9), None, Some(true));
        assert!(allowed.allow);
    }

    #[test]
    fn unknown_tier_coerces_to_critical() {
        let v = evaluate_authority_freshness("made-up", Some(9), Some(9), None, None);
        assert_eq!(v.tier, "critical");
        assert!(!v.allow);
    }
}
