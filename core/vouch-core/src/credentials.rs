//! Vouch Credential build and verify.
//!
//! Byte-exact port of the TypeScript `buildVouchCredential` (vc.ts): same JSON
//! shape and field ordering. The core is deterministic and clock-free, so the
//! caller supplies the credential id and the validity window (the SDK/wrapper
//! computes them); verification takes the current instant as a parameter.

use serde_json::{json, Map, Value};

use crate::data_integrity::{self, BuildProofOptions};
use crate::error::{CoreError, Result};
use crate::time::iso_to_epoch_seconds;

pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const VOUCH_CONTEXT_V1: &str = "https://vouch-protocol.com/contexts/v1";
pub const VC_TYPE: &str = "VerifiableCredential";
pub const VOUCH_CREDENTIAL_TYPE: &str = "VouchCredential";
pub const PROTOCOL_VERSION: &str = "1.0";

/// Inputs to build an unsigned Vouch Credential.
#[derive(Debug, Clone)]
pub struct BuildCredentialOptions {
    pub issuer_did: String,
    pub credential_id: String,
    pub intent: Value,
    pub valid_from: String,
    pub valid_until: String,
    pub reputation_score: Option<i64>,
    pub delegation_chain: Option<Value>,
    pub credential_status: Option<Value>,
}

/// Validate that `intent` carries the REQUIRED non-empty action/target/resource
/// (Specification 5.4.1).
pub fn validate_intent(intent: &Value) -> Result<()> {
    let obj = intent
        .as_object()
        .ok_or_else(|| CoreError::Json("intent must be an object".into()))?;
    for req in ["action", "target", "resource"] {
        match obj.get(req).and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => {}
            _ => {
                return Err(CoreError::Json(format!(
                    "intent.{req} is REQUIRED and must be a non-empty string"
                )))
            }
        }
    }
    Ok(())
}

/// Construct an unsigned Vouch Credential matching `buildVouchCredential`.
pub fn build_vouch_credential(opts: &BuildCredentialOptions) -> Result<Value> {
    validate_intent(&opts.intent)?;

    let mut subject = Map::new();
    subject.insert("id".into(), json!(opts.issuer_did));
    subject.insert("vouchVersion".into(), json!(PROTOCOL_VERSION));
    subject.insert("intent".into(), opts.intent.clone());
    if let Some(r) = opts.reputation_score {
        subject.insert("reputationScore".into(), json!(r.clamp(0, 100)));
    }
    if let Some(chain) = &opts.delegation_chain {
        if chain.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
            subject.insert("delegationChain".into(), chain.clone());
        }
    }

    let mut vc = Map::new();
    vc.insert("@context".into(), json!([VC_CONTEXT_V2, VOUCH_CONTEXT_V1]));
    vc.insert("id".into(), json!(opts.credential_id));
    vc.insert("type".into(), json!([VC_TYPE, VOUCH_CREDENTIAL_TYPE]));
    vc.insert("issuer".into(), json!(opts.issuer_did));
    vc.insert("validFrom".into(), json!(opts.valid_from));
    vc.insert("validUntil".into(), json!(opts.valid_until));
    vc.insert("credentialSubject".into(), Value::Object(subject));
    if let Some(status) = &opts.credential_status {
        vc.insert("credentialStatus".into(), status.clone());
    }
    Ok(Value::Object(vc))
}

/// Build and sign a Vouch Credential in one step (eddsa-jcs-2022).
pub fn sign_vouch_credential(
    opts: &BuildCredentialOptions,
    raw_private_seed: &[u8],
    proof_opts: &BuildProofOptions,
) -> Result<Value> {
    let cred = build_vouch_credential(opts)?;
    data_integrity::sign(&cred, raw_private_seed, proof_opts)
}

/// The outcome of verifying a credential: the proof and the temporal window are
/// reported separately so a caller can distinguish "bad signature" from
/// "expired".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult {
    pub proof_valid: bool,
    pub time_valid: bool,
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        self.proof_valid && self.time_valid
    }
}

/// Verify the Data Integrity proof and the validity window against `now_iso`.
pub fn verify(
    credential: &Value,
    raw_public_key: &[u8],
    now_iso: &str,
    clock_skew_seconds: i64,
) -> Result<VerifyResult> {
    let proof_valid = data_integrity::verify_proof(credential, raw_public_key)?;
    let time_valid = verify_temporal(credential, now_iso, clock_skew_seconds)?;
    Ok(VerifyResult {
        proof_valid,
        time_valid,
    })
}

/// Check that `now_iso` falls within [validFrom, validUntil] allowing
/// `clock_skew_seconds` of drift at each edge (matches the Python verifier).
pub fn verify_temporal(credential: &Value, now_iso: &str, clock_skew_seconds: i64) -> Result<bool> {
    let obj = credential
        .as_object()
        .ok_or_else(|| CoreError::Json("credential must be an object".into()))?;
    let vf = obj
        .get("validFrom")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("credential missing validFrom".into()))?;
    let vu = obj
        .get("validUntil")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Json("credential missing validUntil".into()))?;
    let now = iso_to_epoch_seconds(now_iso)?;
    let from = iso_to_epoch_seconds(vf)?;
    let until = iso_to_epoch_seconds(vu)?;
    Ok(now >= from - clock_skew_seconds && now <= until + clock_skew_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> BuildCredentialOptions {
        BuildCredentialOptions {
            issuer_did: "did:web:agent.example.com".into(),
            credential_id: "urn:uuid:00000000-0000-4000-8000-000000000000".into(),
            intent: json!({
                "action": "read_database",
                "target": "users_table",
                "resource": "https://api.example.com/v1/users"
            }),
            valid_from: "2026-04-26T10:00:00Z".into(),
            valid_until: "2026-04-26T10:05:00Z".into(),
            reputation_score: Some(150),
            delegation_chain: None,
            credential_status: None,
        }
    }

    #[test]
    fn builds_expected_shape() {
        let vc = build_vouch_credential(&opts()).unwrap();
        assert_eq!(
            vc["type"],
            json!(["VerifiableCredential", "VouchCredential"])
        );
        assert_eq!(vc["credentialSubject"]["vouchVersion"], json!("1.0"));
        // reputationScore clamps to 100.
        assert_eq!(vc["credentialSubject"]["reputationScore"], json!(100));
    }

    #[test]
    fn rejects_missing_intent_fields() {
        let mut o = opts();
        o.intent = json!({ "action": "read", "target": "t" }); // no resource
        assert!(build_vouch_credential(&o).is_err());
    }

    #[test]
    fn sign_and_verify_within_window() {
        let seed = [5u8; 32];
        let proof_opts =
            BuildProofOptions::new("did:web:agent.example.com#key-1", "2026-04-26T10:00:00Z");
        let signed = sign_vouch_credential(&opts(), &seed, &proof_opts).unwrap();
        let pk = crate::keys::Ed25519KeyPair::from_seed(&seed).public_key();
        let r = verify(&signed, &pk, "2026-04-26T10:02:00Z", 30).unwrap();
        assert!(r.is_valid());
        // Expired.
        let r2 = verify(&signed, &pk, "2026-04-26T11:00:00Z", 30).unwrap();
        assert!(r2.proof_valid && !r2.time_valid);
    }
}
